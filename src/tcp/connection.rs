use std::net::{IpAddr, Ipv4Addr};
use std::time;
use std::time::Duration;

use crossbeam_queue::ArrayQueue;
use etherparse::{Ipv4Header, TcpHeader};

use crate::data_link::DataLayer;
use crate::meta::ETHERNET_MTU;
use crate::net_types::EtherType;
use crate::net_types::Protocol::TCP;
use crate::reader_writer::RawWriter;
// use crate::reader_writer::RawWriter;
use crate::result;
use crate::tcp::packet::TcpIpHeader;

use super::vars::{ReceiveSequenceSpace, SendSequenceSpace, TcpState};

pub const DEFAULT_ISS: u32 = 0;
pub const DEFAULT_WINDOWS_SIZE: u16 = 1024;
pub const DEFAULT_RTT: u64 = 1 * 60;
pub const TCP_DEFAULT_HANDLE_BUF_SIZE: usize = 5;
pub const DEFAULT_TIME_TO_LIVE: u8 = 64;


#[derive(Debug, Copy, Clone)]
pub struct ConnectionConfig {
    init_send_seq_number: u32,
    window_size: u16,
    send_rtt: time::Duration,
    ttl: u8,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            init_send_seq_number: DEFAULT_ISS,
            window_size: DEFAULT_WINDOWS_SIZE,
            send_rtt: time::Duration::from_secs(DEFAULT_RTT),
            ttl: DEFAULT_TIME_TO_LIVE,
        }
    }
}

#[derive(Clone)]
pub struct TcpConnection {
    /// Tcp connection state
    state: TcpState,
    /// Wait `timeout` seconds, if no inbound packets are received, the connection is aborted.
    timeout: Option<Duration>,
    /// Wait `keep_alive` seconds, the keep alive packets will be sent
    keep_alive: Option<Duration>,
    /// Send Sequence Variables
    send_seq: SendSequenceSpace,
    /// Receive Sequence Variables
    recv_seq: ReceiveSequenceSpace,
    // pub(crate) incoming: ArrayQueue<u8>,
    // pub(crate) wait_ack: ArrayQueue<u8>,
}


// TCP State diagram
//                               +---------+ ---------\      active OPEN
//                               |  CLOSED |            \    -----------
//                               +---------+<---------\   \   create TCB
//                                 |     ^              \   \  snd SYN
//                    passive OPEN |     |   CLOSE        \   \
//                    ------------ |     | ----------       \   \
//                     create TCB  |     | delete TCB         \   \
//                                 V     |                      \   \
//                               +---------+            CLOSE    |    \
//                               |  LISTEN |          ---------- |     |
//                               +---------+          delete TCB |     |
//                    rcv SYN      |     |     SEND              |     |
//                   -----------   |     |    -------            |     V
//  +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
//  |         |<-----------------           ------------------>|         |
//  |   SYN   |                    rcv SYN                     |   SYN   |
//  |   RCVD  |<-----------------------------------------------|   SENT  |
//  |         |                    snd ACK                     |         |
//  |         |------------------           -------------------|         |
//  +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
//    |           --------------   |     |   -----------
//    |                  x         |     |     snd ACK
//    |                            V     V
//    |  CLOSE                   +---------+
//    | -------                  |  ESTAB  |
//    | snd FIN                  +---------+
//    |                   CLOSE    |     |    rcv FIN
//    V                  -------   |     |    -------
//  +---------+          snd FIN  /       \   snd ACK          +---------+
//  |  FIN    |<-----------------           ------------------>|  CLOSE  |
//  | WAIT-1  |------------------                              |   WAIT  |
//  +---------+          rcv FIN  \                            +---------+
//    | rcv ACK of FIN   -------   |                            CLOSE  |
//    | --------------   snd ACK   |                           ------- |
//    V        x                   V                           snd FIN V
//  +---------+                  +---------+                   +---------+
//  |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
//  +---------+                  +---------+                   +---------+
//    |                rcv ACK of FIN |                 rcv ACK of FIN |
//    |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
//    |  -------              x       V    ------------        x       V
//     \ snd ACK                 +---------+delete TCB         +---------+
//      ------------------------>|TIME WAIT|------------------>| CLOSED  |
//                               +---------+                   +---------+
impl TcpConnection {
    fn create() -> Self {
        Self {
            state: TcpState::Closed,
            timeout: None,
            keep_alive: None,
            send_seq: SendSequenceSpace::default(),
            recv_seq: ReceiveSequenceSpace::default(),
            // incoming: ArrayQueue::new(TCP_DEFAULT_HANDLE_BUF_SIZE),
            // wait_ack: ArrayQueue::new(TCP_DEFAULT_HANDLE_BUF_SIZE),
        }
    }

    pub fn connect<L: DataLayer>(iface: &mut L, ip: IpAddr, port: u16) -> result::Result<TcpConnection> {
        // how to get local addr and free port?
        let src_addr = Ipv4Addr::new(192, 168, 1, 1);
        let source_port = 54466_u16;
        let mut conn = TcpConnection::create();

        let tcp_header = TcpHeader::new(
            source_port,
            port,
            DEFAULT_ISS,
            DEFAULT_WINDOWS_SIZE,
        );

        let ip_header = match ip {
            IpAddr::V4(addr) => {
                Ipv4Header::new(
                    tcp_header.header_len(),
                    DEFAULT_TIME_TO_LIVE,
                    etherparse::IpTrafficClass::IPv4,
                    src_addr.octets(),
                    addr.octets(),
                )
            }
            IpAddr::V6(_) => {
                // not support right now
                unimplemented!()
            }
        };

        let mut packet = TcpIpHeader::from_tcpip_header(ip_header, tcp_header);
        packet.snd_syn();

        let mut raw = RawWriter::new(0);
        raw.write_header(&packet)?;
        iface.send(raw.buffer());
        conn.set_state(TcpState::SynSent);
        Ok(conn)
    }

    fn from_recv_sequence(seq_number: u32, wnd: u16) -> Self {
        Self {
            state: TcpState::Closed,
            timeout: None,
            keep_alive: None,
            send_seq: SendSequenceSpace::default(),
            recv_seq: ReceiveSequenceSpace::from_seq_number(seq_number, wnd),
            // incoming: ArrayQueue::new(TCP_DEFAULT_HANDLE_BUF_SIZE),
            // wait_ack: ArrayQueue::new(TCP_DEFAULT_HANDLE_BUF_SIZE),
        }
    }

    fn set_state(&mut self, state: TcpState) {
        self.state = state
    }

    pub fn close(&mut self) {
        self.state = TcpState::Closed
    }

    /// handle the first handshake
    pub fn accept<'a, L: DataLayer>(
        iface: &mut L,
        ip: &'a etherparse::Ipv4HeaderSlice<'a>,
        tcp: &'a etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> result::Result<Option<Self>> {
        debug!("[{:?}:{}] -> [{:?}:{}] SYN: {}, SEQ:{} ,ACK_NUM: {} ACK:{}",
               ip.source_addr(), tcp.source_port(),
               ip.destination_addr(), tcp.destination_port(),
               tcp.syn(),
               tcp.sequence_number(),
               tcp.acknowledgment_number()
        );
        // the first packet SYN flag must be set
        if !tcp.syn() {
            return Ok(None);
        }
        // we create the new connection cause it's first handshake
        // and change send sequence number(nxt)
        let mut conn = TcpConnection::from_recv_sequence(
            tcp.sequence_number(),
            tcp.window_size(),
        );
        // we just crate connection, now state is listen
        // when we send response packet then state will change to SynRecv
        conn.set_state(TcpState::Listen);

        let mut handshake_packet = TcpIpHeader::with_rcv_tcpip_header(tcp, ip);
        let mut writer = RawWriter::with_default_offset();

        handshake(&mut conn, &mut handshake_packet, &mut writer);
        debug!("[{:?}:{}] <- [{:?}:{}] SYN:{} SEQ:{} ACK_NUM:{},ACK:{}",
               ip.destination_addr(), tcp.destination_port(),
               ip.source_addr(), tcp.source_port(),
               handshake_packet.tcp_header.syn,
               handshake_packet.tcp_header.sequence_number,
               handshake_packet.tcp_header.acknowledgment_number,
               handshake_packet.tcp_header.ack
        );
        iface.send(&writer.buffer());
        conn.set_state(TcpState::SynReceived);
        Ok(Some(conn))
    }
}

////         send SYN c_seq=x
/// Client ------------------------------------> Server
///          send SYN,ACK,s_seq=y,ack=x+1
/// Client <----------------------------------- Server
///          send ACK,ack=y+1,c_seq=x+1
/// Client -----------------------------------> Server
fn handshake(conn: &mut TcpConnection, handshake_packet: &mut TcpIpHeader, writer: &mut RawWriter) -> result::Result<()> {
    // we have to set SYN and ACK flags
    handshake_packet.handshake_resp();
    handshake_packet.update_seq_number(&conn.send_seq, &conn.recv_seq);
    // etherparse will calc checksum so we do need this step
    // let checksum = handshake_packet.check_sum(&[])?;
    // handshake_packet.tcp_header.checksum = checksum;
    writer.write_header(handshake_packet)?;
    Ok(())
}
