use std::time;
use std::time::Duration;

use crossbeam_queue::ArrayQueue;
use etherparse::{Ipv4Header, TcpHeader};

use crate::data_link::DataLayer;
use crate::net_types::Protocol::TCP;
use crate::result;

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
    pub(crate) incoming: ArrayQueue<u8>,
    pub(crate) wait_ack: ArrayQueue<u8>,
}


pub struct PacketHeader {
    ip_header: etherparse::Ipv4Header,
    tcp_header: etherparse::TcpHeader,
}

impl PacketHeader {
    pub fn snd_ayn_ack(&mut self) {
        self.tcp_header.syn = true;
        self.tcp_header.ack = true;
    }

    pub fn snd_syn(&mut self) {
        self.tcp_header.syn = true;
    }

    pub fn snd_fin(&mut self) {
        self.tcp_header.fin = true;
    }

    pub fn check_sum(&mut self, payload: &[u8]) -> result::Result<u16> {
        let checksum = self.tcp_header.calc_checksum_ipv4(
            &self.ip_header,
            payload,
        )?;
        Ok(checksum)
    }
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
    pub fn create() -> Self {
        Self {
            state: TcpState::Closed,
            timeout: None,
            keep_alive: None,
            send_seq: SendSequenceSpace::default(),
            recv_seq: ReceiveSequenceSpace::default(),
            incoming: ArrayQueue::new(TCP_DEFAULT_HANDLE_BUF_SIZE),
            wait_ack: ArrayQueue::new(TCP_DEFAULT_HANDLE_BUF_SIZE),
        }
    }

    pub fn from_recv_sequence(seq_number: u32, wnd: u16) -> Self {
        Self {
            state: TcpState::Closed,
            timeout: None,
            keep_alive: None,
            send_seq: SendSequenceSpace::default(),
            recv_seq: ReceiveSequenceSpace::from_seq_number(seq_number, wnd),
            incoming: ArrayQueue::new(TCP_DEFAULT_HANDLE_BUF_SIZE),
            wait_ack: ArrayQueue::new(TCP_DEFAULT_HANDLE_BUF_SIZE),
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
        // the first packet SYN flag must be set
        if !tcp.syn() {
            return Ok(None);
        }
        // we create the new connection cause it's first handshake
        let mut conn = TcpConnection::from_recv_sequence(
            tcp.sequence_number(),
            tcp.window_size(),
        );
        conn.set_state(TcpState::SynReceived);
        let mut resp_packet = PacketHeader {
            ip_header: Ipv4Header::new(
                0,
                DEFAULT_TIME_TO_LIVE,
                etherparse::IpTrafficClass::IPv4,
                ip.destination_addr().octets(),
                ip.source_addr().octets(),
            ),
            tcp_header: TcpHeader::new(
                tcp.destination_port(),
                tcp.source_port(),
                DEFAULT_ISS,
                DEFAULT_WINDOWS_SIZE,
            ),
        };
        handshake(&mut conn, &mut resp_packet);

        Ok(Some(conn))
    }
}

fn handshake(conn: &mut TcpConnection, resp_packet: &mut PacketHeader) {
    // we have to set SYN and ACK flags
    resp_packet.snd_ayn_ack();
    //
    resp_packet.tcp_header.sequence_number = conn.send_seq.nxt;
    //  already init ack number in `TcpConnection::from_recv_sequence`
    resp_packet.tcp_header.acknowledgment_number = conn.recv_seq.nxt;
}
