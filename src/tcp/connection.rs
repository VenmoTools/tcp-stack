use std::time;

use crossbeam_queue::ArrayQueue;

use crate::data_link::DataLayer;
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
    /// Send Sequence Variables
    send_seq: SendSequenceSpace,
    /// Receive Sequence Variables
    recv_seq: ReceiveSequenceSpace,
    pub(crate) incoming: ArrayQueue<u8>,
    pub(crate) wait_ack: ArrayQueue<u8>,
}


impl TcpConnection {
    pub fn accept<'a, L: DataLayer>(
        iface: &mut L,
        ip: &'a etherparse::Ipv4HeaderSlice<'a>,
        tcp: &'a etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> result::Result<usize> {
        use TcpState::*;
        let mut resp_data = [0_u8; 1500];

        let mut conn = TcpConnection {
            state: TcpState::SynReceived,
            send_seq: Default::default(),
            recv_seq: Default::default(),
            incoming: ArrayQueue::new(TCP_DEFAULT_HANDLE_BUF_SIZE),
            wait_ack: ArrayQueue::new(TCP_DEFAULT_HANDLE_BUF_SIZE),
        };

        handle_listen_state(&mut conn, iface, &mut resp_data, ip, tcp)?;

        Ok(0)
    }
}


fn handle_listen_state<'a, L: DataLayer>(
    conn: &mut TcpConnection,
    iface: &mut L,
    resp_data: &mut [u8],
    ip: &'a etherparse::Ipv4HeaderSlice<'a>,
    tcp: &'a etherparse::TcpHeaderSlice<'a>, )
    -> result::Result<usize>
{
    // only accepted SYN packet
    if !tcp.syn() {
        return Ok(0);
    }
    // this connection need save sequence number, excepted next sequence and window size
    conn.recv_seq.save_seq_number(tcp.sequence_number(), tcp.window_size());

    // initial send sequence number for SYN
    conn.send_seq.init_seq_number(DEFAULT_ISS);


    // send response
    let mut resp_header = etherparse::TcpHeader::new(
        tcp.destination_port(),
        tcp.source_port(),
        conn.send_seq.iss,
        conn.send_seq.wnd,
    );
    // we excepted the next number
    resp_header.acknowledgment_number = conn.recv_seq.nxt;


    // recv SYN snd SYN,ACK
    resp_header.syn = true;
    resp_header.ack = true;
    let resp_ip = etherparse::Ipv4Header::new(
        resp_header.header_len(),
        DEFAULT_TIME_TO_LIVE,
        etherparse::IpTrafficClass::IPv4,
        ip.destination_addr().octets(),
        ip.source_addr().octets(),
    );

    let end_index = {
        let mut buf = &mut resp_data[..];
        resp_ip.write(&mut buf)?;
        resp_header.write(&mut buf)?;
        buf.len()
    };

    Ok(iface.send(&resp_data[..end_index])?)
}

