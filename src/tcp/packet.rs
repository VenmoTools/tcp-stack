use etherparse::{Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

use crate::result;
use crate::tcp::connection::{DEFAULT_ISS, DEFAULT_TIME_TO_LIVE, DEFAULT_WINDOWS_SIZE};
use crate::tcp::vars::{ReceiveSequenceSpace, SendSequenceSpace};

pub struct TcpIpHeader {
    pub ip_header: etherparse::Ipv4Header,
    pub tcp_header: etherparse::TcpHeader,
}

impl TcpIpHeader {
    pub fn with_rcv_tcpip_header(rcv_tcp_pkg: &TcpHeaderSlice, rcv_ip_pkg: &Ipv4HeaderSlice) -> Self {
        let tcp = TcpHeader::new(
            rcv_tcp_pkg.destination_port(),
            rcv_tcp_pkg.source_port(),
            DEFAULT_ISS,
            DEFAULT_WINDOWS_SIZE,
        );
        let ip = Ipv4Header::new(
            tcp.header_len(),
            DEFAULT_TIME_TO_LIVE,
            etherparse::IpTrafficClass::IPv4,
            rcv_ip_pkg.destination_addr().octets(),
            rcv_ip_pkg.source_addr().octets(),
        );

        Self::from_tcpip_header(
            ip,
            tcp,
        )
    }

    pub fn from_tcpip_header(ip_header: Ipv4Header, tcp_header: TcpHeader) -> Self {
        Self {
            ip_header,
            tcp_header,
        }
    }

    pub fn update_seq_number(
        &mut self,
        snd_space:
        &SendSequenceSpace,
        rcv_space: &ReceiveSequenceSpace) {
        self.tcp_header.sequence_number = snd_space.nxt;
        self.tcp_header.acknowledgment_number = rcv_space.nxt
    }

    pub fn handshake_resp(&mut self) {
        self.tcp_header.syn = true;
        self.tcp_header.ack = true;
    }

    /// already add tcp header len
    pub fn set_payload_len(&mut self, len: usize) {
        self.ip_header.set_payload_len(self.tcp_header.header_len() as usize + len);
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

