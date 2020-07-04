use etherparse::{Ipv4Header, TcpHeader};

use crate::result;

pub struct TcpIpHeader {
    pub ip_header: etherparse::Ipv4Header,
    pub tcp_header: etherparse::TcpHeader,
}

impl TcpIpHeader {
    pub fn from_tcpip_header(ip_header: Ipv4Header, tcp_header: TcpHeader) -> Self {
        Self {
            ip_header,
            tcp_header,
        }
    }

    pub fn snd_ayn_ack(&mut self) {
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

