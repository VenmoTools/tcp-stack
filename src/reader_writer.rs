use std::net::Ipv4Addr;

use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice, TcpHeaderSlice};
use etherparse::WriteError;

use crate::meta::TUN_SIZE;
use crate::result;
use crate::result::Error;
use crate::tcp::packet::TcpIpHeader;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct Quad {
    src: Addr,
    dest: Addr,
}

impl Quad {
    pub fn new(src: Addr, dest: Addr) -> Self {
        Self {
            src,
            dest,
        }
    }
    pub fn from_tcpip_header<'a>(ip_header: &Ipv4HeaderSlice<'a>, tcp_header: &TcpHeaderSlice<'a>) -> Self {
        Self::new(
            Addr::new(ip_header.source_addr(), tcp_header.source_port()),
            Addr::new(ip_header.destination_addr(), tcp_header.destination_port()),
        )
    }
}


#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct Addr {
    ip: Ipv4Addr,
    port: u16,
}

impl Addr {
    pub fn new(ip: Ipv4Addr, port: u16) -> Self {
        Self {
            ip,
            port,
        }
    }
}

pub struct RawReader<'a> {
    /// the offset of ip header
    /// this is zero If no packet info needs to be provided add corresponding flag with tuntap
    offset: usize,
    /// thw raw buffer
    buf: &'a [u8],
    len: usize,
    data_offset: Option<usize>,
}

impl<'a> RawReader<'a> {
    pub fn from_slice(buf: &'a [u8], nread: usize, offset: usize) -> RawReader {
        Self {
            offset,
            buf,
            len: nread,
            data_offset: None,
        }
    }

    pub fn offset_data(&self) -> &'a [u8] {
        &self.buf[..self.offset]
    }

    pub fn ipv4_header(&self) -> result::Result<Ipv4HeaderSlice<'a>> {
        Ok(Ipv4HeaderSlice::from_slice(&self.buf[self.offset..self.len])?)
    }

    pub fn ipv6_header(&self) -> result::Result<Ipv6HeaderSlice<'a>> {
        Ok(Ipv6HeaderSlice::from_slice(&self.buf[self.offset..self.len])?)
    }

    pub fn is_ipv6_packet(&self) -> bool {
        let version = self.buf[self.offset + 0] >> 4;
        version == 6
    }

    pub fn is_ipv4_packet(&self) -> bool {
        let version = {
            let value = self.buf[self.offset + 0];
            value >> 4
        };
        version == 4
    }

    pub fn tcp_header(&mut self) -> result::Result<TcpHeaderSlice<'a>> {
        let (_, tcp) = self.tcp_ip_header()?;
        Ok(tcp)
    }

    pub fn tcp_ip_header(&mut self) -> result::Result<(Ipv4HeaderSlice<'a>, TcpHeaderSlice<'a>)> {
        let ipheader = self.ipv4_header()?;
        let ip_h_len = ipheader.slice().len();
        let tcp_h = TcpHeaderSlice::from_slice(&self.buf[self.offset + ip_h_len..self.len])?;
        let tcp_len = tcp_h.slice().len();
        if self.data_offset.is_none() {
            self.data_offset = Some(self.offset + ip_h_len + tcp_len);
        }
        Ok((ipheader, tcp_h))
    }

    pub fn data_offset(&mut self) -> usize {
        if self.data_offset.is_none() {
            self.tcp_header()
        }
        self.data_offset.unwrap()
    }
}


pub struct RawWriter<'a> {
    offset: usize,
    buf: &'a [u8],
    packet: &'a TcpIpHeader,
}

impl<'a> RawWriter<'a> {
    pub fn from_tuntap_packet(buf: &'a [u8], packet: &'a TcpIpHeader) -> Self {
        Self {
            offset: TUN_SIZE,
            buf,
            packet,
        }
    }

    pub fn new(offset: usize, buf: &'a [u8], packet: &'a TcpIpHeader) -> Self {
        Self {
            offset,
            buf,
            packet,
        }
    }

    fn minimum_size(&self) -> usize {
        self.offset + self.packet.ip_header.header_len() + self.packet.tcp_header.header_len() - 1
    }

    fn assert_range(&self) -> bool {
        self.buf.len() < self.minimum_size()
    }

    pub fn write_tuntap_header(&mut self, version: u16, flags: u16) {
        let ver_buf: [u8; 2] = version.to_le_bytes();
        let flag_buf: [u8; 2] = flags.to_le_bytes();
        *self.buf[0] = flag_buf[0];
        *self.buf[1] = flag_buf[1];
        *self.buf[2] = ver_buf[0];
        *self.buf[3] = ver_buf[1];
    }

    pub fn write_header(&mut self) -> result::Result<()> {
        if !self.assert_range() {
            return Err(Error::WriteError(WriteError::SliceTooSmall(self.minimum_size())));
        }
        let mut buf = self.buf[self.offset..];
        self.packet.ip_header.write(&mut buf)?;
        self.packet.tcp_header.write(&mut [self.packet.ip_header.header_len()..])?;
        Ok(())
    }

    pub fn write_payload(&mut self) -> result::Result<()> {}
}