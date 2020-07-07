use std::io::{BufWriter, Write};
use std::net::Ipv4Addr;

use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice, TcpHeaderSlice};
use etherparse::WriteError;

use crate::meta::{ETHERNET_MTU, TUN_SIZE};
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
            self.tcp_header();
        }
        self.data_offset.unwrap()
    }
}


pub struct RawWriter {
    offset: usize,
    buf: BufWriter<Vec<u8>>,
}

impl RawWriter {
    pub fn with_default_offset() -> Self {
        Self::new(TUN_SIZE)
    }
    pub fn change_offset(&mut self, offset: usize) {
        self.offset = offset;
    }

    pub fn buffer(&self) -> &[u8] {
        self.buf.buffer()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity <= ETHERNET_MTU, "capacity must less or equal ETHERNET_MTU(1500)");
        Self {
            offset: TUN_SIZE,
            buf: BufWriter::new(Vec::with_capacity(capacity)),
        }
    }
    pub fn new(offset: usize) -> Self {
        Self {
            offset,
            buf: BufWriter::new(Vec::with_capacity(ETHERNET_MTU)),
        }
    }

    pub fn write_tuntap_header(&mut self, version: u16, flags: u16) {
        let ver_buf: [u8; 2] = version.to_le_bytes();
        let flag_buf: [u8; 2] = flags.to_le_bytes();
        self.buf.write(&ver_buf);
        self.buf.write(&flag_buf);
    }

    pub fn write_header(&mut self, packet: &TcpIpHeader) -> result::Result<()> {
        packet.ip_header.write(&mut self.buf)?;
        packet.tcp_header.write(&mut self.buf)?;
        Ok(())
    }
}