use std::io::Result;

pub trait DataLayer {
    fn send(&mut self, data: &[u8]) -> Result<usize>;

    fn recv(&mut self, data: &mut [u8]) -> Result<usize>;
}

impl DataLayer for tun_tap::Iface {
    fn send(&mut self, data: &[u8]) -> Result<usize> {
        self.send(data)
    }

    fn recv(&mut self, data: &mut [u8]) -> Result<usize> {
        self.recv(data)
    }
}
