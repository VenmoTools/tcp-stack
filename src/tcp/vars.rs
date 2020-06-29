/// Send Sequence Variables of TCB block
/// See RFC 793 Section3 for more information
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct SendSequenceSpace {
    /// send unacknowledged
    pub una: u32,
    /// send next
    pub nxt: u32,
    /// send window
    pub wnd: u16,
    /// send urgent pointer
    pub up: bool,
    /// segment sequence number used for last window update
    pub wl1: usize,
    /// segment acknowledgment number used for last window update
    pub wl2: usize,
    /// initial send sequence number
    pub iss: u32,
}

impl SendSequenceSpace {
    /// create send sequence space from iss and window size
    pub fn from_seq_number(iss: u32, wnd: u16) -> Self {
        Self {
            una: iss,
            nxt: iss + 1,
            wnd,
            up: false,
            wl1: 0,
            wl2: 0,
            iss,
        }
    }

    pub fn init_seq_number(&mut self, iss: u32) {
        self.iss = iss;
        self.una = self.iss;
        self.nxt = self.una + 1;
        self.wnd = 10;
    }
}


/// Receive Sequence Variables of TCB block
/// See RFC 793 Section3 for more information
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct ReceiveSequenceSpace {
    /// receive next
    pub nxt: u32,
    /// receive window
    pub wnd: u16,
    /// receive urgent pointer
    pub up: bool,
    /// initial receive sequence number
    pub irs: u32,
}

impl ReceiveSequenceSpace {
    pub fn from_seq_number(seq_number: u32, wnd: u16) -> Self {
        Self {
            nxt: seq_number + 1,
            wnd,
            up: false,
            irs: seq_number,
        }
    }

    pub fn save_seq_number(&mut self, seq_number: u32, wnd: u16) {
        self.irs = seq_number;
        self.nxt = self.irs + 1;
        self.wnd = wnd;
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpState {
    Closed,
    Listen,
    SynReceived,
    SynSent,
    Established,
}