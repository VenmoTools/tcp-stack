use core::fmt;

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

    pub fn acceptable(&self, ack_number: u32) -> bool {
        self.una < ack_number && ack_number <= self.nxt
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
    /// check if the beginning of segment falls in the window
    pub fn beginning_fall_in_wnd(&self, seq_number: u32) -> bool {
        self.nxt <= seq_number && seq_number < self.nxt + self.wnd as u32
    }

    /// check if the end of the segment falls in the window
    pub fn end_of_fall_in_wnd(&self, seq_number: u32, seq_len: u32) -> bool {
        let seq = seq_number + seq_len - 1;
        self.nxt <= seq && seq < self.nxt + self.wnd as u32
    }
}

/// State of a tcp
/// See RFC 793 for more information
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpState {
    Closed,
    Listen,
    SynReceived,
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &TcpState::Closed => write!(f, "CLOSED"),
            &TcpState::Listen => write!(f, "LISTEN"),
            &TcpState::SynSent => write!(f, "SYN-SENT"),
            &TcpState::SynReceived => write!(f, "SYN-RECEIVED"),
            &TcpState::Established => write!(f, "ESTABLISHED"),
            &TcpState::FinWait1 => write!(f, "FIN-WAIT-1"),
            &TcpState::FinWait2 => write!(f, "FIN-WAIT-2"),
            &TcpState::CloseWait => write!(f, "CLOSE-WAIT"),
            &TcpState::Closing => write!(f, "CLOSING"),
            &TcpState::LastAck => write!(f, "LAST-ACK"),
            &TcpState::TimeWait => write!(f, "TIME-WAIT")
        }
    }
}


#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum TcpControl {
    /// Urgent Pointer field significant
    URG,
    /// Acknowledgment field significant
    ACK,
    /// Push Function
    PSH,
    /// Reset the connection
    RST,
    /// Synchronize sequence numbers
    SYN,
    /// No more data from sender
    FIN,
}

impl TcpControl {
    /// Return length of tcp control flag
    pub fn len(&self) -> usize {
        match self {
            TcpControl::SYN | TcpControl::FIN => 1,
            _ => 0
        }
    }
}

pub fn ensure_in_safe_range(data: u32) -> u32 {
    data % u32::max_value()
}


#[derive(Debug)]
pub struct TcpOption {
    /// maximum_segment_size
    mss: Option<MaximumSegmentSize>,
    /// SACK Permitted
    sack: Option<SackPermitted>,
    /// Timestamp
    timestamp: Option<TimeStamp>,
}

#[derive(Debug)]
pub struct MaximumSegmentSize(usize);

#[derive(Debug)]
pub struct SackPermitted(usize);

#[derive(Debug)]
pub struct TimeStamp(usize);
