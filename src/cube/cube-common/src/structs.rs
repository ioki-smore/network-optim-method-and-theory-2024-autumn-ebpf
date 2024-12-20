use core::cmp::Ordering;
use core::ops::{Add, Sub};
#[derive(Default)]
pub struct AllocInfo {
    pub size: usize,
    pub timestamp_ns: u64,
    pub stack_id: u64,
}
impl AllocInfo {
    pub fn new() -> Self {
        Default::default()
    }
}
#[derive(Copy, Clone)]
pub struct CombinedAllocInfo {
    pub total_size: usize,
    pub alloc_number: usize,
}
impl CombinedAllocInfo {
    pub fn new(total_size: usize, alloc_number: usize) -> Self {
        Self {
            total_size,
            alloc_number,
        }
    }
}
impl Add for CombinedAllocInfo {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            total_size: self.total_size + rhs.total_size,
            alloc_number: self.alloc_number + rhs.alloc_number,
        }
    }
}

impl Sub for CombinedAllocInfo {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            total_size: self.total_size - rhs.total_size,
            alloc_number: self.alloc_number - rhs.alloc_number,
        }
    }
}

impl PartialEq for CombinedAllocInfo {
    fn eq(&self, other: &Self) -> bool {
        self.total_size == other.total_size && self.alloc_number == other.alloc_number
    }
}

impl PartialOrd for CombinedAllocInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.total_size.partial_cmp(&other.total_size)
    }

    fn ge(&self, other: &Self) -> bool {
        self.total_size >= other.total_size && self.alloc_number >= other.alloc_number
    }
}

#[repr(C)]
#[derive(Default)]
pub struct Metrics {
    pub mem_usage: usize,
    pub conn_count: usize,
    pub rx_bytes: usize,
    pub tx_bytes: usize,
}

impl Metrics {
    pub fn new_with_mem_usage(mem_usage: usize) -> Self {
        Self {
            mem_usage,
            ..Default::default()
        }
    }
    pub fn increase_mem_usage(other: &Self, mem_usage: usize) -> Self {
        Self {
            mem_usage: other.mem_usage + mem_usage,
            conn_count: other.conn_count,
            rx_bytes: other.rx_bytes,
            tx_bytes: other.tx_bytes,
        }
    }
    pub fn decrease_mem_usage(other: &Self, mem_usage: usize) -> Self {
        Self {
            mem_usage: other.mem_usage - mem_usage,
            conn_count: other.conn_count,
            rx_bytes: other.rx_bytes,
            tx_bytes: other.tx_bytes,
        }
    }

    pub fn increase_conn_count(other: &Self) -> Self {
        Self {
            mem_usage: other.mem_usage,
            conn_count: other.conn_count,
            rx_bytes: other.rx_bytes + 1,
            tx_bytes: other.tx_bytes,
        }
    }

    pub fn decrease_conn_count(other: &Self) -> Self {
        Self {
            mem_usage: other.mem_usage,
            conn_count: other.conn_count,
            rx_bytes: other.rx_bytes - 1,
            tx_bytes: other.tx_bytes,
        }
    }

    pub fn increase_rx_bytes(other: &Self, rx_bytes: usize) -> Self {
        Self {
            mem_usage: other.mem_usage,
            conn_count: other.conn_count,
            rx_bytes: other.rx_bytes + rx_bytes,
            tx_bytes: other.tx_bytes,
        }
    }

    pub fn increase_tx_bytes(other: &Self, tx_bytes: usize) -> Self {
        Self {
            mem_usage: other.mem_usage,
            conn_count: other.conn_count,
            rx_bytes: other.rx_bytes,
            tx_bytes: other.tx_bytes + tx_bytes,
        }
    }
}
