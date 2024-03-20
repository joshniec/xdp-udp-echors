#![no_std]

// Structs created for BPF need to be memory aligned to the value of
// mem::alighn_of::(), commonly 4 and have no padding
// Unaligned structs may have BPF refuse to load with invalid indirect read from stack
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BackendPorts {
    pub ports: [u16; 4],
    pub index: usize,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendPorts {}

// Store BackendPorts in a HashMap, key = frontend port, value is BackendPorts
