use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, StackTrace};
use cube_common::{AllocInfo, Metrics};

#[map(name = "alloc_size")]
pub(crate) static mut SIZES: HashMap<u64, usize> = HashMap::pinned(1 << 10, 0);
#[map(name = "alloc_info")]
pub(crate) static mut ALLOCS: HashMap<u64, AllocInfo> = HashMap::pinned(1000000, 0);
// TODO: why use this and can I change?
#[map(name = "stack_traces")]
pub(crate) static mut STACK_TRACES: StackTrace = StackTrace::pinned((1 << 10) * 10, 0);
#[map(name = "metrics")]
pub(crate) static mut METRICS: HashMap<u64, Metrics> = HashMap::pinned(1 << 7, 0);
