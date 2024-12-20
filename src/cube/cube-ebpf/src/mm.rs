use crate::maps::{ALLOCS, METRICS, SIZES, STACK_TRACES};
use aya_ebpf::helpers::{bpf_get_current_cgroup_id, bpf_ktime_get_ns};
use aya_ebpf::macros::{uprobe, uretprobe};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use cube_common::{AllocInfo, AllocType, Metrics};

// TODO: remove ctx
fn try_alloc_enter<T>(_ctx: T, size: usize, alloc_type: AllocType) -> Result<u32, u32>
where
    T: aya_ebpf::EbpfContext,
{
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let key: u64 = cgroup_id | alloc_type.bits() as u64;
    match unsafe { SIZES.get(&key) } {
        None => unsafe { SIZES.insert(&key, &size, 0) }.map_err(|e| e as u32)?,
        Some(assigned) => unsafe {
            SIZES.remove(&key).map_err(|e| e as u32)?;
            SIZES
                .insert(&key, &(size + assigned), 0)
                .map_err(|e| e as u32)?;
        },
    }
    Ok(0)
}

fn try_alloc_exit(ctx: RetProbeContext, alloc_type: AllocType) -> Result<u32, u32> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let key: u64 = cgroup_id | alloc_type.bits() as u64;
    let mut info = AllocInfo::new();

    if let size = unsafe { SIZES.get(&key) }.ok_or(0_u32)? {
        info.size = *size;
        unsafe { SIZES.remove(&key) }.map_err(|e| e as u32)?;
    }

    let address: u64 = ctx.ret().ok_or(0_u32)?;

    if address != 0 {
        unsafe {
            info.timestamp_ns = bpf_ktime_get_ns();
            info.stack_id = STACK_TRACES.get_stackid(&ctx, 0).map_err(|e| e as u32)? as u64;
            match ALLOCS.get(&address) {
                None => ALLOCS.insert(&key, &info, 0).map_err(|e| e as u32)?,
                Some(_) => {
                    ALLOCS.remove(&key).map_err(|e| e as u32)?;
                    ALLOCS.insert(&key, &info, 0).map_err(|e| e as u32)?;
                    match METRICS.get(&cgroup_id) {
                        None => METRICS
                            .insert(&cgroup_id, &Metrics::new_with_mem_usage(info.size), 0)
                            .map_err(|e| e as u32)?,
                        Some(old) => {
                            METRICS.remove(&cgroup_id).map_err(|e| e as u32)?;
                            METRICS
                                .insert(&cgroup_id, &Metrics::increase_mem_usage(old, info.size), 0)
                                .map_err(|e| e as u32)?;
                        }
                    }
                }
            }
        }
    }

    Ok(0)
}

fn try_free_enter(ctx: &ProbeContext) -> Result<u32, u32> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let address = ctx.arg(0).ok_or(0_u32)?;
    let info = unsafe { ALLOCS.get(&address) }.ok_or(0_u32)?;

    unsafe {
        ALLOCS.remove(&address).map_err(|e| e as u32)?;
        let old = METRICS.get(&cgroup_id).ok_or(0_u32)?;
        METRICS.remove(&cgroup_id).map_err(|e| e as u32)?;
        METRICS
            .insert(&cgroup_id, &Metrics::decrease_mem_usage(old, info.size), 0)
            .map_err(|e| e as u32)?;
    }
    Ok(0)
}

fn try_free_exit(_ctx: RetProbeContext, _alloc_type: AllocType) -> Result<u32, u32> {
    todo!()
}

// No probe attaching here. Allocations are counted by attaching to tracepoints.
//
// Memory allocations in Linux kernel are not limited to malloc/free equivalents. It's also common
// to allocate a memory page or multiple pages. Page allocator have two interfaces, one working with
// page frame numbers (PFN), while other working with page addresses. It's possible to allocate
// pages with one kind of functions, and free them with another. Code in kernel can easily convert
// PFNs to addresses and back, but it's hard to do the same in eBPF kprobe without fragile hacks.
//
// Fortunately, Linux exposes tracepoints for memory allocations, which can be instrumented by eBPF
// programs. Tracepoint for page allocations gives access to PFNs for both allocator interfaces. So
// there is no need to guess which allocation corresponds to which free.

/// void *malloc(size_t size);
/// The malloc() function allocates size bytes and returns a pointer to the allocated  memory.
/// The memory is not initialized.  If size is 0, then malloc() returns either NULL, or a unique
/// pointer value that can  later be successfully passed to free().
#[uprobe]
fn malloc_enter(ctx: ProbeContext) -> u32 {
    let size: usize = ctx.arg(0).ok_or(0_u32).unwrap();
    if size == 0 {
        return 0;
    }
    try_alloc_enter(ctx, size, AllocType::malloc).unwrap_or_else(|ret| ret)
}

#[uretprobe]
fn malloc_exit(ctx: RetProbeContext) -> u32 {
    try_alloc_exit(ctx, AllocType::malloc).unwrap_or_else(|ret| ret)
}
/// void *calloc(size_t nmemb, size_t size);
///
/// The calloc() function allocates memory for an array of nmemb elements of size bytes each and
/// returns a pointer to the allocated memory. The memory is set to zero.
/// If nmemb or size is 0, then calloc() returns either NULL, or a unique pointer value that can
/// later be successfully passed to free(). If the multiplication of nmemb and size would result in
/// integer overflow, then calloc() returns an error. By contrast, an integer overflow would not be
/// detected in the following call to malloc(), with the result that an incorrectly sized block of
/// memory would be allocated:
/// malloc(nmemb * size);
#[uprobe]
fn calloc_enter(ctx: ProbeContext) -> u32 {
    let nmemb: usize = ctx.arg(0).ok_or(0_u32).unwrap();
    let size: usize = ctx.arg(1).ok_or(0_u32).unwrap();
    if nmemb.wrapping_mul(size) == usize::MAX {
        return 0;
    }
    try_alloc_enter(ctx, nmemb * size, AllocType::calloc).unwrap_or_else(|ret| ret)
}

#[uretprobe]
fn calloc_exit(ctx: RetProbeContext) -> u32 {
    try_alloc_exit(ctx, AllocType::calloc).unwrap_or_else(|ret| ret)
}

/// void *realloc(void *ptr, size_t size);
/// The realloc() function changes the size of the memory block pointed to by ptr to size bytes. The
/// contents will be unchanged in the range from the start of the region up to the minimum of the
/// old and new sizes. If the new size is larger than the old size, the added memory will not be
/// initialized. If ptr is NULL, then the call is equivalent to malloc(size), for all values of
/// size; if size is equal to zero, and ptr is not NULL, then the call is equivalent to free(ptr).
/// Unless ptr is NULL, it must have been returned by an earlier call to malloc(), calloc(),
/// or realloc(). If the area pointed to was moved, a free(ptr) is done.
#[uprobe]
fn realloc_enter(ctx: ProbeContext) -> u32 {
    try_free_enter(&ctx).unwrap_or_else(|ret| ret);
    let size: usize = ctx.arg(1).ok_or(0_u32).unwrap();
    try_alloc_enter(ctx, size, AllocType::realloc).unwrap_or_else(|ret| ret)
}

#[uretprobe]
fn realloc_exit(ctx: RetProbeContext) -> u32 {
    try_alloc_exit(ctx, AllocType::realloc).unwrap_or_else(|ret| ret)
}
/// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
///
/// failed on jemalloc
#[uprobe]
fn mmap_enter(ctx: ProbeContext) -> u32 {
    let size: usize = ctx.arg(1).ok_or(0_u32).unwrap();
    try_alloc_enter(ctx, size, AllocType::mmap).unwrap_or_else(|ret| ret)
}

#[uretprobe]
fn mmap_exit(ctx: RetProbeContext) -> u32 {
    try_alloc_exit(ctx, AllocType::mmap).unwrap_or_else(|ret| ret)
}
/// int munmap(void *addr, size_t length)
///
/// failed on jemalloc
///
/// On success, mmap() returns a pointer to the mapped area.  On error, the value MAP_FAILED (that
/// is, (void *) -1) is returned, and errno is set to indicate the cause of the error.
#[uprobe]
fn munmap_enter(ctx: ProbeContext) -> u32 {
    try_free_enter(&ctx).unwrap_or_else(|ret| ret)
}
/// On  success, munmap() returns 0. On failure, it returns -1, and errno is set to indicate the
/// cause of the error (probably to EINVAL).
#[uretprobe]
fn munmap_exit(_ctx: RetProbeContext) -> u32 {
    0
}

/// int posix_memalign(void **memptr, size_t alignment, size_t size);
///
/// The  function posix_memalign() allocates size bytes and places the address of the allocated
/// memory in *memptr. The address of the allocated memory will be a multiple of alignment, which
/// must be a power of two and a multiple of sizeof(void *). This address can later be successfully
/// passed to free(3). If size is 0, then the value placed in *memptr is either NULL or a unique
/// pointer value.
#[uprobe]
fn posix_memalign_enter(ctx: ProbeContext) -> u32 {
    let _memptr: usize = ctx.arg(0).ok_or(0_u32).unwrap();
    let size = ctx.arg(2).ok_or(0_u32).unwrap();

    try_alloc_enter(ctx, size, AllocType::posix_memalign).unwrap_or_else(|ret| ret)
}
/// On  success, munmap() returns 0. On failure, it returns -1, and errno is set to indicate the
/// cause of the error (probably to EINVAL).
#[uretprobe]
fn posix_memalign_exit(_ctx: RetProbeContext) -> u32 {
    0
}
/// void *aligned_alloc(size_t alignment, size_t size);
///
/// added in C11
///
/// The function aligned_alloc() is the same as memalign(), except for the added restriction that
/// size should be a multiple of alignment.
#[uprobe]
fn aligned_alloc_enter(ctx: ProbeContext) -> u32 {
    let size = ctx.arg(1).ok_or(0_u32).unwrap();
    try_alloc_enter(ctx, size, AllocType::aligned_alloc).unwrap_or_else(|ret| ret)
}
/// return a pointer to the allocated memory on success. On error, NULL is returned, and errno is
/// set to indicate the cause of the error.
#[uretprobe]
fn aligned_alloc_exit(ctx: RetProbeContext) -> u32 {
    try_alloc_exit(ctx, AllocType::aligned_alloc).unwrap_or_else(|ret| ret)
}
/// void *valloc(size_t size);
///
/// failed on Android, is deprecated in libc.so from bionic directory
///
/// The obsolete function valloc() allocates size bytes and returns a pointer to the allocated
/// memory. The memory address will be a multiple of the page size. It is equivalent to
/// memalign(sysconf(_SC_PAGESIZE),size).
#[uprobe]
fn valloc_enter(ctx: ProbeContext) -> u32 {
    let size = ctx.arg(0).ok_or(0_u32).unwrap();
    try_alloc_enter(ctx, size, AllocType::valloc).unwrap_or_else(|ret| ret)
}
/// return a pointer to the allocated memory on success. On error, NULL is returned, and errno is
/// set to indicate the cause of the error.
#[uretprobe]
fn valloc_exit(ctx: RetProbeContext) -> u32 {
    try_alloc_exit(ctx, AllocType::valloc).unwrap_or_else(|ret| ret)
}
/// void *memalign(size_t alignment, size_t size);
///
/// The obsolete function memalign() allocates size bytes and returns a pointer to the allocated
/// memory. The memory address will be a multiple of alignment, which must be a power of two.
#[uprobe]
fn memalign_enter(ctx: ProbeContext) -> u32 {
    let size = ctx.arg(1).ok_or(0_u32).unwrap();
    try_alloc_enter(ctx, size, AllocType::memalign).unwrap_or_else(|ret| ret)
}
/// return a pointer to the allocated memory on success. On error, NULL is returned, and errno is
/// set to indicate the cause of the error.
#[uretprobe]
fn memalign_exit(ctx: RetProbeContext) -> u32 {
    try_alloc_exit(ctx, AllocType::memalign).unwrap_or_else(|ret| ret)
}
/// void *pvalloc(size_t size);
///
/// failed on Android, is deprecated in libc.so from bionic directory
///
/// The obsolete function pvalloc() is similar to valloc(), but rounds the size of the allocation up
/// to the next multiple of the system page size.
#[uprobe]
fn pvalloc_enter(ctx: ProbeContext) -> u32 {
    let size = ctx.arg(0).ok_or(0_u32).unwrap();
    try_alloc_enter(ctx, size, AllocType::pvalloc).unwrap_or_else(|ret| ret)
}
/// return a pointer to the allocated memory on success. On error, NULL is returned, and errno is
/// set to indicate the cause of the error.
#[uretprobe]
fn pvalloc_exit(ctx: RetProbeContext) -> u32 {
    try_alloc_exit(ctx, AllocType::pvalloc).unwrap_or_else(|ret| ret)
}
/// void free(void *ptr);
/// The free() function frees the memory space pointed to by ptr, which must have been returned by a
/// previous call to malloc(), calloc(), or realloc(). Otherwise, or if free(ptr) has already been
/// called before, undefined behavior occurs.
/// If ptr is NULL, no operation is performed.
#[uprobe]
fn free_enter(ctx: ProbeContext) -> u32 {
    try_free_enter(&ctx).unwrap_or_else(|ret| ret)
}
#[uretprobe]
fn free_exit(ctx: RetProbeContext) -> u32 {
    try_free_exit(ctx, AllocType::malloc).unwrap_or_else(|ret| ret)
}
// ID: 550
// format:
//         ...
//         field:unsigned long call_site;  offset:8;       size:8; signed:0;
//         field:const void * ptr; offset:16;      size:8; signed:0;
//         field:size_t bytes_req; offset:24;      size:8; signed:0;
//         field:size_t bytes_alloc;       offset:32;      size:8; signed:0;
//         field:gfp_t gfp_flags;  offset:40;      size:4; signed:0;
// #[tracepoint(category = "kmem", name = "kmalloc")]
// fn kmalloc_enter(ctx: TracePointContext) -> u32 {
//     let size = unsafe { ctx.read_at::<u64>(32) }.map_or(0, |e| e) as usize;
//     if size == 0 {
//         return 0;
//     }
//     try_alloc_enter(ctx, size, AllocType::kernel).unwrap()
// }
