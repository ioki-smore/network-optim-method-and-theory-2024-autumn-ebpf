use bitflags::bitflags;

bitflags! {
    pub struct AllocType: u16 {
        const kernel = 0x0;
        const malloc = 0x1;
        const calloc = 0x2;
        const realloc = 0x4;
        const mmap = 0x8;
        const posix_memalign = 0x10;
        const aligned_alloc = 0x20;
        const valloc = 0x40;
        const memalign = 0x80;
        const pvalloc = 0x100;
    }
}
