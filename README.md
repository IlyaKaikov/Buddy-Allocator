malloc_3.cpp is an implementation of a Linux Buddy memory allocator.

This was done as part of an Operating Systems course.

First call initializes the buddy allocator by allocating, using sbrk(), 32 blocks of size 128KB each.

Small allocations (below 128KB) are handled by the buddy allocator, by splitting and merging blocks to minimize internal fragmentation.

Large allocations (above 128KB) are handled with anonymous mmap().

More information about the allocator's functionality is provided in Buddy_Allocator_PDF.pdf
