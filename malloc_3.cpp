#include <unistd.h>
#include <string.h>
#include <iostream>
#include <sys/mman.h>

#define MAX_ALLOC_SIZE 1e8
#define MIN_BLOCK_SIZE 128
#define MAX_ORDER 10
#define BLOCK_SIZE (MIN_BLOCK_SIZE << MAX_ORDER) // 128KB sized block

typedef struct MallocMetadata {
    size_t size;
    bool is_free;
    MallocMetadata* next;
    MallocMetadata* prev;
} MetaData;

class BlockList {
public:
    MetaData* head;

    BlockList() : head(nullptr) {}

    void add(MetaData* block) { // add sorts by address
        if (!head) {
            head = block;
            block->next = nullptr;
            block->prev = nullptr;
            return;
        }
        MetaData* current = head;
        while (current->next && current < block) {
            current = current->next;
        }
        if (current == head && block < current) { // block inserts at the beginning
            block->next = current;
            block->prev = nullptr;
            current->prev = block;
            head = block;
        }
        else if (current->next == nullptr && current < block) { // block inserts at the end
            block->next = nullptr;
            block->prev = current;
            current->next = block;
        }
        else { // block inserts in the middle (before current)
            block->next = current;
            block->prev = current->prev;
            current->prev->next = block;
            current->prev = block;
        }
    }

    void remove(MetaData* block) {
        if (block->prev) {
            block->prev->next = block->next;
        } 
        else {
            head = block->next;
        }
        if (block->next) {
            block->next->prev = block->prev;
        }
        block->next = nullptr;
        block->prev = nullptr;
    }

    MetaData* find(size_t size) {
        MetaData* current = head;
        while (current && current->size < size) {
            current = current->next;
        }
        return current;
    }

    bool contains(MetaData* block) {
        MetaData* current = head;
        while (current) {
            if (current == block) {
                return true;
            }
            current = current->next;
        }
        return false;
    }
};

class MallocList {

public:
    bool is_allocated;
    BlockList free_blocks[MAX_ORDER + 1];
    BlockList mmap_blocks;
    size_t allocated_blocks_count; // does not include *free blocks*
    size_t allocated_blocks_size; // does not include *free bytes*
    size_t mmap_allocated_blocks_size;
    void* heap_start = nullptr;

    // list related functions
    MallocList(): is_allocated(false), allocated_blocks_count(0), allocated_blocks_size(0), mmap_allocated_blocks_size(0) {}

    void initialAllocation() {
        void* aligned_start = sbrk(0);
        size_t alignment_offset = (uintptr_t)aligned_start % (BLOCK_SIZE * 32);
        int alignment_param = 1;
        if (alignment_offset == 0) {
            alignment_param = 0; // if address is already aligned, alignemnt value will be zero.
        }

        heap_start = sbrk((alignment_param * ((BLOCK_SIZE * 32) - alignment_offset)) + (BLOCK_SIZE * 32)); // alignment + 32 block allocation
        if (heap_start == (void*)(-1)) {
            heap_start = nullptr;
            return;
        }
        else {
            heap_start = (void*)((char*)heap_start + (alignment_param * ((BLOCK_SIZE * 32) - alignment_offset))); // add alignment to start at first block
            for (int i = 0; i < 32; ++i) {
                MetaData* block = (MetaData*)((char*)heap_start + (i * BLOCK_SIZE));
                block->size = BLOCK_SIZE;
                block->is_free = true;
                block->next = nullptr;
                block->prev = nullptr;
                free_blocks[MAX_ORDER].add(block);
            }
        }
        is_allocated = true;
    }

    MetaData* findSuitableBlock(size_t size);
    void splitBlock(MetaData* block, int target_order, int current_order);
    void mergeBlock(MetaData* block);
    void printList();
    // memory related functions
    void* mallocBlock(size_t size);
    void freeBlock(void* data_ptr);

    // stats related functions
    size_t numAllocatedBlocks();
    size_t numFreeBlocks();
    size_t numAllocatedBytes();
    size_t numFreeBytes();
};

/**********************************************************************/
/**                                                                  **/
/**                      MallocList Functions                        **/
/**                                                                  **/
/**********************************************************************/

MetaData* MallocList::findSuitableBlock(size_t real_size) {
    int order = 0;
    while ((MIN_BLOCK_SIZE << order) < real_size) {
        order++;
    }
    for (int i = order; i <= MAX_ORDER; ++i) {
        MetaData* block = free_blocks[i].find(real_size);
        if (block) {
            return block;
        }
    }
    return nullptr;
}

void MallocList::splitBlock(MetaData* block, int target_order, int current_order) {
    
    while (current_order > target_order) {
        current_order--;
        MetaData* buddy = (MetaData*)((char*)block + (MIN_BLOCK_SIZE << current_order));
        buddy->size = MIN_BLOCK_SIZE << current_order;
        buddy->is_free = true;
        buddy->next = nullptr;
        buddy->prev = nullptr;
        free_blocks[current_order].add(buddy);
        block->size = MIN_BLOCK_SIZE << current_order;
    }
}

void MallocList::mergeBlock(MetaData* block) {
    int order = 0;
    block->size += sizeof(MetaData);
    while ((MIN_BLOCK_SIZE << order) < block->size) {
        order++;
    }
    void* block_addr = (void*)block;
    while (order < MAX_ORDER) {
        size_t buddy_offset = (size_t)block_addr ^ (MIN_BLOCK_SIZE << order);
        MetaData* buddy = (MetaData*)buddy_offset;
        if (free_blocks[order].contains(buddy)) {
            free_blocks[order].remove(buddy);
            block_addr = std::min(block_addr, (void*)buddy);
            block = (MetaData*)block_addr;
            block->size = MIN_BLOCK_SIZE << (order + 1);
            order++;
        } else {
            break;
        }
    }
    free_blocks[order].add(block);
}

void MallocList::printList(){
    for (int i = 0; i <= MAX_ORDER; i++) {
        MetaData* current = free_blocks[i].head;
        int num = 0;
        std::cout << "Order " << i << ": ";
        while (current) {
            num++;
            current = current->next;
        }
        std::cout << num << std::endl;
    }
}

void* MallocList::mallocBlock(size_t size) {
    size_t real_block_size = (size + sizeof(MetaData));
    // checks for large allocation (128KB or more)
    if (real_block_size >= BLOCK_SIZE) {
        void* mmap_block = mmap(nullptr, real_block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mmap_block == MAP_FAILED) {
            return nullptr;
        }
        MetaData* block = (MetaData*)mmap_block;
        block->size = real_block_size - sizeof(MetaData);
        block->is_free = false;
        block->next = nullptr;
        block->prev = nullptr;
        mmap_blocks.add(block);
        mmap_allocated_blocks_size += block->size;
        allocated_blocks_count++;
        return ((char*)block + sizeof(MetaData));
    }

    MetaData* block = findSuitableBlock(real_block_size);
    if (block == nullptr) {
        return nullptr;
    }

    int target_order = 0;
    while ((MIN_BLOCK_SIZE << target_order) < real_block_size) {
        target_order++;
    }
    int current_order;
    for (current_order = target_order; current_order <= MAX_ORDER; ++current_order) {
        if (free_blocks[current_order].contains(block)) {
            free_blocks[current_order].remove(block);
            break;
        }
    }
    splitBlock(block, target_order, current_order);
    block->size -= sizeof(MetaData);
    block->is_free = false;
    allocated_blocks_count++;
    allocated_blocks_size += block->size;
    return ((char*)block + sizeof(MetaData));
}

void MallocList::freeBlock(void* data_ptr) {
    MetaData* block = (MetaData*)((char*)data_ptr - sizeof(MetaData));
    if (block->size > (BLOCK_SIZE - sizeof(MetaData))) {
        mmap_blocks.remove(block);
        mmap_allocated_blocks_size -= block->size;
        munmap((void*)block, block->size + sizeof(MetaData));
    }
    else {
        block->is_free = true;
        allocated_blocks_size -= block->size;
        mergeBlock(block);
    }
    allocated_blocks_count--;
}

size_t MallocList::numAllocatedBlocks() {
    return allocated_blocks_count + numFreeBlocks();
}

size_t MallocList::numFreeBlocks() {
    size_t num = 0;
    for (int i = 0; i <= MAX_ORDER; ++i) {
        MetaData* current = free_blocks[i].head;
        while (current) {
            num++;
            current = current->next;
        }
    }
    return num;
}

size_t MallocList::numFreeBytes() { // does not include metadata bytes in each block
    size_t num = 0;
    for (int i = 0; i <= MAX_ORDER; ++i) {
        MetaData* current = free_blocks[i].head;
        while (current) {
            if (current->is_free) {
                num += (current->size - sizeof(MetaData));
            }
            current = current->next;
        }
    }
    return num;
}

size_t MallocList::numAllocatedBytes() {
    return allocated_blocks_size + mmap_allocated_blocks_size + numFreeBytes();
}


/**********************************************************************/
/**                                                                  **/
/**                       Allocation Functions                       **/
/**                                                                  **/
/**********************************************************************/

MallocList malloc_list = MallocList();

void* smalloc(size_t size) {
    if (!malloc_list.is_allocated) {
        malloc_list.initialAllocation();
    }
    if (size == 0 || size > MAX_ALLOC_SIZE) {
        return nullptr;
    }
    void* block = malloc_list.mallocBlock(size);
    if (block == nullptr) {
        return nullptr;
    }
    return block;
}

void* scalloc(size_t num, size_t size) {
    void* data_ptr = smalloc(num * size);
    if (data_ptr == nullptr) {
        return nullptr;
    }
    memset(data_ptr, 0, (num * size));
    return data_ptr;
}

void sfree(void* p) {
    if (p == nullptr) {
        return;
    }
    malloc_list.freeBlock(p);
}

void* srealloc(void* oldp, size_t size) {
    if (size == 0 || size > MAX_ALLOC_SIZE) {
        return nullptr;
    }
    if (oldp == nullptr) {
        return smalloc(size);
    }

    MetaData* block = (MetaData*)((char*)oldp - sizeof(MetaData));
    size_t old_size = block->size;
    size_t current_size = block->size + sizeof(MetaData);

    //mmap block handler
    if (current_size > BLOCK_SIZE) {
        if (block->size == size) {
            return oldp;
        }
        void* newp = smalloc(size);
        if (newp == nullptr) {
            return nullptr;
        }
        memmove(newp, oldp, old_size);
        sfree(oldp);
        return newp;
    }

    // reuse old block if it's large enough
    if (size <= old_size) {
        return oldp;
    }

    // check if merging can result a a large enough block (no actual merging is done yet)
    size_t required_size = size + sizeof(MetaData);
    MetaData* current_block = block;
    MetaData* buddy = nullptr;
    int order = 0;
    while ((MIN_BLOCK_SIZE << order) < current_size) {
        order++;
    }
    int target_order = order;
    while (target_order < MAX_ORDER) {
        size_t buddy_offset = (size_t)current_block ^ (MIN_BLOCK_SIZE << target_order);
        buddy = (MetaData*)buddy_offset;
        
        if (malloc_list.free_blocks[target_order].contains(buddy)) {
            if (current_block > buddy) {
                void* block_addr = (void*)current_block;
                block_addr = std::min(block_addr, (void*)buddy);
                current_block = (MetaData*)block_addr;
            }
            current_size = MIN_BLOCK_SIZE << (target_order + 1);
            
            if (current_size >= required_size) {
                target_order++;
                break;
            }
            target_order++;
        }
        else {
            break;
        }
    }

    // found a merged block that's large enough
    if (current_size >= required_size) {
        current_block = block;
        while (order < target_order) {
            size_t buddy_offset = (size_t)current_block ^ (MIN_BLOCK_SIZE << order);
            buddy = (MetaData*)buddy_offset;
            if (malloc_list.free_blocks[order].contains(buddy)) {
                malloc_list.free_blocks[order].remove(buddy);
                void* block_addr = (void*)current_block;
                block_addr = std::min(block_addr, (void*)buddy);
                current_block = (MetaData*)block_addr;
                current_block->size = MIN_BLOCK_SIZE << (order + 1);
                order++;
            } else {
                break;
            }
        }
        current_block->size -= sizeof(MetaData);
        current_block->is_free = false;
        malloc_list.allocated_blocks_size += (current_block->size - old_size);
        void* newp = (char*)current_block + sizeof(MetaData);
        memmove(newp, oldp, old_size);
        return newp;
    }

    // find a different block that’s large enough
    void* newp = smalloc(size);
    if (newp == nullptr) {
        return nullptr;
    }
    memmove(newp, oldp, old_size);
    sfree(oldp);

    return newp;
}


/**********************************************************************/
/**                                                                  **/
/**                         Stats Functions                          **/
/**                                                                  **/
/**********************************************************************/


size_t _num_free_blocks() {
    return malloc_list.numFreeBlocks();
}

size_t _num_free_bytes() { // free bytes (not including metadata)
    return malloc_list.numFreeBytes();
}

size_t _num_allocated_blocks() { // free + used blocks
    return malloc_list.numAllocatedBlocks();
}

size_t _num_allocated_bytes() { // free + used bytes (not including metadata)
    return malloc_list.numAllocatedBytes();
}

size_t _num_meta_data_bytes() {
    return ((malloc_list.numAllocatedBlocks()) * sizeof(MetaData));
}

size_t _size_meta_data() {
    return (sizeof(MetaData));
}
