// tiny_alloc.c
#define _DEFAULT_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/// --------- Tunables / Macros ----------
#define ALIGN 16UL
#define ALIGN_UP(x) (((x) + (ALIGN - 1)) & ~(ALIGN - 1))
#define HDR_SIZE ((long)sizeof(header_t))
#define FTR_SIZE ((long)sizeof(size_t))
#define MIN_BLOCK                                                              \
  (long)ALIGN_UP(HDR_SIZE + FTR_SIZE +                                         \
                 2 * sizeof(void *)) // header+footer+prev+next
#define ALLOC_BIT ((size_t)1)

/// --------- Block Header / Free Node ----------
typedef struct header {
  size_t size_and_flags; // low bit = allocated?, rest = size including
                         // header+footer (and free links if free)
} header_t;

// In a FREE block, immediately after header is a free node {prev,next}
typedef struct free_node {
  struct free_node *prev;
  struct free_node *next;
} free_node_t;

/// --------- Free list head ----------
static free_node_t free_list_sentinel = {&free_list_sentinel,
                                         &free_list_sentinel};
static inline int free_list_empty(void) {
  return free_list_sentinel.next == &free_list_sentinel;
}

// Track the first heap block so coalesce() can avoid probing before it.
static header_t *heap_start = NULL;

/// --------- Helpers ----------
static inline size_t blk_size(header_t *h) {
  return h->size_and_flags & ~ALLOC_BIT;
}
static inline int blk_allocd(header_t *h) {
  return (int)(h->size_and_flags & ALLOC_BIT);
}
static inline void set_hdr(header_t *h, size_t size, int allocd) {
  h->size_and_flags = size | (allocd ? ALLOC_BIT : 0);
}
static inline void *hdr_to_payload(header_t *h) {
  return (void *)((char *)h + HDR_SIZE);
}
static inline header_t *payload_to_hdr(void *p) {
  return (header_t *)((char *)p - HDR_SIZE);
}
static inline void set_footer(header_t *h) {
  *(size_t *)((char *)h + blk_size(h) - FTR_SIZE) = blk_size(h);
}
static inline size_t read_footer(header_t *h) {
  return *(size_t *)((char *)h + blk_size(h) - FTR_SIZE);
}

static inline header_t *next_hdr(header_t *h) {
  return (header_t *)((char *)h + blk_size(h));
}
static inline header_t *prev_hdr(header_t *h) {
  size_t prev_size = *(size_t *)((char *)h - FTR_SIZE);
  return (header_t *)((char *)h - prev_size);
}

static inline free_node_t *as_freenode(header_t *h) {
  return (free_node_t *)hdr_to_payload(h);
}

static void freelist_insert(header_t *h) {
  free_node_t *n = as_freenode(h);
  n->next = free_list_sentinel.next;
  n->prev = &free_list_sentinel;
  free_list_sentinel.next->prev = n;
  free_list_sentinel.next = n;
}

static void freelist_remove(header_t *h) {
  free_node_t *n = as_freenode(h);
  n->prev->next = n->next;
  n->next->prev = n->prev;
}

/// --------- Heap extension ----------
static header_t *extend_heap(size_t need) {
  // Ensure we request at least MIN_BLOCK and page-aligned-ish growth
  long pagesz = sysconf(_SC_PAGESIZE);
  size_t req = (need < (size_t)pagesz ? (size_t)pagesz : need);
  req = ALIGN_UP(req);

  void *p = sbrk(req);
  if (p == (void *)-1)
    return NULL;

  header_t *h = (header_t *)p;
  set_hdr(h, req, 0);
  set_footer(h);
  // Make an end "epilogue" header (size=0, alloc=1) to simplify next_hdr()
  // bounds
  header_t *epi = next_hdr(h);
  set_hdr(epi, 0, 1);

  if (!heap_start)
    heap_start = h;
  return h;
}

/// --------- Coalescing ----------
static header_t *coalesce(header_t *h) {
  header_t *res = h;

  // Coalesce with next if free
  header_t *nh = next_hdr(h);
  if (blk_size(nh) && !blk_allocd(nh)) {
    freelist_remove(nh);
    size_t newsize = blk_size(h) + blk_size(nh);
    set_hdr(h, newsize, 0);
    set_footer(h);
  }

  // Coalesce with prev if free (need a real prev; footer must exist)
  if (h != heap_start) {
    size_t prevsz = *(size_t *)((char *)h - FTR_SIZE);
    if (prevsz >= MIN_BLOCK && (prevsz % ALIGN == 0)) {
      header_t *ph = prev_hdr(h);
      if (!blk_allocd(ph)) {
        freelist_remove(ph);
        size_t newsize = blk_size(ph) + blk_size(h);
        set_hdr(ph, newsize, 0);
        set_footer(ph);
        res = ph;
      }
    }
  }
  return res;
}

/// --------- Find fit (first-fit) ----------
static header_t *find_fit(size_t asize) {
  for (free_node_t *it = free_list_sentinel.next; it != &free_list_sentinel;
       it = it->next) {
    header_t *h = payload_to_hdr(it);
    if (blk_size(h) >= asize)
      return h;
  }
  return NULL;
}

/// --------- Place (optionally split) ----------
static void place(header_t *h, size_t asize) {
  size_t csize = blk_size(h);
  freelist_remove(h);

  if (csize - asize >= (size_t)MIN_BLOCK) {
    // Split
    set_hdr(h, asize, 1);

    header_t *nh = (header_t *)((char *)h + asize);
    size_t rsize = csize - asize;
    set_hdr(nh, rsize, 0);
    set_footer(nh);
    freelist_insert(nh);
  } else {
    // Use entire block
    set_hdr(h, csize, 1);
  }
}

/// --------- Public API ----------
void *tiny_malloc(size_t size) {
  if (size == 0)
    return NULL;
  size_t asize = ALIGN_UP(size + HDR_SIZE); // header included in block size
  if (asize < (size_t)MIN_BLOCK)
    asize = MIN_BLOCK;

  header_t *h = find_fit(asize);
  if (!h) {
    header_t *newh = extend_heap(asize);
    if (!newh)
      return NULL;
    // Insert then coalesce with trailing epilogue (no-op), then find again
    newh = coalesce(newh);
    freelist_insert(newh);
    h = find_fit(asize);
    if (!h)
      return NULL; // should not happen
  }
  place(h, asize);
  return hdr_to_payload(h);
}

void tiny_free(void *ptr) {
  if (!ptr)
    return;
  header_t *h = payload_to_hdr(ptr);
  if (!blk_allocd(h))
    return; // simple double-free guard (not robust)
  set_hdr(h, blk_size(h), 0);
  set_footer(h);
  h = coalesce(h);
  freelist_insert(h);
}

void *tiny_realloc(void *ptr, size_t size) {
  if (!ptr)
    return tiny_malloc(size);
  if (size == 0) {
    tiny_free(ptr);
    return NULL;
  }

  header_t *h = payload_to_hdr(ptr);
  size_t asize = ALIGN_UP(size + HDR_SIZE);
  if (asize < (size_t)MIN_BLOCK)
    asize = MIN_BLOCK;

  size_t csize = blk_size(h);
  if (asize <= csize) {
    // shrink (optional split)
    if (csize - asize >= (size_t)MIN_BLOCK) {
      set_hdr(h, asize, 1);
      header_t *nh = (header_t *)((char *)h + asize);
      size_t rsize = csize - asize;
      set_hdr(nh, rsize, 0);
      set_footer(nh);
      nh = coalesce(nh);
      freelist_insert(nh);
    }
    return ptr;
  } else {
    // Try grow-in-place by merging with next free neighbor
    header_t *nh = next_hdr(h);
    if (blk_size(nh) && !blk_allocd(nh) && (csize + blk_size(nh) >= asize)) {
      freelist_remove(nh);
      size_t nsize = csize + blk_size(nh);
      set_hdr(h, nsize, 1);
      // maybe split remainder
      if (nsize - asize >= (size_t)MIN_BLOCK) {
        set_hdr(h, asize, 1);
        header_t *r = (header_t *)((char *)h + asize);
        size_t rsz = nsize - asize;
        set_hdr(r, rsz, 0);
        set_footer(r);
        r = coalesce(r);
        freelist_insert(r);
      }
      return hdr_to_payload(h);
    }
    // Fallback: allocate new, copy, free old
    void *np = tiny_malloc(size);
    if (!np)
      return NULL;
    size_t copy = csize - HDR_SIZE; // payload bytes available
    if (copy > size)
      copy = size;
    memcpy(np, ptr, copy);
    tiny_free(ptr);
    return np;
  }
}
