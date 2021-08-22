/*
 * Copyright © 2014 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

#include <linux/mm.h>
#include <linux/io-mapping.h>

#include <asm/pgtable.h>

#include "i915_drv.h"

#ifdef __FreeBSD__
#include <vm/vm_pageout.h>
#define	pte_t	linux_pte_t
#endif

struct remap_pfn {
	struct mm_struct *mm;
	unsigned long pfn;
#ifdef __linux__
	pgprot_t prot;
#elif defined(__FreeBSD__)
	struct vm_area_struct *vma;
	vm_memattr_t attr;
#endif

	struct sgt_iter sgt;
	resource_size_t iobase;
};

#ifdef __FreeBSD__
static inline int
insert_pfn(vm_object_t vm_obj, unsigned long addr, unsigned long pfn,
    vm_memattr_t attr)
{
	vm_page_t m;
	vm_paddr_t pa;
	vm_pindex_t pidx;
	vm_object_t rmobj;

	VM_OBJECT_ASSERT_WLOCKED(vm_obj);
	pa = IDX_TO_OFF(pfn);
	pidx = OFF_TO_IDX(addr);

retry:
	m = vm_page_grab(vm_obj, pidx, VM_ALLOC_NOCREAT);
	if (m == NULL) {
		m = PHYS_TO_VM_PAGE(pa);
		if (!vm_page_busy_acquire(m, VM_ALLOC_WAITFAIL))
			goto retry;
		if (m->object != NULL) {
			rmobj = m->object;
			VM_OBJECT_WUNLOCK(vm_obj);
			VM_OBJECT_WLOCK(rmobj);
			vm_page_remove(m);
			VM_OBJECT_WUNLOCK(rmobj);
			VM_OBJECT_WLOCK(vm_obj);
			goto retry;
		}
		if (vm_page_insert(m, vm_obj, pidx)) {
			vm_page_xunbusy(m);
#if 0
			return (-ENOMEM);
#else
			VM_OBJECT_WUNLOCK(vm_obj);
			vm_wait(NULL);
			VM_OBJECT_WLOCK(vm_obj);
			goto retry;
#endif
		}
		vm_page_valid(m);
	}
	pmap_page_set_memattr(m, attr);

	return (0);
}

#define	apply_to_page_range(dummy, addr, size, fn, data)	\
	_apply_to_page_range(addr, size, fn, data)
static int
_apply_to_page_range(unsigned long start_addr, unsigned long size,
    pte_fn_t fn,  struct remap_pfn *r)
{
	unsigned long addr;
	int err = 0;

	r->vma->vm_pfn_first = OFF_TO_IDX(start_addr);
	VM_OBJECT_WLOCK(r->vma->vm_obj);
	for (addr = start_addr; addr < start_addr + size; addr += PAGE_SIZE) {
		err = fn(0, addr, r);
		if (err)
			break;
		r->vma->vm_pfn_count++;
	}
	VM_OBJECT_WUNLOCK(r->vma->vm_obj);

	return (err);
}
#endif

static int remap_pfn(pte_t *pte, unsigned long addr, void *data)
{
	struct remap_pfn *r = data;

#ifdef __linux__
	/* Special PTE are not associated with any struct page */
	set_pte_at(r->mm, addr, pte, pte_mkspecial(pfn_pte(r->pfn, r->prot)));
#elif defined(__FreeBSD__)
	insert_pfn(r->vma->vm_obj, addr, r->pfn, r->attr);
#endif
	r->pfn++;

	return 0;
}

#define use_dma(io) ((io) != -1)

static inline unsigned long sgt_pfn(const struct remap_pfn *r)
{
	if (use_dma(r->iobase))
		return (r->sgt.dma + r->sgt.curr + r->iobase) >> PAGE_SHIFT;
	else
		return r->sgt.pfn + (r->sgt.curr >> PAGE_SHIFT);
}

static int remap_sg(pte_t *pte, unsigned long addr, void *data)
{
	struct remap_pfn *r = data;

	if (GEM_WARN_ON(!r->sgt.pfn))
		return -EINVAL;

#ifdef __linux__
	/* Special PTE are not associated with any struct page */
	set_pte_at(r->mm, addr, pte,
		   pte_mkspecial(pfn_pte(sgt_pfn(r), r->prot)));
#elif defined(__FreeBSD__)
	insert_pfn(r->vma->vm_obj, addr, sgt_pfn(r), r->attr);
#endif
	r->pfn++; /* track insertions in case we need to unwind later */

	r->sgt.curr += PAGE_SIZE;
	if (r->sgt.curr >= r->sgt.max)
		r->sgt = __sgt_iter(__sg_next(r->sgt.sgp), use_dma(r->iobase));

	return 0;
}

/**
 * remap_io_mapping - remap an IO mapping to userspace
 * @vma: user vma to map to
 * @addr: target user address to start at
 * @pfn: physical address of kernel memory
 * @size: size of map area
 * @iomap: the source io_mapping
 *
 *  Note: this is only safe if the mm semaphore is held when called.
 */
int remap_io_mapping(struct vm_area_struct *vma,
		     unsigned long addr, unsigned long pfn, unsigned long size,
		     struct io_mapping *iomap)
{
	struct remap_pfn r;
	int err;

#define EXPECTED_FLAGS (VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP)
	GEM_BUG_ON((vma->vm_flags & EXPECTED_FLAGS) != EXPECTED_FLAGS);

	/* We rely on prevalidation of the io-mapping to skip track_pfn(). */
	r.mm = vma->vm_mm;
	r.pfn = pfn;
#ifdef __linux__
	r.prot = __pgprot((pgprot_val(iomap->prot) & _PAGE_CACHE_MASK) |
			  (pgprot_val(vma->vm_page_prot) & ~_PAGE_CACHE_MASK));
#elif defined(__FreeBSD__)
	r.vma = vma;
	r.attr = iomap->attr;
#endif

	err = apply_to_page_range(r.mm, addr, size, remap_pfn, &r);
	if (unlikely(err)) {
		zap_vma_ptes(vma, addr, (r.pfn - pfn) << PAGE_SHIFT);
		return err;
	}

	return 0;
}

/**
 * remap_io_sg - remap an IO mapping to userspace
 * @vma: user vma to map to
 * @addr: target user address to start at
 * @size: size of map area
 * @sgl: Start sg entry
 * @iobase: Use stored dma address offset by this address or pfn if -1
 *
 *  Note: this is only safe if the mm semaphore is held when called.
 */
int remap_io_sg(struct vm_area_struct *vma,
		unsigned long addr, unsigned long size,
		struct scatterlist *sgl, resource_size_t iobase)
{
	struct remap_pfn r = {
		.mm = vma->vm_mm,
#ifdef __linux__
		.prot = vma->vm_page_prot,
#elif defined(__FreeBSD__)
		.vma = vma,
		.attr = pgprot2cachemode(vma->vm_page_prot),
#endif
		.sgt = __sgt_iter(sgl, use_dma(iobase)),
		.iobase = iobase,
	};
	int err;

	/* We rely on prevalidation of the io-mapping to skip track_pfn(). */
	GEM_BUG_ON((vma->vm_flags & EXPECTED_FLAGS) != EXPECTED_FLAGS);

#ifdef __linux__
	if (!use_dma(iobase))
		flush_cache_range(vma, addr, size);
#endif

	err = apply_to_page_range(r.mm, addr, size, remap_sg, &r);
	if (unlikely(err)) {
		zap_vma_ptes(vma, addr, r.pfn << PAGE_SHIFT);
		return err;
	}

	return 0;
}
