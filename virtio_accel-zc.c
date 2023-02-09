/* based on drivers/scsi/st.c & cryptodev-linux */
#include <linux/scatterlist.h>
#include <linux/err.h>
#include <linux/atomic.h>
#include <linux/virtio.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include "accel.h"
#include "virtio_accel-common.h"

#define PAGECOUNT(buf, buflen) ((buflen) \
		? ((((unsigned long)((unsigned long)buf + buflen - 1)) \
				>> PAGE_SHIFT) - \
			(((unsigned long)(buf             )) >> PAGE_SHIFT) + 1) \
		: 0)

int virtaccel_map_user_buf(struct sg_table **m_sgt, struct page ***m_pages,
						   void __user *_uaddr, size_t ulen,
						   int write, struct virtio_device *vdev)
{
	unsigned long uaddr = (unsigned long)_uaddr;
	const int max_pages = PAGECOUNT(uaddr, ulen);
	int ret = 0, i, pg_len, nr_pages;
	struct page **pages;
	struct scatterlist *sg;

	/* User attempted overflow! */
	if ((uaddr + ulen) < uaddr)
		return -EINVAL;

	if (ulen == 0)
		return 0;
	
	pages = kzalloc(max_pages * sizeof(*m_pages), GFP_ATOMIC);
	if (!pages)
		return -ENOMEM;

	nr_pages = get_user_pages_fast(uaddr, max_pages, write ? FOLL_WRITE : 0, pages);
	if (nr_pages < max_pages)
		goto out_unmap;

	*m_sgt = kzalloc(sizeof(**m_sgt), GFP_ATOMIC);
	if (!*m_sgt) {
		ret = -ENOMEM;
		goto out_unmap;
	}

	ret = sg_alloc_table(*m_sgt, nr_pages, GFP_ATOMIC);
	if (ret < 0)
		goto out_free_table;

	i = 0;
	pg_len = min((ptrdiff_t)(PAGE_SIZE - PAGEOFFSET(uaddr)), (ptrdiff_t)ulen);
	sg_set_page((*m_sgt)->sgl, pages[i], pg_len, PAGEOFFSET(uaddr));
	ulen -= pg_len;

	for_each_sg(sg_next((*m_sgt)->sgl), sg, (*m_sgt)->orig_nents - 1, i) {
		pg_len = min(PAGE_SIZE, ulen);
		sg_set_page(sg, pages[i+1], pg_len, 0);
		ulen -= pg_len;
		if (!ulen)
			break;
	}

	*m_pages = pages;

	return nr_pages;

out_free_table:
	kfree(*m_sgt);
out_unmap:
	if (nr_pages > 0) {
		for (i = 0; i < nr_pages; i++)
			put_page(pages[i]);
		if (ret == 0)
			ret = -EFAULT;
	}
	kfree(pages);
	return ret;
}

void virtaccel_unmap_user_buf(struct sg_table *m_sgt, struct page **m_pages,
				const unsigned int nr_pages)
{
	int i;

	sg_free_table(m_sgt);
	for (i=0; i < nr_pages; i++) {
		struct page *page = m_pages[i];

		if (!PageReserved(page))
			SetPageDirty(page);
		// FIXME: cache flush missing for rw==READ
		// flush_dcache_page(page);
		put_page(page);
	}
	kfree(m_pages);
}
