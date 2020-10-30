/* based on drivers/scsi/st.c & cryptodev-linux */
#include <linux/scatterlist.h>
#include <linux/err.h>
#include <linux/atomic.h>
#include <linux/virtio.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include "accel.h"
#include "virtio_accel-common.h"

#define PAGEOFFSET(buf) ((unsigned long)buf & ~PAGE_MASK)
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
	unsigned int offset = 0;
	const int max_pages = PAGECOUNT(uaddr, ulen);
	int ret = 0, i, pg_len, nr_pages;
	struct page **pages;
	struct scatterlist *sg;
	size_t len = ulen;
	void *buf;
//	struct timespec ts1, ts2, ts3, ts4, ts5, ts;

	/* User attempted overflow! */
	if ((uaddr + ulen) < uaddr)
		return -EINVAL;

	if (ulen == 0)
		return 0;
	
	//ktime_get_ts(&ts1);
	pages = kzalloc(max_pages * sizeof(*m_pages), GFP_ATOMIC);
	if (!pages)
		return -ENOMEM;

//	ktime_get_ts(&ts2);
	nr_pages = get_user_pages_fast(uaddr, max_pages, write ? FOLL_WRITE : 0, pages);
	//printk("WRITE: %d, NR_PAGES: %d, ULEN: %ld, PAGE_SIZE: %ld\n",  write ? FOLL_WRITE : 0, nr_pages, ulen, PAGE_SIZE);
	if (nr_pages < max_pages)
		goto out_unmap;

//	ktime_get_ts(&ts3);
//	for (i = 0; i < nr_pages; i++) {
//		/* FIXME: flush superflous for rw==READ,
//		 * probably wrong function for rw==WRITE
//		 */
//		flush_dcache_page(pages[i]);
//	}

//	ktime_get_ts(&ts4);
	
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
		//printk("- %d", i);
		pg_len = min(PAGE_SIZE, ulen);
		sg_set_page(sg, pages[i+1], pg_len, 0);
		ulen -= pg_len;
		if (!ulen)
			break;
	}
	
//	ktime_get_ts(&ts5);
//	ts = timespec_sub(ts2, ts1);
//	printk("TIME 1-2: %lus%luns \r\n", ts.tv_sec, ts.tv_nsec);
//	ts = timespec_sub(ts3, ts2);
//	printk("TIME 2-3: %lus%luns \r\n", ts.tv_sec, ts.tv_nsec);
//	ts = timespec_sub(ts4, ts3);
//	printk("TIME 3-4: %lus%luns \r\n", ts.tv_sec, ts.tv_nsec);
//	ts = timespec_sub(ts5, ts4);
//	printk("TIME 4-5: %lus%luns \r\n", ts.tv_sec, ts.tv_nsec);

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
