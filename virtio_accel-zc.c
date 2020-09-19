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

int virtaccel_map_user_buf(struct scatterlist *mpages_sg, struct page ***mpages,
						   void __user *_uaddr, size_t ulen, int rw,
						   struct virtio_device *vdev)
{
	unsigned long uaddr = (unsigned long)_uaddr;
	const int nr_pages = PAGECOUNT(uaddr, ulen);
	int ret, i, pg_len;
	struct page **pages;
	struct scatterlist *sg;
//	struct timespec ts1, ts2, ts3, ts4, ts5, ts;

	/* User attempted overflow! */
	if ((uaddr + ulen) < uaddr)
		return -EINVAL;

	if (ulen == 0)
		return 0;
	
	//ktime_get_ts(&ts1);
	pages = kzalloc_node(nr_pages * sizeof(*mpages), GFP_ATOMIC,
					dev_to_node(&vdev->dev));
	if (!pages)
		return -ENOMEM;

//	ktime_get_ts(&ts2);
	ret = get_user_pages_fast(uaddr, nr_pages, rw, pages);
	if (ret < nr_pages)
		goto out_unmap;

//	ktime_get_ts(&ts3);
	for (i = 0; i < nr_pages; i++) {
		/* FIXME: flush superflous for rw==READ,
		 * probably wrong function for rw==WRITE
		 */
		flush_dcache_page(pages[i]);
	}

//	ktime_get_ts(&ts4);
/*
 * FIXME: PAGECOUNT (+PAGE_SIZE) ???
 * 		  PAGE ALIGNMENT ????
 */

	sg_init_table(mpages_sg, nr_pages);
	i = 0;
	pg_len = min((ptrdiff_t)(PAGE_SIZE - PAGEOFFSET(uaddr)), (ptrdiff_t)ulen);
	sg_set_page(mpages_sg, pages[i++], pg_len, PAGEOFFSET(uaddr));

	ulen -= pg_len;
	for (sg = sg_next(mpages_sg); ulen; sg = sg_next(sg)) {
		pg_len = min(PAGE_SIZE, ulen);
		sg_set_page(sg, pages[i++], pg_len, 0);
		ulen -= pg_len;
	}
	sg_mark_end(sg_last(mpages_sg, nr_pages));

//	ktime_get_ts(&ts5);
//	ts = timespec_sub(ts2, ts1);
//	printk("TIME 1-2: %lus%luns \r\n", ts.tv_sec, ts.tv_nsec);
//	ts = timespec_sub(ts3, ts2);
//	printk("TIME 2-3: %lus%luns \r\n", ts.tv_sec, ts.tv_nsec);
//	ts = timespec_sub(ts4, ts3);
//	printk("TIME 3-4: %lus%luns \r\n", ts.tv_sec, ts.tv_nsec);
//	ts = timespec_sub(ts5, ts4);
//	printk("TIME 4-5: %lus%luns \r\n", ts.tv_sec, ts.tv_nsec);

	*mpages = pages;

	return nr_pages;

out_unmap:
	if (ret > 0) {
		for (i = 0; i < ret; i++)
			put_page(pages[i]);
		ret = -EFAULT;
	}
	kfree(pages);
	return ret;
}

void virtaccel_unmap_user_buf(struct page **mpages, const unsigned int nr_pages)
{
	int i;

	for (i=0; i < nr_pages; i++) {
		struct page *page = mpages[i];

		if (!PageReserved(page))
			SetPageDirty(page);
		/* FIXME: cache flush missing for rw==READ
		 * FIXME: call the correct reference counting function
		 */
		put_page(page);
	}
	kfree(mpages);
}
