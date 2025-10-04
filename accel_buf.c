// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/virtio.h>

#include "accel-internal.h"

#ifdef ZC

static inline unsigned int get_page_count(unsigned long addr, size_t len)
{
	unsigned long start, end;

	if (!len)
		return 0;

	start = addr >> PAGE_SHIFT;
	end = (addr + len - 1) >> PAGE_SHIFT;
	return (unsigned int)(end - start + 1);
}

static int __accel_buf_init(struct accel_buf *a_buf, void __user *u_buf,
			    size_t u_len, bool write)
{
	unsigned long u_addr = (unsigned long)u_buf;
	unsigned int nr_pages = get_page_count(u_addr, u_len);
	unsigned int offset = offset_in_page(u_addr);
	int ret = 0;
	struct sg_table *sgt;
	struct page **pages;

	pages = kcalloc(nr_pages, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	ret = pin_user_pages_fast(u_addr, (int)nr_pages, write ? FOLL_WRITE : 0,
				  pages);
	if (ret < 0)
		goto err_free_pages;

	if (ret != nr_pages) {
		unpin_user_pages(pages, ret);
		ret = -EFAULT;
		goto err_free_pages;
	}

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt) {
		ret = -ENOMEM;
		goto err_unpin;
	}

	ret = sg_alloc_table_from_pages(sgt, pages, nr_pages, offset, u_len,
					GFP_KERNEL);
	if (ret)
		goto err_free_sgt;

	a_buf->sgt = sgt;
	a_buf->pages = pages;
	a_buf->offset = offset;
	a_buf->v_addr = NULL;
	a_buf->pinned = true;

	return 0;

err_free_sgt:
	kfree(sgt);
err_unpin:
	unpin_user_pages(pages, nr_pages);
err_free_pages:
	kfree(pages);
	return ret;
}

static void __accel_buf_release(struct accel_buf *a_buf, bool write)
{
	if (!a_buf->sgt)
		return;

	unpin_user_pages_dirty_lock(a_buf->pages, a_buf->sgt->orig_nents,
				    write);

	sg_free_table(a_buf->sgt);
	kfree(a_buf->pages);
	kfree(a_buf->sgt);
}

#else

static int __accel_buf_init(struct accel_buf *a_buf, void __user *u_buf,
			    size_t u_len, bool write)
{
	a_buf->buf = memdup_user(u_buf, u_len);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	a_buf->pinned = false;
	return 0;
}

static void __accel_buf_release(struct accel_buf *a_buf, bool write)
{
	(void)write;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	kzfree(a_buf->buf);
#else
	kfree_sensitive(a_buf->buf);
#endif
}

#endif

int accel_buf_init(struct accel_buf *a_buf, void __user *u_buf, size_t u_len,
		   bool write)
{
	unsigned long u_addr = (unsigned long)u_buf;

	if (!a_buf || (u_len && !u_buf))
		return -EINVAL;

	if (!u_len) {
		memset(a_buf, 0, sizeof(*a_buf));
		return 0;
	}

	/* Check for overflow */
	if ((u_addr + u_len) < u_addr)
		return -EINVAL;

	a_buf->u_buf = u_buf;
	a_buf->len = u_len;

	return __accel_buf_init(a_buf, u_buf, u_len, write);
}

void accel_buf_release(struct accel_buf *a_buf, bool write)
{
	if (!a_buf || !a_buf->len)
		return;

	accel_buf_unmap(a_buf);
	__accel_buf_release(a_buf, write);

	memset(a_buf, 0, sizeof(*a_buf));
}

void *accel_buf_map(struct accel_buf *a_buf)
{
	if (!a_buf || !a_buf->len)
		return NULL;

	if (!a_buf->pinned)
		return a_buf->buf;

	if (a_buf->v_addr)
		return a_buf->v_addr + a_buf->offset;

	void *v_addr =
		vmap(a_buf->pages, a_buf->sgt->orig_nents, VM_MAP, PAGE_KERNEL);
	if (!v_addr)
		return NULL;

	a_buf->v_addr = v_addr;
	return a_buf->v_addr + a_buf->offset;
}

void accel_buf_unmap(struct accel_buf *a_buf)
{
	if (!a_buf)
		return;

	if (a_buf->pinned) {
		vunmap(a_buf->v_addr);
		a_buf->v_addr = NULL;
	}
}

int accel_buf_copy_to_user(struct accel_buf *a_buf)
{
	if (!a_buf || !a_buf->len)
		return -EINVAL;

	if (a_buf->pinned)
		return 0;

	if (unlikely(copy_to_user(a_buf->u_buf, a_buf->buf, a_buf->len)))
		return -EFAULT;
	return 0;
}
