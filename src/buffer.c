// SPDX-License-Identifier: GPL-2.0

#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/gfp_types.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "buffer.h"

static bool zero_copy = true;
module_param(zero_copy, bool, S_IRUGO);
MODULE_PARM_DESC(zero_copy, "virtio-accel zero-copy");

static inline unsigned int get_page_count(unsigned long addr, size_t len)
{
	unsigned long start, end;

	if (!len)
		return 0;

	start = addr >> PAGE_SHIFT;
	end = (addr + len - 1) >> PAGE_SHIFT;
	return (unsigned int)(end - start + 1);
}

static int buffer_init_pinned(struct virtio_accel_buffer *v_buf,
			      void __user *u_buf, size_t u_len, bool write)
{
	unsigned long u_addr = (unsigned long)u_buf;
	unsigned int nr_pages = get_page_count(u_addr, u_len);
	unsigned int offset = offset_in_page(u_addr);
	int ret = 0;
	struct sg_table *sgt;
	struct page **pages;

	pages = kvcalloc(nr_pages, sizeof(*pages), GFP_KERNEL);
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

	v_buf->sgt = sgt;
	v_buf->pages = pages;
	v_buf->nr_pages = nr_pages;
	v_buf->offset = offset;
	v_buf->v_addr = NULL;
	v_buf->pinned = true;

	return 0;

err_free_sgt:
	sg_free_table(sgt);
	kfree(sgt);
err_unpin:
	unpin_user_pages(pages, nr_pages);
err_free_pages:
	kvfree(pages);
	return ret;
}

static void buffer_release_pinned(struct virtio_accel_buffer *v_buf, bool write)
{
	if (!v_buf->sgt)
		return;

	unpin_user_pages_dirty_lock(v_buf->pages, v_buf->nr_pages, write);

	sg_free_table(v_buf->sgt);
	kfree(v_buf->sgt);
	kvfree(v_buf->pages);
}

static int buffer_init_copied(struct virtio_accel_buffer *v_buf,
			      void __user *u_buf, size_t u_len, bool write)
{
	v_buf->buf = memdup_user(u_buf, u_len);
	if (IS_ERR(v_buf->buf))
		return PTR_ERR(v_buf->buf);

	v_buf->pinned = false;
	return 0;
}

static void buffer_release_copied(struct virtio_accel_buffer *v_buf, bool write)
{
	(void)write;
	kfree_sensitive(v_buf->buf);
}

int virtio_accel_buffer_init(struct virtio_accel_buffer *v_buf,
			     void __user *u_buf, size_t u_len, bool write)
{
	unsigned long u_addr = (unsigned long)u_buf;

	if (!v_buf || (u_len && !u_buf))
		return -EINVAL;

	if (!u_len) {
		memset(v_buf, 0, sizeof(*v_buf));
		return 0;
	}

	/* Check for overflow */
	if ((u_addr + u_len) < u_addr)
		return -EINVAL;

	v_buf->u_buf = u_buf;
	v_buf->len = u_len;

	if (zero_copy)
		return buffer_init_pinned(v_buf, u_buf, u_len, write);

	return buffer_init_copied(v_buf, u_buf, u_len, write);
}

void virtio_accel_buffer_release(struct virtio_accel_buffer *v_buf, bool write)
{
	if (!v_buf || !v_buf->len)
		return;

	virtio_accel_buffer_unmap(v_buf);

	if (zero_copy)
		buffer_release_pinned(v_buf, write);
	else
		buffer_release_copied(v_buf, write);

	memset(v_buf, 0, sizeof(*v_buf));
}

void *virtio_accel_buffer_map(struct virtio_accel_buffer *v_buf)
{
	if (!v_buf || !v_buf->len)
		return NULL;

	if (!v_buf->pinned)
		return v_buf->buf;

	if (v_buf->v_addr)
		return v_buf->v_addr + v_buf->offset;

	void *v_addr =
		vmap(v_buf->pages, v_buf->sgt->orig_nents, VM_MAP, PAGE_KERNEL);
	if (!v_addr)
		return NULL;

	v_buf->v_addr = v_addr;
	return v_buf->v_addr + v_buf->offset;
}

void virtio_accel_buffer_unmap(struct virtio_accel_buffer *v_buf)
{
	if (!v_buf)
		return;

	if (v_buf->pinned) {
		vunmap(v_buf->v_addr);
		v_buf->v_addr = NULL;
	}
}

int virtio_accel_buffer_copy_to_user(struct virtio_accel_buffer *v_buf)
{
	if (!v_buf || !v_buf->len)
		return -EINVAL;

	if (v_buf->pinned)
		return 0;

	if (unlikely(copy_to_user(v_buf->u_buf, v_buf->buf, v_buf->len)))
		return -EFAULT;
	return 0;
}
