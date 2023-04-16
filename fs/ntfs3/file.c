// SPDX-License-Identifier: GPL-2.0
/*
<<<<<<< HEAD
 *  linux/fs/ntfs3/file.c
 *
 * Copyright (C) 2019-2020 Paragon Software GmbH, All rights reserved.
 *
 *  regular file handling primitives for ntfs-based filesystems
 */
=======
 *
 * Copyright (C) 2019-2021 Paragon Software GmbH, All rights reserved.
 *
 *  Regular file handling primitives for NTFS-based filesystems.
 *
 */

>>>>>>> wip
#include <linux/backing-dev.h>
#include <linux/buffer_head.h>
#include <linux/compat.h>
#include <linux/falloc.h>
<<<<<<< HEAD
#include <linux/msdos_fs.h> /* FAT_IOCTL_XXX */
=======
#include <linux/fiemap.h>
>>>>>>> wip
#include <linux/nls.h>

#include "debug.h"
#include "ntfs.h"
#include "ntfs_fs.h"

<<<<<<< HEAD
static int ntfs_ioctl_fitrim(ntfs_sb_info *sbi, unsigned long arg)
=======
static int ntfs_ioctl_fitrim(struct ntfs_sb_info *sbi, unsigned long arg)
>>>>>>> wip
{
	struct fstrim_range __user *user_range;
	struct fstrim_range range;
	struct request_queue *q = bdev_get_queue(sbi->sb->s_bdev);
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!blk_queue_discard(q))
		return -EOPNOTSUPP;

	user_range = (struct fstrim_range __user *)arg;
	if (copy_from_user(&range, user_range, sizeof(range)))
		return -EFAULT;

	range.minlen = max_t(u32, range.minlen, q->limits.discard_granularity);

	err = ntfs_trim_fs(sbi, &range);
	if (err < 0)
		return err;

	if (copy_to_user(user_range, &range, sizeof(range)))
		return -EFAULT;

	return 0;
}

static long ntfs_ioctl(struct file *filp, u32 cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
<<<<<<< HEAD
	ntfs_sb_info *sbi = inode->i_sb->s_fs_info;
	u32 __user *user_attr = (u32 __user *)arg;

	switch (cmd) {
	case FAT_IOCTL_GET_ATTRIBUTES:
		return put_user(le32_to_cpu(ntfs_i(inode)->std_fa), user_attr);

	case FAT_IOCTL_GET_VOLUME_ID:
		return put_user(sbi->volume.ser_num, user_attr);

	case FITRIM:
		return ntfs_ioctl_fitrim(sbi, arg);
	}
	return -ENOTTY; /* Inappropriate ioctl for device */
=======
	struct ntfs_sb_info *sbi = inode->i_sb->s_fs_info;

	switch (cmd) {
	case FITRIM:
		return ntfs_ioctl_fitrim(sbi, arg);
	}
	return -ENOTTY; /* Inappropriate ioctl for device. */
>>>>>>> wip
}

#ifdef CONFIG_COMPAT
static long ntfs_compat_ioctl(struct file *filp, u32 cmd, unsigned long arg)

{
	return ntfs_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));
}
#endif

/*
<<<<<<< HEAD
 * inode_operations::getattr
 */
int ntfs_getattr(const struct path *path, struct kstat *stat, u32 request_mask,
		 u32 flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct super_block *sb = inode->i_sb;
	ntfs_sb_info *sbi = sb->s_fs_info;
	ntfs_inode *ni = ntfs_i(inode);
=======
 * ntfs_getattr - inode_operations::getattr
 */
int ntfs_getattr(const struct path *path,
		 struct kstat *stat, u32 request_mask, u32 flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct ntfs_inode *ni = ntfs_i(inode);
>>>>>>> wip

	if (is_compressed(ni))
		stat->attributes |= STATX_ATTR_COMPRESSED;

	if (is_encrypted(ni))
		stat->attributes |= STATX_ATTR_ENCRYPTED;

	stat->attributes_mask |= STATX_ATTR_COMPRESSED | STATX_ATTR_ENCRYPTED;

	generic_fillattr(inode, stat);

	stat->result_mask |= STATX_BTIME;
<<<<<<< HEAD
	stat->btime.tv_sec = ni->i_crtime.tv_sec;
	stat->btime.tv_nsec = ni->i_crtime.tv_nsec;
	stat->blksize = sbi->cluster_size;
	stat->blocks <<= sbi->cluster_bits - 9;
=======
	stat->btime = ni->i_crtime;
	stat->blksize = ni->mi.sbi->cluster_size; /* 512, 1K, ..., 2M */
>>>>>>> wip

	return 0;
}

<<<<<<< HEAD
static int ntfs_extend_initialized_size(struct file *file, ntfs_inode *ni,
=======
static int ntfs_extend_initialized_size(struct file *file,
					struct ntfs_inode *ni,
>>>>>>> wip
					const loff_t valid,
					const loff_t new_valid)
{
	struct inode *inode = &ni->vfs_inode;
	struct address_space *mapping = inode->i_mapping;
<<<<<<< HEAD
	ntfs_sb_info *sbi = inode->i_sb->s_fs_info;
	loff_t pos = valid;
	int err;

=======
	struct ntfs_sb_info *sbi = inode->i_sb->s_fs_info;
	loff_t pos = valid;
	int err;

	if (is_resident(ni)) {
		ni->i_valid = new_valid;
		return 0;
	}

>>>>>>> wip
	WARN_ON(is_compressed(ni));
	WARN_ON(valid >= new_valid);

	for (;;) {
		u32 zerofrom, len;
		struct page *page;
		void *fsdata;
		u8 bits;
		CLST vcn, lcn, clen;

		if (is_sparsed(ni)) {
			bits = sbi->cluster_bits;
			vcn = pos >> bits;

<<<<<<< HEAD
			err = attr_data_get_block(ni, vcn, &lcn, &clen, NULL);

=======
			err = attr_data_get_block(ni, vcn, 0, &lcn, &clen,
						  NULL);
>>>>>>> wip
			if (err)
				goto out;

			if (lcn == SPARSE_LCN) {
				loff_t vbo = (loff_t)vcn << bits;
				loff_t to = vbo + ((loff_t)clen << bits);

				if (to <= new_valid) {
					ni->i_valid = to;
					pos = to;
					goto next;
				}

<<<<<<< HEAD
				if (vbo < pos)
					pos = vbo;
				else {
=======
				if (vbo < pos) {
					pos = vbo;
				} else {
>>>>>>> wip
					to = (new_valid >> bits) << bits;
					if (pos < to) {
						ni->i_valid = to;
						pos = to;
						goto next;
					}
				}
			}
		}

		zerofrom = pos & (PAGE_SIZE - 1);
		len = PAGE_SIZE - zerofrom;

		if (pos + len > new_valid)
			len = new_valid - pos;

		err = pagecache_write_begin(file, mapping, pos, len, 0, &page,
					    &fsdata);
		if (err)
			goto out;

		zero_user_segment(page, zerofrom, PAGE_SIZE);

<<<<<<< HEAD
		/* this function in any case puts page*/
=======
		/* This function in any case puts page. */
>>>>>>> wip
		err = pagecache_write_end(file, mapping, pos, len, len, page,
					  fsdata);
		if (err < 0)
			goto out;
		pos += len;

next:
		if (pos >= new_valid)
			break;
<<<<<<< HEAD
		balance_dirty_pages_ratelimited(mapping);
	}

	mark_inode_dirty(inode);
=======

		balance_dirty_pages_ratelimited(mapping);
		cond_resched();
	}
>>>>>>> wip

	return 0;

out:
	ni->i_valid = valid;
<<<<<<< HEAD
	ntfs_inode_warning(inode, "failed to extend initialized size to %llx.",
			   new_valid);
	return err;
}

static int ntfs_extend_initialized_size_cmpr(struct file *file, ntfs_inode *ni,
					     const loff_t valid,
					     const loff_t new_valid)
{
	struct inode *inode = &ni->vfs_inode;
	struct address_space *mapping = inode->i_mapping;
	ntfs_sb_info *sbi = inode->i_sb->s_fs_info;
	loff_t pos = valid;
	u8 bits = NTFS_LZNT_CUNIT + sbi->cluster_bits;
	int err;

	WARN_ON(!is_compressed(ni));
	WARN_ON(valid >= new_valid);

	for (;;) {
		u32 zerofrom, len;
		struct page *page;
		CLST frame, vcn, lcn, clen;

		frame = pos >> bits;
		vcn = frame << NTFS_LZNT_CUNIT;

		err = attr_data_get_block(ni, vcn, &lcn, &clen, NULL);

		if (err)
			goto out;

		if (lcn == SPARSE_LCN) {
			loff_t vbo = (loff_t)frame << bits;
			loff_t to = vbo + ((u64)clen << sbi->cluster_bits);

			if (to <= new_valid) {
				ni->i_valid = to;
				pos = to;
				goto next;
			}

			if (vbo >= pos) {
				to = (new_valid >> bits) << bits;
				if (pos < to) {
					ni->i_valid = to;
					pos = to;
					goto next;
				}
			}
		}

		zerofrom = pos & (PAGE_SIZE - 1);
		len = PAGE_SIZE - zerofrom;

		if (pos + len > new_valid)
			len = new_valid - pos;
again:
		page = find_or_create_page(mapping, pos >> PAGE_SHIFT,
					   mapping_gfp_constraint(mapping,
								  ~__GFP_FS));

		if (!page) {
			err = -ENOMEM;
			goto out;
		}

		if (zerofrom && !PageUptodate(page)) {
			err = ntfs_readpage(NULL, page);
			lock_page(page);
			if (page->mapping != mapping) {
				unlock_page(page);
				put_page(page);
				goto again;
			}
			if (!PageUptodate(page)) {
				err = -EIO;
				unlock_page(page);
				put_page(page);
				goto out;
			}
		}

		wait_on_page_writeback(page);

		zero_user_segment(page, zerofrom, PAGE_SIZE);
		if (!zerofrom)
			SetPageUptodate(page);

		ClearPageChecked(page);
		set_page_dirty(page);
		unlock_page(page);
		put_page(page);
		pos += len;
		ni->i_valid = pos;
next:
		if (pos >= new_valid)
			break;
		balance_dirty_pages_ratelimited(mapping);
	}

	mark_inode_dirty(inode);

	return 0;

out:
	ni->i_valid = valid;
	ntfs_inode_warning(
		inode, "failed to extend initialized compressed size to %llx.",
		new_valid);
=======
	ntfs_inode_warn(inode, "failed to extend initialized size to %llx.",
			new_valid);
>>>>>>> wip
	return err;
}

/*
<<<<<<< HEAD
 * ntfs_sparse_cluster
 *
 * Helper function to zero a new allocated clusters
 */
void ntfs_sparse_cluster(struct inode *inode, struct page *page0, loff_t vbo,
			 u32 bytes)
{
	struct address_space *mapping = inode->i_mapping;
	ntfs_sb_info *sbi = inode->i_sb->s_fs_info;
=======
 * ntfs_zero_range - Helper function for punch_hole.
 *
 * It zeroes a range [vbo, vbo_to).
 */
static int ntfs_zero_range(struct inode *inode, u64 vbo, u64 vbo_to)
{
	int err = 0;
	struct address_space *mapping = inode->i_mapping;
	u32 blocksize = 1 << inode->i_blkbits;
	pgoff_t idx = vbo >> PAGE_SHIFT;
	u32 z_start = vbo & (PAGE_SIZE - 1);
	pgoff_t idx_end = (vbo_to + PAGE_SIZE - 1) >> PAGE_SHIFT;
	loff_t page_off;
	struct buffer_head *head, *bh;
	u32 bh_next, bh_off, z_end;
	sector_t iblock;
	struct page *page;

	for (; idx < idx_end; idx += 1, z_start = 0) {
		page_off = (loff_t)idx << PAGE_SHIFT;
		z_end = (page_off + PAGE_SIZE) > vbo_to ? (vbo_to - page_off)
							: PAGE_SIZE;
		iblock = page_off >> inode->i_blkbits;

		page = find_or_create_page(mapping, idx,
					   mapping_gfp_constraint(mapping,
								  ~__GFP_FS));
		if (!page)
			return -ENOMEM;

		if (!page_has_buffers(page))
			create_empty_buffers(page, blocksize, 0);

		bh = head = page_buffers(page);
		bh_off = 0;
		do {
			bh_next = bh_off + blocksize;

			if (bh_next <= z_start || bh_off >= z_end)
				continue;

			if (!buffer_mapped(bh)) {
				ntfs_get_block(inode, iblock, bh, 0);
				/* Unmapped? It's a hole - nothing to do. */
				if (!buffer_mapped(bh))
					continue;
			}

			/* Ok, it's mapped. Make sure it's up-to-date. */
			if (PageUptodate(page))
				set_buffer_uptodate(bh);

			if (!buffer_uptodate(bh)) {
				lock_buffer(bh);
				bh->b_end_io = end_buffer_read_sync;
				get_bh(bh);
				submit_bh(REQ_OP_READ, 0, bh);

				wait_on_buffer(bh);
				if (!buffer_uptodate(bh)) {
					unlock_page(page);
					put_page(page);
					err = -EIO;
					goto out;
				}
			}

			mark_buffer_dirty(bh);

		} while (bh_off = bh_next, iblock += 1,
			 head != (bh = bh->b_this_page));

		zero_user_segment(page, z_start, z_end);

		unlock_page(page);
		put_page(page);
		cond_resched();
	}
out:
	mark_inode_dirty(inode);
	return err;
}

/*
 * ntfs_sparse_cluster - Helper function to zero a new allocated clusters.
 *
 * NOTE: 512 <= cluster size <= 2M
 */
void ntfs_sparse_cluster(struct inode *inode, struct page *page0, CLST vcn,
			 CLST len)
{
	struct address_space *mapping = inode->i_mapping;
	struct ntfs_sb_info *sbi = inode->i_sb->s_fs_info;
	u64 vbo = (u64)vcn << sbi->cluster_bits;
	u64 bytes = (u64)len << sbi->cluster_bits;
>>>>>>> wip
	u32 blocksize = 1 << inode->i_blkbits;
	pgoff_t idx0 = page0 ? page0->index : -1;
	loff_t vbo_clst = vbo & sbi->cluster_mask_inv;
	loff_t end = ntfs_up_cluster(sbi, vbo + bytes);
	pgoff_t idx = vbo_clst >> PAGE_SHIFT;
	u32 from = vbo_clst & (PAGE_SIZE - 1);
	pgoff_t idx_end = (end + PAGE_SIZE - 1) >> PAGE_SHIFT;
	loff_t page_off;
	u32 to;
	bool partial;
	struct page *page;

	for (; idx < idx_end; idx += 1, from = 0) {
		page = idx == idx0 ? page0 : grab_cache_page(mapping, idx);

		if (!page)
			continue;

		page_off = (loff_t)idx << PAGE_SHIFT;
<<<<<<< HEAD
		to = (page_off + PAGE_SIZE) > end ? (end - page_off) :
						    PAGE_SIZE;
=======
		to = (page_off + PAGE_SIZE) > end ? (end - page_off)
						  : PAGE_SIZE;
>>>>>>> wip
		partial = false;

		if ((from || PAGE_SIZE != to) &&
		    likely(!page_has_buffers(page))) {
			create_empty_buffers(page, blocksize, 0);
<<<<<<< HEAD
			if (!page_has_buffers(page)) {
				ntfs_inode_error(
					inode,
					"failed to allocate page buffers.");
				/*err = -ENOMEM;*/
				goto unlock_page;
			}
=======
>>>>>>> wip
		}

		if (page_has_buffers(page)) {
			struct buffer_head *head, *bh;
			u32 bh_off = 0;

			bh = head = page_buffers(page);
			do {
				u32 bh_next = bh_off + blocksize;

				if (from <= bh_off && bh_next <= to) {
					set_buffer_uptodate(bh);
					mark_buffer_dirty(bh);
<<<<<<< HEAD
				} else if (!buffer_uptodate(bh))
					partial = true;
=======
				} else if (!buffer_uptodate(bh)) {
					partial = true;
				}
>>>>>>> wip
				bh_off = bh_next;
			} while (head != (bh = bh->b_this_page));
		}

		zero_user_segment(page, from, to);

		if (!partial) {
			if (!PageUptodate(page))
				SetPageUptodate(page);
			set_page_dirty(page);
		}

<<<<<<< HEAD
unlock_page:
=======
>>>>>>> wip
		if (idx != idx0) {
			unlock_page(page);
			put_page(page);
		}
<<<<<<< HEAD
	}

	mark_inode_dirty(inode);
}

struct ntfs_file_vm_ops {
	atomic_t refcnt;
	loff_t to;

	const struct vm_operations_struct *base;
	struct vm_operations_struct vm_ops;
};

/*
 * vm_operations_struct::open
 */
static void ntfs_filemap_open(struct vm_area_struct *vma)
{
	struct ntfs_file_vm_ops *vm_ops;
	const struct vm_operations_struct *base;

	vm_ops = container_of(vma->vm_ops, struct ntfs_file_vm_ops, vm_ops);
	base = vm_ops->base;

	atomic_inc(&vm_ops->refcnt);

	if (base->open)
		base->open(vma);
}

/*
 * vm_operations_struct::close
 */
static void ntfs_filemap_close(struct vm_area_struct *vma)
{
	struct ntfs_file_vm_ops *vm_ops;
	const struct vm_operations_struct *base;
	struct inode *inode;
	ntfs_inode *ni;
	// unsigned long flags;

	vm_ops = container_of(vma->vm_ops, struct ntfs_file_vm_ops, vm_ops);

	if (!atomic_dec_and_test(&vm_ops->refcnt))
		return;

	base = vm_ops->base;
	if (!(vma->vm_flags & VM_WRITE))
		goto close_base;

	inode = file_inode(vma->vm_file);
	ni = ntfs_i(inode);

	// Update valid size
	// write_lock_irqsave( &ni->rwlock, flags );
	ni->i_valid = max_t(loff_t, ni->i_valid,
			    min_t(loff_t, i_size_read(inode), vm_ops->to));
	// write_unlock_irqrestore( &u->rwlock, flags );

close_base:
	if (base->close)
		base->close(vma);

	vma->vm_ops = base;
	ntfs_free(vm_ops);
}

/*
 * vm_operations_struct::fault
 */
static vm_fault_t ntfs_filemap_fault(struct vm_fault *vmf)
{
	vm_fault_t ret;
	struct ntfs_file_vm_ops *vm_ops;
	struct vm_area_struct *vma = vmf->vma;

	vm_ops = container_of(vma->vm_ops, struct ntfs_file_vm_ops, vm_ops);

	/* Call base function */
	ret = vm_ops->base->fault(vmf);

	if (VM_FAULT_LOCKED & ret) {
		/* Update maximum mapped range */
		loff_t to = (loff_t)(vmf->pgoff + 1) << PAGE_SHIFT;

		if (vm_ops->to < to)
			vm_ops->to = to;
	}

	return ret;
}

/*
 * file_operations::mmap
 */
static int ntfs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file->f_mapping->host;
	ntfs_inode *ni = ntfs_i(inode);
	u64 to, from = ((u64)vma->vm_pgoff << PAGE_SHIFT);
	bool rw = vma->vm_flags & VM_WRITE;
	struct ntfs_file_vm_ops *vm_ops = NULL;
	int err;

	if (is_encrypted(ni)) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!rw)
		goto generic;

	if (is_compressed(ni)) {
		err = -EOPNOTSUPP;
		goto out;
	}

	/*
	 * Allocate and init small struct to keep track the mapping operations
	 * It is useful when mmap(size) + truncate(size/2) + unmap(). see
	 * xfstests/generic/039
	 */
	vm_ops = ntfs_alloc(sizeof(struct ntfs_file_vm_ops), 1);
	if (unlikely(!vm_ops)) {
		err = -ENOMEM;
		goto out;
	}

	// map for write
	inode_lock(inode);

	to = from + vma->vm_end - vma->vm_start;

	if (to > inode->i_size)
		to = inode->i_size;

	if (is_sparsed(ni)) {
		/* allocate clusters for rw map */
		ntfs_sb_info *sbi = inode->i_sb->s_fs_info;
		CLST vcn, lcn, len;
		CLST end = bytes_to_cluster(sbi, to);
		bool new;

		for (vcn = from >> sbi->cluster_bits; vcn < end; vcn += len) {
			err = attr_data_get_block(ni, vcn, &lcn, &len, &new);
			if (err) {
				inode_unlock(inode);
				goto out;
			}
			if (!new)
				continue;
			ntfs_sparse_cluster(inode, NULL,
					    (u64)vcn << sbi->cluster_bits,
					    sbi->cluster_size);
		}
	}

	err = ni->i_valid < to ?
		      ntfs_extend_initialized_size(file, ni, ni->i_valid, to) :
		      0;

	inode_unlock(inode);
	if (err)
		goto out;

generic:
	err = generic_file_mmap(file, vma);
	if (err)
		goto out;

	if (rw) {
		atomic_set(&vm_ops->refcnt, 1);
		vm_ops->to = to;
		vm_ops->base = vma->vm_ops;
		memcpy(&vm_ops->vm_ops, vma->vm_ops,
		       sizeof(struct vm_operations_struct));
		vm_ops->vm_ops.fault = &ntfs_filemap_fault;
		vm_ops->vm_ops.open = &ntfs_filemap_open;
		vm_ops->vm_ops.close = &ntfs_filemap_close;
		vma->vm_ops = &vm_ops->vm_ops;
	}

out:
	if (err)
		ntfs_free(vm_ops);

	return err;
}

/*
 * file_operations::fsync
 */
int ntfs_file_fsync(struct file *filp, loff_t start, loff_t end, int datasync)
{
	return generic_file_fsync(filp, start, end, datasync);
}

static int ntfs_extend_ex(struct inode *inode, loff_t pos, size_t count,
			  struct file *file)
{
	ntfs_inode *ni = ntfs_i(inode);
	struct address_space *mapping = inode->i_mapping;
	loff_t end = pos + count;
	int err;
	bool extend_init = file && pos > ni->i_valid;
=======
		cond_resched();
	}
	mark_inode_dirty(inode);
}

/*
 * ntfs_file_mmap - file_operations::mmap
 */
static int ntfs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	struct ntfs_inode *ni = ntfs_i(inode);
	u64 from = ((u64)vma->vm_pgoff << PAGE_SHIFT);
	bool rw = vma->vm_flags & VM_WRITE;
	int err;

	if (is_encrypted(ni)) {
		ntfs_inode_warn(inode, "mmap encrypted not supported");
		return -EOPNOTSUPP;
	}

	if (is_dedup(ni)) {
		ntfs_inode_warn(inode, "mmap deduplicated not supported");
		return -EOPNOTSUPP;
	}

	if (is_compressed(ni) && rw) {
		ntfs_inode_warn(inode, "mmap(write) compressed not supported");
		return -EOPNOTSUPP;
	}

	if (rw) {
		u64 to = min_t(loff_t, i_size_read(inode),
			       from + vma->vm_end - vma->vm_start);

		if (is_sparsed(ni)) {
			/* Allocate clusters for rw map. */
			struct ntfs_sb_info *sbi = inode->i_sb->s_fs_info;
			CLST lcn, len;
			CLST vcn = from >> sbi->cluster_bits;
			CLST end = bytes_to_cluster(sbi, to);
			bool new;

			for (; vcn < end; vcn += len) {
				err = attr_data_get_block(ni, vcn, 1, &lcn,
							  &len, &new);
				if (err)
					goto out;

				if (!new)
					continue;
				ntfs_sparse_cluster(inode, NULL, vcn, 1);
			}
		}

		if (ni->i_valid < to) {
			if (!inode_trylock(inode)) {
				err = -EAGAIN;
				goto out;
			}
			err = ntfs_extend_initialized_size(file, ni,
							   ni->i_valid, to);
			inode_unlock(inode);
			if (err)
				goto out;
		}
	}

	err = generic_file_mmap(file, vma);
out:
	return err;
}

static int ntfs_extend(struct inode *inode, loff_t pos, size_t count,
		       struct file *file)
{
	struct ntfs_inode *ni = ntfs_i(inode);
	struct address_space *mapping = inode->i_mapping;
	loff_t end = pos + count;
	bool extend_init = file && pos > ni->i_valid;
	int err;
>>>>>>> wip

	if (end <= inode->i_size && !extend_init)
		return 0;

<<<<<<< HEAD
	/*mark rw ntfs as dirty. it will be cleared at umount*/
=======
	/* Mark rw ntfs as dirty. It will be cleared at umount. */
>>>>>>> wip
	ntfs_set_state(ni->mi.sbi, NTFS_DIRTY_DIRTY);

	if (end > inode->i_size) {
		err = ntfs_set_size(inode, end);
		if (err)
			goto out;
		inode->i_size = end;
	}

<<<<<<< HEAD
	if (extend_init) {
		err = (is_compressed(ni) ? ntfs_extend_initialized_size_cmpr :
					   ntfs_extend_initialized_size)(
			file, ni, ni->i_valid, pos);
		if (err)
			goto out;
	}

	inode->i_ctime = inode->i_mtime = current_time(inode);
	ni->ni_flags |= NI_FLAG_UPDATE_PARENT;
=======
	if (extend_init && !is_compressed(ni)) {
		err = ntfs_extend_initialized_size(file, ni, ni->i_valid, pos);
		if (err)
			goto out;
	} else {
		err = 0;
	}

	inode->i_ctime = inode->i_mtime = current_time(inode);
>>>>>>> wip
	mark_inode_dirty(inode);

	if (IS_SYNC(inode)) {
		int err2;

		err = filemap_fdatawrite_range(mapping, pos, end - 1);
		err2 = sync_mapping_buffers(mapping);
		if (!err)
			err = err2;
		err2 = write_inode_now(inode, 1);
		if (!err)
			err = err2;
		if (!err)
			err = filemap_fdatawait_range(mapping, pos, end - 1);
	}

out:
	return err;
}

<<<<<<< HEAD
/*
 * Preallocate space for a file. This implements ntfs's fallocate file
 * operation, which gets called from sys_fallocate system call. User
 * space requests len bytes at offset. If FALLOC_FL_KEEP_SIZE is set
 * we just allocate clusters without zeroing them out. Otherwise we
 * allocate and zero out clusters via an expanding truncate.
 */
static long ntfs_fallocate(struct file *file, int mode, loff_t offset,
			   loff_t len)
{
	struct inode *inode = file->f_mapping->host;
	struct super_block *sb = inode->i_sb;
	ntfs_sb_info *sbi = sb->s_fs_info;
	loff_t end;
	int err;

	/* No support for dir */
	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;

	/* Return error if mode is not supported */
	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
		     FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_ZERO_RANGE |
		     FALLOC_FL_INSERT_RANGE))
		return -EOPNOTSUPP;

	inode_lock(inode);

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		if (!(mode & FALLOC_FL_KEEP_SIZE)) {
			err = -EINVAL;
			goto out;
		}
		/*TODO*/
		err = -EOPNOTSUPP;
		goto out;
	}

	if (mode & FALLOC_FL_COLLAPSE_RANGE) {
		if (mode & ~FALLOC_FL_COLLAPSE_RANGE) {
			err = -EINVAL;
			goto out;
		}

		/*TODO*/
		err = -EOPNOTSUPP;
		goto out;
	}

	if (mode & FALLOC_FL_INSERT_RANGE) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (mode & FALLOC_FL_ZERO_RANGE) {
		err = -EOPNOTSUPP;
		goto out;
	}

	end = offset + len;
	if (mode & FALLOC_FL_KEEP_SIZE) {
		/* Start the allocation.We are not zeroing out the clusters */
		err = ntfs_set_size(inode, bytes_to_cluster(sbi, end));
		goto out;
	}

	err = 0;

	if (end <= i_size_read(inode))
		goto out;

	/*
	 * Allocate clusters but does not change 'valid'
	 */
	err = ntfs_extend_ex(inode, offset, len, NULL);

out:
	if (err == -EFBIG)
		err = -ENOSPC;

	inode_unlock(inode);
	return err;
}

void ntfs_truncate_blocks(struct inode *inode, loff_t new_size)
{
	struct super_block *sb = inode->i_sb;
	ntfs_sb_info *sbi = sb->s_fs_info;
	ntfs_inode *ni = ntfs_i(inode);
	int err, dirty = 0;
	u32 vcn;
	u64 new_valid;

	if (!S_ISREG(inode->i_mode))
		return;

	vcn = bytes_to_cluster(sbi, new_size);
	new_valid = ntfs_up_block(sb, min(ni->i_valid, new_size));

	ni_lock(ni);
	down_write(&ni->file.run_lock);

	truncate_setsize(inode, new_size);

	err = attr_set_size(ni, ATTR_DATA, NULL, 0, &ni->file.run, new_size,
			    &new_valid, true, NULL);
=======
static int ntfs_truncate(struct inode *inode, loff_t new_size)
{
	struct super_block *sb = inode->i_sb;
	struct ntfs_inode *ni = ntfs_i(inode);
	int err, dirty = 0;
	u64 new_valid;

	if (!S_ISREG(inode->i_mode))
		return 0;

	if (is_compressed(ni)) {
		if (ni->i_valid > new_size)
			ni->i_valid = new_size;
	} else {
		err = block_truncate_page(inode->i_mapping, new_size,
					  ntfs_get_block);
		if (err)
			return err;
	}

	new_valid = ntfs_up_block(sb, min_t(u64, ni->i_valid, new_size));

	ni_lock(ni);

	truncate_setsize(inode, new_size);

	down_write(&ni->file.run_lock);
	err = attr_set_size(ni, ATTR_DATA, NULL, 0, &ni->file.run, new_size,
			    &new_valid, true, NULL);
	up_write(&ni->file.run_lock);
>>>>>>> wip

	if (new_valid < ni->i_valid)
		ni->i_valid = new_valid;

<<<<<<< HEAD
	up_write(&ni->file.run_lock);
=======
>>>>>>> wip
	ni_unlock(ni);

	ni->std_fa |= FILE_ATTRIBUTE_ARCHIVE;
	inode->i_ctime = inode->i_mtime = current_time(inode);
	if (!IS_DIRSYNC(inode)) {
		dirty = 1;
	} else {
		err = ntfs_sync_inode(inode);
		if (err)
<<<<<<< HEAD
			return;
	}

	inode->i_blocks = vcn;

=======
			return err;
	}

>>>>>>> wip
	if (dirty)
		mark_inode_dirty(inode);

	/*ntfs_flush_inodes(inode->i_sb, inode, NULL);*/
<<<<<<< HEAD
}

/*
 * inode_operations::setattr
 */
int ntfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct super_block *sb = dentry->d_sb;
	ntfs_sb_info *sbi = sb->s_fs_info;
	struct inode *inode = d_inode(dentry);
	ntfs_inode *ni = ntfs_i(inode);
=======

	return 0;
}

/*
 * ntfs_fallocate
 *
 * Preallocate space for a file. This implements ntfs's fallocate file
 * operation, which gets called from sys_fallocate system call. User
 * space requests 'len' bytes at 'vbo'. If FALLOC_FL_KEEP_SIZE is set
 * we just allocate clusters without zeroing them out. Otherwise we
 * allocate and zero out clusters via an expanding truncate.
 */
static long ntfs_fallocate(struct file *file, int mode, loff_t vbo, loff_t len)
{
	struct inode *inode = file->f_mapping->host;
	struct super_block *sb = inode->i_sb;
	struct ntfs_sb_info *sbi = sb->s_fs_info;
	struct ntfs_inode *ni = ntfs_i(inode);
	loff_t end = vbo + len;
	loff_t vbo_down = round_down(vbo, PAGE_SIZE);
	loff_t i_size;
	int err;

	/* No support for dir. */
	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;

	/* Return error if mode is not supported. */
	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
		     FALLOC_FL_COLLAPSE_RANGE)) {
		ntfs_inode_warn(inode, "fallocate(0x%x) is not supported",
				mode);
		return -EOPNOTSUPP;
	}

	ntfs_set_state(sbi, NTFS_DIRTY_DIRTY);

	inode_lock(inode);
	i_size = inode->i_size;

	if (WARN_ON(ni->ni_flags & NI_FLAG_COMPRESSED_MASK)) {
		/* Should never be here, see ntfs_file_open. */
		err = -EOPNOTSUPP;
		goto out;
	}

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		u32 frame_size;
		loff_t mask, vbo_a, end_a, tmp;

		if (!(mode & FALLOC_FL_KEEP_SIZE)) {
			err = -EINVAL;
			goto out;
		}

		err = filemap_write_and_wait_range(inode->i_mapping, vbo,
						   end - 1);
		if (err)
			goto out;

		err = filemap_write_and_wait_range(inode->i_mapping, end,
						   LLONG_MAX);
		if (err)
			goto out;

		inode_dio_wait(inode);

		truncate_pagecache(inode, vbo_down);

		if (!is_sparsed(ni) && !is_compressed(ni)) {
			/* Normal file. */
			err = ntfs_zero_range(inode, vbo, end);
			goto out;
		}

		ni_lock(ni);
		err = attr_punch_hole(ni, vbo, len, &frame_size);
		ni_unlock(ni);
		if (err != E_NTFS_NOTALIGNED)
			goto out;

		/* Process not aligned punch. */
		mask = frame_size - 1;
		vbo_a = (vbo + mask) & ~mask;
		end_a = end & ~mask;

		tmp = min(vbo_a, end);
		if (tmp > vbo) {
			err = ntfs_zero_range(inode, vbo, tmp);
			if (err)
				goto out;
		}

		if (vbo < end_a && end_a < end) {
			err = ntfs_zero_range(inode, end_a, end);
			if (err)
				goto out;
		}

		/* Aligned punch_hole */
		if (end_a > vbo_a) {
			ni_lock(ni);
			err = attr_punch_hole(ni, vbo_a, end_a - vbo_a, NULL);
			ni_unlock(ni);
		}
	} else if (mode & FALLOC_FL_COLLAPSE_RANGE) {
		if (mode & ~FALLOC_FL_COLLAPSE_RANGE) {
			err = -EINVAL;
			goto out;
		}

		/*
		 * Write tail of the last page before removed range since
		 * it will get removed from the page cache below.
		 */
		err = filemap_write_and_wait_range(inode->i_mapping, vbo_down,
						   vbo);
		if (err)
			goto out;

		/*
		 * Write data that will be shifted to preserve them
		 * when discarding page cache below.
		 */
		err = filemap_write_and_wait_range(inode->i_mapping, end,
						   LLONG_MAX);
		if (err)
			goto out;

		/* Wait for existing dio to complete. */
		inode_dio_wait(inode);

		truncate_pagecache(inode, vbo_down);

		ni_lock(ni);
		err = attr_collapse_range(ni, vbo, len);
		ni_unlock(ni);
	} else {
		/*
		 * Normal file: Allocate clusters, do not change 'valid' size.
		 */
		err = ntfs_set_size(inode, max(end, i_size));
		if (err)
			goto out;

		if (is_sparsed(ni) || is_compressed(ni)) {
			CLST vcn_v = ni->i_valid >> sbi->cluster_bits;
			CLST vcn = vbo >> sbi->cluster_bits;
			CLST cend = bytes_to_cluster(sbi, end);
			CLST lcn, clen;
			bool new;

			/*
			 * Allocate but do not zero new clusters. (see below comments)
			 * This breaks security: One can read unused on-disk areas.
			 * Zeroing these clusters may be too long.
			 * Maybe we should check here for root rights?
			 */
			for (; vcn < cend; vcn += clen) {
				err = attr_data_get_block(ni, vcn, cend - vcn,
							  &lcn, &clen, &new);
				if (err)
					goto out;
				if (!new || vcn >= vcn_v)
					continue;

				/*
				 * Unwritten area.
				 * NTFS is not able to store several unwritten areas.
				 * Activate 'ntfs_sparse_cluster' to zero new allocated clusters.
				 *
				 * Dangerous in case:
				 * 1G of sparsed clusters + 1 cluster of data =>
				 * valid_size == 1G + 1 cluster
				 * fallocate(1G) will zero 1G and this can be very long
				 * xfstest 016/086 will fail without 'ntfs_sparse_cluster'.
				 */
				ntfs_sparse_cluster(inode, NULL, vcn,
						    min(vcn_v - vcn, clen));
			}
		}

		if (mode & FALLOC_FL_KEEP_SIZE) {
			ni_lock(ni);
			/* True - Keep preallocated. */
			err = attr_set_size(ni, ATTR_DATA, NULL, 0,
					    &ni->file.run, i_size, &ni->i_valid,
					    true, NULL);
			ni_unlock(ni);
		}
	}

out:
	if (err == -EFBIG)
		err = -ENOSPC;

	if (!err) {
		inode->i_ctime = inode->i_mtime = current_time(inode);
		mark_inode_dirty(inode);
	}

	inode_unlock(inode);
	return err;
}

/*
 * ntfs3_setattr - inode_operations::setattr
 */
int ntfs3_setattr(struct dentry *dentry,
		  struct iattr *attr)
{
	struct super_block *sb = dentry->d_sb;
	struct ntfs_sb_info *sbi = sb->s_fs_info;
	struct inode *inode = d_inode(dentry);
	struct ntfs_inode *ni = ntfs_i(inode);
>>>>>>> wip
	u32 ia_valid = attr->ia_valid;
	umode_t mode = inode->i_mode;
	int err;

	if (sbi->options.no_acs_rules) {
<<<<<<< HEAD
		/* "no access rules" - force any changes of time etc. */
		attr->ia_valid |= ATTR_FORCE;
		/* and disable for editing some attributes */
=======
		/* "No access rules" - Force any changes of time etc. */
		attr->ia_valid |= ATTR_FORCE;
		/* and disable for editing some attributes. */
>>>>>>> wip
		attr->ia_valid &= ~(ATTR_UID | ATTR_GID | ATTR_MODE);
		ia_valid = attr->ia_valid;
	}

	err = setattr_prepare(dentry, attr);
<<<<<<< HEAD
	if (err) {
		if (sbi->options.quiet)
			err = 0;
		goto out;
	}
=======
	if (err)
		goto out;
>>>>>>> wip

	if (ia_valid & ATTR_SIZE) {
		loff_t oldsize = inode->i_size;

<<<<<<< HEAD
		inode_dio_wait(inode);

		if (attr->ia_size < oldsize) {
			err = block_truncate_page(inode->i_mapping,
						  attr->ia_size,
						  ntfs_get_block);
			if (err)
				goto out;
			ntfs_truncate_blocks(inode, attr->ia_size);
		} else if (attr->ia_size > oldsize) {
			err = ntfs_extend_ex(inode, attr->ia_size, 0, NULL);
			if (err)
				goto out;
		}
=======
		if (WARN_ON(ni->ni_flags & NI_FLAG_COMPRESSED_MASK)) {
			/* Should never be here, see ntfs_file_open(). */
			err = -EOPNOTSUPP;
			goto out;
		}
		inode_dio_wait(inode);

		if (attr->ia_size < oldsize)
			err = ntfs_truncate(inode, attr->ia_size);
		else if (attr->ia_size > oldsize)
			err = ntfs_extend(inode, attr->ia_size, 0, NULL);

		if (err)
			goto out;
>>>>>>> wip

		ni->ni_flags |= NI_FLAG_UPDATE_PARENT;
	}

	setattr_copy(inode, attr);

	if (mode != inode->i_mode) {
		err = ntfs_acl_chmod(inode);
		if (err)
			goto out;

<<<<<<< HEAD
		/* linux 'w' -> windows 'ro' */
=======
		/* Linux 'w' -> Windows 'ro'. */
>>>>>>> wip
		if (0222 & inode->i_mode)
			ni->std_fa &= ~FILE_ATTRIBUTE_READONLY;
		else
			ni->std_fa |= FILE_ATTRIBUTE_READONLY;
	}

<<<<<<< HEAD
	mark_inode_dirty(inode);
out:

=======
	if (ia_valid & (ATTR_UID | ATTR_GID | ATTR_MODE))
		ntfs_save_wsl_perm(inode);
	mark_inode_dirty(inode);
out:
>>>>>>> wip
	return err;
}

static ssize_t ntfs_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
<<<<<<< HEAD
	ssize_t err;
	size_t count = iov_iter_count(iter);
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ntfs_inode *ni = ntfs_i(inode);

	if (is_encrypted(ni))
		return -EOPNOTSUPP;

	if (is_dedup(ni))
		return -EOPNOTSUPP;

	err = count ? generic_file_read_iter(iocb, iter) : 0;

	return err;
}

/*
 * on error we return an unlocked page and the error value
 * on success we return a locked page and 0
 */
static int prepare_uptodate_page(struct inode *inode, struct page *page,
				 u64 pos, bool force_uptodate)
{
	int err = 0;

	if (((pos & (PAGE_SIZE - 1)) || force_uptodate) &&
	    !PageUptodate(page)) {
		err = ntfs_readpage(NULL, page);
		if (err)
			return err;
		lock_page(page);
		if (!PageUptodate(page)) {
			unlock_page(page);
			return -EIO;
		}
		if (page->mapping != inode->i_mapping) {
			unlock_page(page);
			return -EAGAIN;
		}
	}
	return 0;
}

/*helper for ntfs_file_write_iter (compressed files)*/
static noinline ssize_t ntfs_compress_write(struct kiocb *iocb,
					    struct iov_iter *from)
=======
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct ntfs_inode *ni = ntfs_i(inode);

	if (is_encrypted(ni)) {
		ntfs_inode_warn(inode, "encrypted i/o not supported");
		return -EOPNOTSUPP;
	}

	if (is_compressed(ni) && (iocb->ki_flags & IOCB_DIRECT)) {
		ntfs_inode_warn(inode, "direct i/o + compressed not supported");
		return -EOPNOTSUPP;
	}

#ifndef CONFIG_NTFS3_LZX_XPRESS
	if (ni->ni_flags & NI_FLAG_COMPRESSED_MASK) {
		ntfs_inode_warn(
			inode,
			"activate CONFIG_NTFS3_LZX_XPRESS to read external compressed files");
		return -EOPNOTSUPP;
	}
#endif

	if (is_dedup(ni)) {
		ntfs_inode_warn(inode, "read deduplicated not supported");
		return -EOPNOTSUPP;
	}

	return generic_file_read_iter(iocb, iter);
}

/*
 * ntfs_get_frame_pages
 *
 * Return: Array of locked pages.
 */
static int ntfs_get_frame_pages(struct address_space *mapping, pgoff_t index,
				struct page **pages, u32 pages_per_frame,
				bool *frame_uptodate)
{
	gfp_t gfp_mask = mapping_gfp_mask(mapping);
	u32 npages;

	*frame_uptodate = true;

	for (npages = 0; npages < pages_per_frame; npages++, index++) {
		struct page *page;

		page = find_or_create_page(mapping, index, gfp_mask);
		if (!page) {
			while (npages--) {
				page = pages[npages];
				unlock_page(page);
				put_page(page);
			}

			return -ENOMEM;
		}

		if (!PageUptodate(page))
			*frame_uptodate = false;

		pages[npages] = page;
	}

	return 0;
}

/*
 * ntfs_compress_write - Helper for ntfs_file_write_iter() (compressed files).
 */
static ssize_t ntfs_compress_write(struct kiocb *iocb, struct iov_iter *from)
>>>>>>> wip
{
	int err;
	struct file *file = iocb->ki_filp;
	size_t count = iov_iter_count(from);
	loff_t pos = iocb->ki_pos;
<<<<<<< HEAD
	loff_t end = pos + count;
	struct inode *inode = file_inode(file);
	struct address_space *mapping = inode->i_mapping;
	ntfs_inode *ni = ntfs_i(inode);
	// struct ntfs_sb_info *sbi = ni->mi.sbi;
	struct page *page, **pages = NULL;
	size_t ip, max_pages, written = 0;
	bool force_uptodate = false;
	pgoff_t from_idx, end_idx;
	u32 off;
	gfp_t mask = mapping_gfp_constraint(mapping, ~__GFP_FS) | __GFP_WRITE;

	from_idx = pos >> PAGE_SHIFT;
	end_idx = (end + PAGE_SIZE - 1) >> PAGE_SHIFT;
	max_pages = end_idx - from_idx;
	if (max_pages > 16)
		max_pages = 16;
	WARN_ON(end_idx <= from_idx);

	pages = ntfs_alloc(max_pages * sizeof(struct page *), 1);
=======
	struct inode *inode = file_inode(file);
	loff_t i_size = inode->i_size;
	struct address_space *mapping = inode->i_mapping;
	struct ntfs_inode *ni = ntfs_i(inode);
	u64 valid = ni->i_valid;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	struct page *page, **pages = NULL;
	size_t written = 0;
	u8 frame_bits = NTFS_LZNT_CUNIT + sbi->cluster_bits;
	u32 frame_size = 1u << frame_bits;
	u32 pages_per_frame = frame_size >> PAGE_SHIFT;
	u32 ip, off;
	CLST frame;
	u64 frame_vbo;
	pgoff_t index;
	bool frame_uptodate;

	if (frame_size < PAGE_SIZE) {
		/*
		 * frame_size == 8K if cluster 512
		 * frame_size == 64K if cluster 4096
		 */
		ntfs_inode_warn(inode, "page size is bigger than frame size");
		return -EOPNOTSUPP;
	}

	pages = kmalloc_array(pages_per_frame, sizeof(struct page *), GFP_NOFS);
>>>>>>> wip
	if (!pages)
		return -ENOMEM;

	current->backing_dev_info = inode_to_bdi(inode);
	err = file_remove_privs(file);
	if (err)
		goto out;

	err = file_update_time(file);
	if (err)
		goto out;

<<<<<<< HEAD
	while (count) {
		pgoff_t index = pos >> PAGE_SHIFT;
		size_t offset = offset_in_page(pos);
		size_t bytes = max_pages * PAGE_SIZE - offset;
		size_t wpages, copied;

		if (bytes > count)
			bytes = count;

		wpages = (offset + bytes + PAGE_SIZE - 1) >> PAGE_SHIFT;

		WARN_ON(wpages > max_pages);
=======
	/* Zero range [valid : pos). */
	while (valid < pos) {
		CLST lcn, clen;

		frame = valid >> frame_bits;
		frame_vbo = valid & ~(frame_size - 1);
		off = valid & (frame_size - 1);

		err = attr_data_get_block(ni, frame << NTFS_LZNT_CUNIT, 0, &lcn,
					  &clen, NULL);
		if (err)
			goto out;

		if (lcn == SPARSE_LCN) {
			ni->i_valid = valid =
				frame_vbo + ((u64)clen << sbi->cluster_bits);
			continue;
		}

		/* Load full frame. */
		err = ntfs_get_frame_pages(mapping, frame_vbo >> PAGE_SHIFT,
					   pages, pages_per_frame,
					   &frame_uptodate);
		if (err)
			goto out;

		if (!frame_uptodate && off) {
			err = ni_read_frame(ni, frame_vbo, pages,
					    pages_per_frame);
			if (err) {
				for (ip = 0; ip < pages_per_frame; ip++) {
					page = pages[ip];
					unlock_page(page);
					put_page(page);
				}
				goto out;
			}
		}

		ip = off >> PAGE_SHIFT;
		off = offset_in_page(valid);
		for (; ip < pages_per_frame; ip++, off = 0) {
			page = pages[ip];
			zero_user_segment(page, off, PAGE_SIZE);
			flush_dcache_page(page);
			SetPageUptodate(page);
		}

		ni_lock(ni);
		err = ni_write_frame(ni, pages, pages_per_frame);
		ni_unlock(ni);

		for (ip = 0; ip < pages_per_frame; ip++) {
			page = pages[ip];
			SetPageUptodate(page);
			unlock_page(page);
			put_page(page);
		}

		if (err)
			goto out;

		ni->i_valid = valid = frame_vbo + frame_size;
	}

	/* Copy user data [pos : pos + count). */
	while (count) {
		size_t copied, bytes;

		off = pos & (frame_size - 1);
		bytes = frame_size - off;
		if (bytes > count)
			bytes = count;

		frame = pos >> frame_bits;
		frame_vbo = pos & ~(frame_size - 1);
		index = frame_vbo >> PAGE_SHIFT;
>>>>>>> wip

		if (unlikely(iov_iter_fault_in_readable(from, bytes))) {
			err = -EFAULT;
			goto out;
		}

<<<<<<< HEAD
		for (ip = 0; ip < wpages; ip++) {
again:
			page = find_or_create_page(mapping, index + ip, mask);
			if (!page) {
				err = -ENOMEM;
fail:
				while (ip--) {
					page = pages[ip];
					unlock_page(page);
					put_page(page);
				}

				goto out;
			}

			pages[ip] = page;

			if (!ip)
				err = prepare_uptodate_page(inode, page, pos,
							    force_uptodate);

			if (!err && ip == wpages - 1)
				err = prepare_uptodate_page(inode, page,
							    pos + bytes, false);

			if (err) {
				put_page(page);
				if (err == -EAGAIN) {
					err = 0;
					goto again;
				}
				goto fail;
			}
			wait_on_page_writeback(page);
=======
		/* Load full frame. */
		err = ntfs_get_frame_pages(mapping, index, pages,
					   pages_per_frame, &frame_uptodate);
		if (err)
			goto out;

		if (!frame_uptodate) {
			loff_t to = pos + bytes;

			if (off || (to < i_size && (to & (frame_size - 1)))) {
				err = ni_read_frame(ni, frame_vbo, pages,
						    pages_per_frame);
				if (err) {
					for (ip = 0; ip < pages_per_frame;
					     ip++) {
						page = pages[ip];
						unlock_page(page);
						put_page(page);
					}
					goto out;
				}
			}
>>>>>>> wip
		}

		WARN_ON(!bytes);
		copied = 0;
<<<<<<< HEAD
		ip = 0;
		off = offset_in_page(pos);

		for (;;) {
			size_t tail = PAGE_SIZE - off;
			size_t count = min(tail, bytes);
			size_t cp;

			page = pages[ip];

			cp = iov_iter_copy_from_user_atomic(page, from, off,
							    count);

			flush_dcache_page(page);

			if (!PageUptodate(page) && cp < count)
				cp = 0;

			iov_iter_advance(from, cp);
=======
		ip = off >> PAGE_SHIFT;
		off = offset_in_page(pos);

		/* Copy user data to pages. */
		for (;;) {
			size_t cp, tail = PAGE_SIZE - off;

			page = pages[ip];
			cp = iov_iter_copy_from_user_atomic(page, from, off,
							min(tail, bytes));
			flush_dcache_page(page);

>>>>>>> wip
			copied += cp;
			bytes -= cp;
			if (!bytes || !cp)
				break;

<<<<<<< HEAD
			if (cp < tail)
				off += cp;
			else {
=======
			if (cp < tail) {
				off += cp;
			} else {
>>>>>>> wip
				ip++;
				off = 0;
			}
		}

<<<<<<< HEAD
		if (!copied)
			force_uptodate = true;
		else {
			size_t dpages;

			force_uptodate = false;
			dpages =
				(offset + copied + PAGE_SIZE - 1) >> PAGE_SHIFT;

			for (ip = 0; ip < dpages; ip++) {
				page = pages[ip];
				SetPageUptodate(page);
				ClearPageChecked(page);
				set_page_dirty(page);
			}
		}

		for (ip = 0; ip < wpages; ip++) {
			page = pages[ip];
			ClearPageChecked(page);
=======
		ni_lock(ni);
		err = ni_write_frame(ni, pages, pages_per_frame);
		ni_unlock(ni);

		for (ip = 0; ip < pages_per_frame; ip++) {
			page = pages[ip];
			ClearPageDirty(page);
			SetPageUptodate(page);
>>>>>>> wip
			unlock_page(page);
			put_page(page);
		}

<<<<<<< HEAD
		cond_resched();

		balance_dirty_pages_ratelimited(mapping);
=======
		if (err)
			goto out;

		/*
		 * We can loop for a long time in here. Be nice and allow
		 * us to schedule out to avoid softlocking if preempt
		 * is disabled.
		 */
		cond_resched();
>>>>>>> wip

		pos += copied;
		written += copied;

		count = iov_iter_count(from);
	}

out:
<<<<<<< HEAD
	ntfs_free(pages);
=======
	kfree(pages);
>>>>>>> wip

	current->backing_dev_info = NULL;

	if (err < 0)
		return err;

	iocb->ki_pos += written;
	if (iocb->ki_pos > ni->i_valid)
		ni->i_valid = iocb->ki_pos;

	return written;
}

/*
<<<<<<< HEAD
 * file_operations::write_iter
=======
 * ntfs_file_write_iter - file_operations::write_iter
>>>>>>> wip
 */
static ssize_t ntfs_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t ret;
<<<<<<< HEAD
	ntfs_inode *ni = ntfs_i(inode);

	if (is_encrypted(ni)) {
		ntfs_inode_warning(inode, "encrypted i/o not supported");
=======
	struct ntfs_inode *ni = ntfs_i(inode);

	if (is_encrypted(ni)) {
		ntfs_inode_warn(inode, "encrypted i/o not supported");
>>>>>>> wip
		return -EOPNOTSUPP;
	}

	if (is_compressed(ni) && (iocb->ki_flags & IOCB_DIRECT)) {
<<<<<<< HEAD
		ntfs_inode_warning(inode,
				   "direct i/o + compressed not supported");
		return -EOPNOTSUPP;
	}

	if (ni->ni_flags & NI_FLAG_COMPRESSED_MASK) {
		ntfs_inode_warning(
			inode,
			"write into external compressed file not supported (temporary)");
=======
		ntfs_inode_warn(inode, "direct i/o + compressed not supported");
>>>>>>> wip
		return -EOPNOTSUPP;
	}

	if (is_dedup(ni)) {
<<<<<<< HEAD
		ntfs_inode_warning(inode,
				   "write into deduplicated not supported");
=======
		ntfs_inode_warn(inode, "write into deduplicated not supported");
>>>>>>> wip
		return -EOPNOTSUPP;
	}

	if (!inode_trylock(inode)) {
		if (iocb->ki_flags & IOCB_NOWAIT)
			return -EAGAIN;
		inode_lock(inode);
	}

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

<<<<<<< HEAD
	ret = ntfs_extend_ex(inode, iocb->ki_pos, ret, file);
	if (ret)
		goto out;

	ret = is_compressed(ni) ? ntfs_compress_write(iocb, from) :
				  __generic_file_write_iter(iocb, from);
=======
	if (WARN_ON(ni->ni_flags & NI_FLAG_COMPRESSED_MASK)) {
		/* Should never be here, see ntfs_file_open(). */
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = ntfs_extend(inode, iocb->ki_pos, ret, file);
	if (ret)
		goto out;

	ret = is_compressed(ni) ? ntfs_compress_write(iocb, from)
				: __generic_file_write_iter(iocb, from);
>>>>>>> wip

out:
	inode_unlock(inode);

	if (ret > 0)
		ret = generic_write_sync(iocb, ret);

	return ret;
}

/*
<<<<<<< HEAD
 * file_operations::open
 */
int ntfs_file_open(struct inode *inode, struct file *file)
{
	ntfs_inode *ni = ntfs_i(inode);

	if (unlikely((is_compressed(ni) || is_encrypted(ni)) &&
		     (file->f_flags & O_DIRECT))) {
		return -ENOTBLK;
=======
 * ntfs_file_open - file_operations::open
 */
int ntfs_file_open(struct inode *inode, struct file *file)
{
	struct ntfs_inode *ni = ntfs_i(inode);

	if (unlikely((is_compressed(ni) || is_encrypted(ni)) &&
		     (file->f_flags & O_DIRECT))) {
		return -EOPNOTSUPP;
	}

	/* Decompress "external compressed" file if opened for rw. */
	if ((ni->ni_flags & NI_FLAG_COMPRESSED_MASK) &&
	    (file->f_flags & (O_WRONLY | O_RDWR | O_TRUNC))) {
#ifdef CONFIG_NTFS3_LZX_XPRESS
		int err = ni_decompress_file(ni);

		if (err)
			return err;
#else
		ntfs_inode_warn(
			inode,
			"activate CONFIG_NTFS3_LZX_XPRESS to write external compressed files");
		return -EOPNOTSUPP;
#endif
>>>>>>> wip
	}

	return generic_file_open(inode, file);
}

<<<<<<< HEAD
#ifdef NTFS3_PREALLOCATE
/*
 * file_operations::release
 */
static int ntfs_file_release(struct inode *inode, struct file *file)
{
	ntfs_inode *ni = ntfs_i(inode);
	int err;

	/* if we are the last writer on the inode, drop the block reservation */
	if (!(file->f_mode & FMODE_WRITE) ||
	    atomic_read(&inode->i_writecount) != 1)
		return 0;

	ni_lock(ni);

	err = attr_set_size(ni, ATTR_DATA, NULL, 0, &ni->file.run,
			    inode->i_size, &ni->i_valid, false, NULL);

	ni_unlock(ni);

	/*congestion_wait(BLK_RW_ASYNC, HZ / 10);*/

	return err;
}
#endif

const struct inode_operations ntfs_file_inode_operations = {
	.getattr = ntfs_getattr,
	.setattr = ntfs_setattr,
	.listxattr = ntfs_listxattr,
	.permission = ntfs_permission,
	.get_acl = ntfs_get_acl,
	.set_acl = ntfs_set_acl,
};

const struct file_operations ntfs_file_operations = {
	.llseek = generic_file_llseek,
	.read_iter = ntfs_file_read_iter,
	.write_iter = ntfs_file_write_iter,
	.unlocked_ioctl = ntfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ntfs_compat_ioctl,
#endif
	.splice_read = generic_file_splice_read,
	.mmap = ntfs_file_mmap,
	.open = ntfs_file_open,
	.fsync = ntfs_file_fsync,
	.splice_write = iter_file_splice_write,
	.fallocate = ntfs_fallocate,
#ifdef NTFS3_PREALLOCATE
	.release = ntfs_file_release,
#endif
};
=======
/*
 * ntfs_file_release - file_operations::release
 */
static int ntfs_file_release(struct inode *inode, struct file *file)
{
	struct ntfs_inode *ni = ntfs_i(inode);
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	int err = 0;

	/* If we are last writer on the inode, drop the block reservation. */
	if (sbi->options.prealloc && ((file->f_mode & FMODE_WRITE) &&
				      atomic_read(&inode->i_writecount) == 1)) {
		ni_lock(ni);
		down_write(&ni->file.run_lock);

		err = attr_set_size(ni, ATTR_DATA, NULL, 0, &ni->file.run,
				    inode->i_size, &ni->i_valid, false, NULL);

		up_write(&ni->file.run_lock);
		ni_unlock(ni);
	}
	return err;
}

/*
 * ntfs_fiemap - file_operations::fiemap
 */
int ntfs_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		__u64 start, __u64 len)
{
	int err;
	struct ntfs_inode *ni = ntfs_i(inode);

	err = fiemap_check_flags(fieinfo, ~FIEMAP_FLAG_XATTR);
	if (err)
		return err;

	ni_lock(ni);

	err = ni_fiemap(ni, fieinfo, start, len);

	ni_unlock(ni);

	return err;
}

// clang-format off
const struct inode_operations ntfs_file_inode_operations = {
	.getattr	= ntfs_getattr,
	.setattr	= ntfs3_setattr,
	.listxattr	= ntfs_listxattr,
	.permission	= ntfs_permission,
	.get_acl	= ntfs_get_acl,
	.set_acl	= ntfs_set_acl,
	.fiemap		= ntfs_fiemap,
};

const struct file_operations ntfs_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= ntfs_file_read_iter,
	.write_iter	= ntfs_file_write_iter,
	.unlocked_ioctl = ntfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ntfs_compat_ioctl,
#endif
	.splice_read	= generic_file_splice_read,
	.mmap		= ntfs_file_mmap,
	.open		= ntfs_file_open,
	.fsync		= generic_file_fsync,
	.splice_write	= iter_file_splice_write,
	.fallocate	= ntfs_fallocate,
	.release	= ntfs_file_release,
};
// clang-format on
>>>>>>> wip
