// SPDX-License-Identifier: GPL-2.0
/*
<<<<<<< HEAD
 *  linux/fs/ntfs3/namei.c
 *
 * Copyright (C) 2019-2020 Paragon Software GmbH, All rights reserved.
=======
 *
 * Copyright (C) 2019-2021 Paragon Software GmbH, All rights reserved.
>>>>>>> wip
 *
 */

#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/iversion.h>
#include <linux/namei.h>
#include <linux/nls.h>

#include "debug.h"
#include "ntfs.h"
#include "ntfs_fs.h"

/*
<<<<<<< HEAD
 * fill_name_de
 *
 * formats NTFS_DE in 'buf'
 */
int fill_name_de(ntfs_sb_info *sbi, void *buf, const struct qstr *name)
{
	int err;
	NTFS_DE *e = buf;
	u16 data_size;
	ATTR_FILE_NAME *fname = (ATTR_FILE_NAME *)(e + 1);

#ifndef NTFS3_64BIT_CLUSTER
	e->ref.high = fname->home.high = 0;
#endif
	/* Convert input string to unicode */
	err = x8_to_uni(sbi, name->name, name->len,
			(struct cpu_str *)&fname->name_len, NTFS_NAME_LEN,
			UTF16_LITTLE_ENDIAN);
	if (err < 0)
		return err;
=======
 * fill_name_de - Format NTFS_DE in @buf.
 */
int fill_name_de(struct ntfs_sb_info *sbi, void *buf, const struct qstr *name,
		 const struct cpu_str *uni)
{
	int err;
	struct NTFS_DE *e = buf;
	u16 data_size;
	struct ATTR_FILE_NAME *fname = (struct ATTR_FILE_NAME *)(e + 1);

#ifndef CONFIG_NTFS3_64BIT_CLUSTER
	e->ref.high = fname->home.high = 0;
#endif
	if (uni) {
#ifdef __BIG_ENDIAN
		int ulen = uni->len;
		__le16 *uname = fname->name;
		const u16 *name_cpu = uni->name;

		while (ulen--)
			*uname++ = cpu_to_le16(*name_cpu++);
#else
		memcpy(fname->name, uni->name, uni->len * sizeof(u16));
#endif
		fname->name_len = uni->len;

	} else {
		/* Convert input string to unicode. */
		err = ntfs_nls_to_utf16(sbi, name->name, name->len,
					(struct cpu_str *)&fname->name_len,
					NTFS_NAME_LEN, UTF16_LITTLE_ENDIAN);
		if (err < 0)
			return err;
	}
>>>>>>> wip

	fname->type = FILE_NAME_POSIX;
	data_size = fname_full_size(fname);

<<<<<<< HEAD
	e->size = cpu_to_le16(QuadAlign(data_size) + sizeof(NTFS_DE));
	e->key_size = cpu_to_le16(data_size);
	e->flags = 0;
	e->Reserved = 0;
=======
	e->size = cpu_to_le16(ALIGN(data_size, 8) + sizeof(struct NTFS_DE));
	e->key_size = cpu_to_le16(data_size);
	e->flags = 0;
	e->res = 0;
>>>>>>> wip

	return 0;
}

<<<<<<< HEAD
static struct dentry *__ntfs_lookup(struct inode *dir, struct dentry *dentry,
				    struct ntfs_fnd *fnd)
{
	struct dentry *d;
	struct inode *inode;

	inode = dir_search(dir, &dentry->d_name, fnd);

	if (!inode) {
		d_add(dentry, NULL);
		d = NULL;
		goto out;
	}

	if (IS_ERR(inode)) {
		d = ERR_CAST(inode);
		goto out;
	}

	d = d_splice_alias(inode, dentry);
	if (IS_ERR(d)) {
		iput(inode);
		goto out;
	}

out:
	return d;
}

/*
 * ntfs_lookup
 *
 * inode_operations::lookup
=======
/*
 * ntfs_lookup - inode_operations::lookup
>>>>>>> wip
 */
static struct dentry *ntfs_lookup(struct inode *dir, struct dentry *dentry,
				  u32 flags)
{
<<<<<<< HEAD
	struct dentry *de;
	ntfs_inode *ni = ntfs_i(dir);

	ni_lock(ni);

	de = __ntfs_lookup(dir, dentry, NULL);

	ni_unlock(ni);
	return de;
}

/*
 * ntfs_create
 *
 * inode_operations::create
 */
static int ntfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		       bool excl)
{
	int err;
	ntfs_inode *ni = ntfs_i(dir);
	struct inode *inode;

	ni_lock(ni);

	err = ntfs_create_inode(dir, dentry, NULL, S_IFREG | mode, 0, NULL, 0,
				excl, NULL, &inode);

	ni_unlock(ni);

	return err;
}

/*
 * ntfs_link
 *
 * inode_operations::link
=======
	struct ntfs_inode *ni = ntfs_i(dir);
	struct cpu_str *uni = __getname();
	struct inode *inode;
	int err;

	if (!uni)
		inode = ERR_PTR(-ENOMEM);
	else {
		err = ntfs_nls_to_utf16(ni->mi.sbi, dentry->d_name.name,
					dentry->d_name.len, uni, NTFS_NAME_LEN,
					UTF16_HOST_ENDIAN);
		if (err < 0)
			inode = ERR_PTR(err);
		else {
			ni_lock(ni);
			inode = dir_search_u(dir, uni, NULL);
			ni_unlock(ni);
		}
		__putname(uni);
	}

	return d_splice_alias(inode, dentry);
}

/*
 * ntfs_create - inode_operations::create
 */
static int ntfs_create(struct inode *dir,
		       struct dentry *dentry, umode_t mode, bool excl)
{
	struct ntfs_inode *ni = ntfs_i(dir);
	struct inode *inode;

	ni_lock_dir(ni);

	inode = ntfs_create_inode(dir, dentry, NULL, S_IFREG | mode,
				  0, NULL, 0, NULL);

	ni_unlock(ni);

	return IS_ERR(inode) ? PTR_ERR(inode) : 0;
}

/*
 * ntfs_mknod
 *
 * inode_operations::mknod
 */
static int ntfs_mknod(struct inode *dir,
		      struct dentry *dentry, umode_t mode, dev_t rdev)
{
	struct ntfs_inode *ni = ntfs_i(dir);
	struct inode *inode;

	ni_lock_dir(ni);

	inode = ntfs_create_inode(dir, dentry, NULL, mode, rdev,
				  NULL, 0, NULL);

	ni_unlock(ni);

	return IS_ERR(inode) ? PTR_ERR(inode) : 0;
}

/*
 * ntfs_link - inode_operations::link
>>>>>>> wip
 */
static int ntfs_link(struct dentry *ode, struct inode *dir, struct dentry *de)
{
	int err;
	struct inode *inode = d_inode(ode);
<<<<<<< HEAD
	ntfs_inode *ni = ntfs_i(inode);
=======
	struct ntfs_inode *ni = ntfs_i(inode);
>>>>>>> wip

	if (S_ISDIR(inode->i_mode))
		return -EPERM;

	if (inode->i_nlink >= NTFS_LINK_MAX)
		return -EMLINK;

<<<<<<< HEAD
	ni_lock(ni);

	dir->i_ctime = dir->i_mtime = inode->i_ctime = current_time(inode);
=======
	ni_lock_dir(ntfs_i(dir));
	if (inode != dir)
		ni_lock(ni);

>>>>>>> wip
	inc_nlink(inode);
	ihold(inode);

	err = ntfs_link_inode(inode, de);
<<<<<<< HEAD
	if (!err) {
		mark_inode_dirty(inode);
=======

	if (!err) {
		dir->i_ctime = dir->i_mtime = inode->i_ctime =
			current_time(dir);
		mark_inode_dirty(inode);
		mark_inode_dirty(dir);
>>>>>>> wip
		d_instantiate(de, inode);
	} else {
		drop_nlink(inode);
		iput(inode);
	}

<<<<<<< HEAD
	ni_unlock(ni);
=======
	if (inode != dir)
		ni_unlock(ni);
	ni_unlock(ntfs_i(dir));
>>>>>>> wip

	return err;
}

/*
<<<<<<< HEAD
 * ntfs_unlink
 *
 * inode_operations::unlink
 */
static int ntfs_unlink(struct inode *dir, struct dentry *dentry)
{
	ntfs_inode *ni = ntfs_i(dir);
	int err;

	ni_lock(ni);
=======
 * ntfs_unlink - inode_operations::unlink
 */
static int ntfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct ntfs_inode *ni = ntfs_i(dir);
	int err;

	ni_lock_dir(ni);
>>>>>>> wip

	err = ntfs_unlink_inode(dir, dentry);

	ni_unlock(ni);

	return err;
}

/*
<<<<<<< HEAD
 * ntfs_symlink
 *
 * inode_operations::symlink
 */
static int ntfs_symlink(struct inode *dir, struct dentry *dentry,
			const char *symname)
{
	int err;
	u32 size = strlen(symname);
	struct inode *inode;
	ntfs_inode *ni = ntfs_i(dir);

	ni_lock(ni);

	err = ntfs_create_inode(dir, dentry, NULL, S_IFLNK | 0777, 0, symname,
				size, 0, NULL, &inode);

	ni_unlock(ni);

	return err;
}

/*
 * ntfs_mkdir
 *
 * inode_operations::mkdir
 */
static int ntfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct inode *inode;
	ntfs_inode *ni = ntfs_i(dir);

	ni_lock(ni);

	err = ntfs_create_inode(dir, dentry, NULL, S_IFDIR | mode, 0, NULL, -1,
				0, NULL, &inode);

	ni_unlock(ni);

	return err;
}

/*
 * ntfs_rmdir
 *
 * inode_operations::rm_dir
 */
static int ntfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	ntfs_inode *ni = ntfs_i(dir);
	int err;

	ni_lock(ni);
=======
 * ntfs_symlink - inode_operations::symlink
 */
static int ntfs_symlink(struct inode *dir,
			struct dentry *dentry, const char *symname)
{
	u32 size = strlen(symname);
	struct inode *inode;
	struct ntfs_inode *ni = ntfs_i(dir);

	ni_lock_dir(ni);

	inode = ntfs_create_inode(dir, dentry, NULL, S_IFLNK | 0777,
				  0, symname, size, NULL);

	ni_unlock(ni);

	return IS_ERR(inode) ? PTR_ERR(inode) : 0;
}

/*
 * ntfs_mkdir- inode_operations::mkdir
 */
static int ntfs_mkdir(struct inode *dir,
		      struct dentry *dentry, umode_t mode)
{
	struct inode *inode;
	struct ntfs_inode *ni = ntfs_i(dir);

	ni_lock_dir(ni);

	inode = ntfs_create_inode(dir, dentry, NULL, S_IFDIR | mode,
				  0, NULL, 0, NULL);

	ni_unlock(ni);

	return IS_ERR(inode) ? PTR_ERR(inode) : 0;
}

/*
 * ntfs_rmdir - inode_operations::rm_dir
 */
static int ntfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct ntfs_inode *ni = ntfs_i(dir);
	int err;

	ni_lock_dir(ni);
>>>>>>> wip

	err = ntfs_unlink_inode(dir, dentry);

	ni_unlock(ni);

	return err;
}

/*
<<<<<<< HEAD
 * ntfs_rename
 *
 * inode_operations::rename
 */
static int ntfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry,
		       u32 flags)
{
	int err;
	struct super_block *sb = old_dir->i_sb;
	ntfs_sb_info *sbi = sb->s_fs_info;
	ntfs_inode *old_diri = ntfs_i(old_dir);
	ntfs_inode *new_diri = ntfs_i(new_dir);
	ntfs_inode *ni;
	ATTR_FILE_NAME *old_name, *new_name, *fname;
	u8 name_type;
	bool is_same;
	struct inode *old_inode, *new_inode;
	NTFS_DE *old_de, *new_de;
	ATTRIB *attr;
	ATTR_LIST_ENTRY *le;
	u16 new_de_key_size;

	static_assert(SIZEOF_ATTRIBUTE_FILENAME_MAX + SIZEOF_RESIDENT < 1024);
	static_assert(SIZEOF_ATTRIBUTE_FILENAME_MAX + sizeof(NTFS_DE) < 1024);
=======
 * ntfs_rename - inode_operations::rename
 */
static int ntfs_rename(struct inode *dir,
		       struct dentry *dentry, struct inode *new_dir,
		       struct dentry *new_dentry, u32 flags)
{
	int err;
	struct super_block *sb = dir->i_sb;
	struct ntfs_sb_info *sbi = sb->s_fs_info;
	struct ntfs_inode *dir_ni = ntfs_i(dir);
	struct ntfs_inode *new_dir_ni = ntfs_i(new_dir);
	struct inode *inode = d_inode(dentry);
	struct ntfs_inode *ni = ntfs_i(inode);
	struct inode *new_inode = d_inode(new_dentry);
	struct NTFS_DE *de, *new_de;
	bool is_same, is_bad;
	/*
	 * de		- memory of PATH_MAX bytes:
	 * [0-1024)	- original name (dentry->d_name)
	 * [1024-2048)	- paired to original name, usually DOS variant of dentry->d_name
	 * [2048-3072)	- new name (new_dentry->d_name)
	 */
	static_assert(SIZEOF_ATTRIBUTE_FILENAME_MAX + SIZEOF_RESIDENT < 1024);
	static_assert(SIZEOF_ATTRIBUTE_FILENAME_MAX + sizeof(struct NTFS_DE) <
		      1024);
>>>>>>> wip
	static_assert(PATH_MAX >= 4 * 1024);

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

<<<<<<< HEAD
	old_inode = d_inode(old_dentry);
	new_inode = d_inode(new_dentry);

	ni = ntfs_i(old_inode);

	ni_lock(ni);

	is_same = old_dentry->d_name.len == new_dentry->d_name.len &&
		  !memcmp(old_dentry->d_name.name, new_dentry->d_name.name,
			  old_dentry->d_name.len);

	if (is_same && old_dir == new_dir) {
		/* Nothing to do */
		err = 0;
		goto out1;
	}

	if (ntfs_is_meta_file(sbi, old_inode->i_ino)) {
		err = -EINVAL;
		goto out1;
	}

	if (new_inode) {
		/*target name exists. unlink it*/
		dget(new_dentry);
		err = ntfs_unlink_inode(new_dir, new_dentry);
		dput(new_dentry);
		if (err)
			goto out1;
	}

	old_de = __getname();
	if (!old_de) {
		err = -ENOMEM;
		goto out1;
	}

	err = fill_name_de(sbi, old_de, &old_dentry->d_name);
	if (err < 0)
		goto out2;

	old_name = (ATTR_FILE_NAME *)(old_de + 1);

	if (is_same) {
		new_de = old_de;
	} else {
		new_de = Add2Ptr(old_de, 1024);
		err = fill_name_de(sbi, new_de, &new_dentry->d_name);
		if (err < 0)
			goto out2;
	}

	old_name->home.low = cpu_to_le32(old_dir->i_ino);
#ifdef NTFS3_64BIT_CLUSTER
	old_name->home.high = cpu_to_le16(old_dir->i_ino >> 32);
#endif
	old_name->home.seq = ntfs_i(old_dir)->mi.mrec->seq;

	/*get pointer to file_name in mft*/
	fname = ni_fname_name(ni, (struct cpu_str *)&old_name->name_len,
			      &old_name->home, &le);
	if (!fname) {
		err = -EINVAL;
		goto out2;
	}

	/* Copy fname info from record into new fname */
	new_name = (ATTR_FILE_NAME *)(new_de + 1);
	memcpy(&new_name->dup, &fname->dup, sizeof(fname->dup));

	name_type = paired_name(fname->type);

	/* remove first name from directory */
	err = indx_delete_entry(&old_diri->dir, old_diri, old_de + 1,
				le16_to_cpu(old_de->key_size), sbi);
	if (err)
		goto out3;

	/* remove first name from mft */
	err = ni_remove_attr_le(ni, attr_from_name(fname), le);
	if (err)
		goto out4;

	le16_add_cpu(&ni->mi.mrec->hard_links, -1);
	ni->mi.dirty = true;

	if (name_type == FILE_NAME_POSIX)
		goto skip_short;

	/* get paired name */
	fname = ni_fname_type(ni, name_type, &le);
	if (!fname)
		goto skip_short;

	/* remove second name from directory */
	err = indx_delete_entry(&old_diri->dir, old_diri, fname,
				fname_full_size(fname), sbi);
	if (err)
		goto out5;

	/* remove second name from mft */
	err = ni_remove_attr_le(ni, attr_from_name(fname), le);
	if (err)
		goto out6;

	le16_add_cpu(&ni->mi.mrec->hard_links, -1);
	ni->mi.dirty = true;

skip_short:

	/* Add new name */
	new_de->ref.low = cpu_to_le32(old_inode->i_ino);
#ifdef NTFS3_64BIT_CLUSTER
	new_de->ref.high = cpu_to_le16(old_inode->i_ino >> 32);
	new_name->home.high = cpu_to_le16(new_dir->i_ino >> 32);
#endif
	new_de->ref.seq = ni->mi.mrec->seq;

	new_name->home.low = cpu_to_le32(new_dir->i_ino);
	new_name->home.seq = ntfs_i(new_dir)->mi.mrec->seq;

	new_de_key_size = le16_to_cpu(new_de->key_size);

	/* insert new name in mft */
	err = ni_insert_resident(ni, new_de_key_size, ATTR_NAME, NULL, 0, &attr,
				 NULL);
	if (err)
		goto out7;

	attr->res.flags = RESIDENT_FLAG_INDEXED;

	memcpy(Add2Ptr(attr, SIZEOF_RESIDENT), new_name, new_de_key_size);

	le16_add_cpu(&ni->mi.mrec->hard_links, 1);
	ni->mi.dirty = true;

	/* insert new name in directory */
	err = indx_insert_entry(&new_diri->dir, new_diri, new_de, sbi, NULL);
	if (err)
		goto out8;

	if (IS_DIRSYNC(new_dir))
		err = ntfs_sync_inode(old_inode);
	else
		mark_inode_dirty(old_inode);

	old_dir->i_ctime = old_dir->i_mtime = current_time(old_dir);
	if (IS_DIRSYNC(old_dir))
		(void)ntfs_sync_inode(old_dir);
	else
		mark_inode_dirty(old_dir);

	if (old_dir != new_dir) {
		new_dir->i_mtime = new_dir->i_ctime = old_dir->i_ctime;
		mark_inode_dirty(new_dir);
#ifdef NTFS_COUNT_CONTAINED
		if (S_ISDIR(old_inode->i_mode)) {
			drop_nlink(old_dir);
			if (!new_inode)
				inc_nlink(new_dir);
		}
#endif
	}

	if (old_inode) {
		old_inode->i_ctime = old_dir->i_ctime;
		mark_inode_dirty(old_inode);
	}

	err = 0;
	goto out2;

out8:
	mi_remove_attr(&ni->mi, attr);

out7:
out6:
out5:
out4:
	/* Undo:
	 *err = indx_delete_entry(&old_diri->dir, old_diri, old_de + 1,
	 *			old_de->key_size, NULL);
	 */

out3:
out2:
	__putname(old_de);
out1:
	ni_unlock(ni);

	return err;
}

/*
 * ntfs_atomic_open
 *
 * inode_operations::atomic_open
 */
static int ntfs_atomic_open(struct inode *dir, struct dentry *dentry,
			    struct file *file, u32 flags, umode_t mode)
{
	int err;
	bool excl = !!(flags & O_EXCL);
	struct inode *inode;
	struct ntfs_fnd *fnd = NULL;
	ntfs_inode *ni = ntfs_i(dir);

	ni_lock(ni);

	if (d_in_lookup(dentry)) {
		struct dentry *d;

		fnd = fnd_get(&ntfs_i(dir)->dir);
		if (!fnd) {
			err = -ENOMEM;
			goto out;
		}

		d = __ntfs_lookup(dir, dentry, fnd);
		if (IS_ERR(d)) {
			err = PTR_ERR(d);
			d = NULL;
			goto out1;
		}

		if (d)
			dentry = d;

		if (d_really_is_positive(dentry)) {
			if (file->f_mode & FMODE_OPENED) {
				dput(d);
				err = 0;
			} else
				err = finish_no_open(file, d);
			goto out1;
		}
		WARN_ON(d);
	}

	if (!(flags & O_CREAT)) {
		err = -ENOENT;
		goto out1;
	}

	err = ntfs_create_inode(dir, dentry, file, mode, 0, NULL, 0, excl, fnd,
				&inode);

out1:
	fnd_put(fnd);
out:
	ni_unlock(ni);

	return err;
}

struct dentry *ntfs_get_parent(struct dentry *child)
{
	struct inode *inode = d_inode(child);
	ntfs_inode *ni = ntfs_i(inode);

	ATTR_LIST_ENTRY *le = NULL;
	ATTRIB *attr = NULL;
	ATTR_FILE_NAME *fname;
=======
	is_same = dentry->d_name.len == new_dentry->d_name.len &&
		  !memcmp(dentry->d_name.name, new_dentry->d_name.name,
			  dentry->d_name.len);

	if (is_same && dir == new_dir) {
		/* Nothing to do. */
		return 0;
	}

	if (ntfs_is_meta_file(sbi, inode->i_ino)) {
		/* Should we print an error? */
		return -EINVAL;
	}

	if (new_inode) {
		/* Target name exists. Unlink it. */
		dget(new_dentry);
		ni_lock_dir(new_dir_ni);
		err = ntfs_unlink_inode(new_dir, new_dentry);
		ni_unlock(new_dir_ni);
		dput(new_dentry);
		if (err)
			return err;
	}

	/* Allocate PATH_MAX bytes. */
	de = __getname();
	if (!de)
		return -ENOMEM;

	/* Translate dentry->d_name into unicode form. */
	err = fill_name_de(sbi, de, &dentry->d_name, NULL);
	if (err < 0)
		goto out;

	if (is_same) {
		/* Reuse 'de'. */
		new_de = de;
	} else {
		/* Translate new_dentry->d_name into unicode form. */
		new_de = Add2Ptr(de, 2048);
		err = fill_name_de(sbi, new_de, &new_dentry->d_name, NULL);
		if (err < 0)
			goto out;
	}

	ni_lock_dir(dir_ni);
	ni_lock(ni);

	is_bad = false;
	err = ni_rename(dir_ni, new_dir_ni, ni, de, new_de, &is_bad);
	if (is_bad) {
		/* Restore after failed rename failed too. */
		make_bad_inode(inode);
		ntfs_inode_err(inode, "failed to undo rename");
		ntfs_set_state(sbi, NTFS_DIRTY_ERROR);
	} else if (!err) {
		inode->i_ctime = dir->i_ctime = dir->i_mtime =
			current_time(dir);
		mark_inode_dirty(inode);
		mark_inode_dirty(dir);
		if (dir != new_dir) {
			new_dir->i_mtime = new_dir->i_ctime = dir->i_ctime;
			mark_inode_dirty(new_dir);
		}

		if (IS_DIRSYNC(dir))
			ntfs_sync_inode(dir);

		if (IS_DIRSYNC(new_dir))
			ntfs_sync_inode(inode);
	}

	ni_unlock(ni);
	ni_unlock(dir_ni);
out:
	__putname(de);
	return err;
}

struct dentry *ntfs3_get_parent(struct dentry *child)
{
	struct inode *inode = d_inode(child);
	struct ntfs_inode *ni = ntfs_i(inode);

	struct ATTR_LIST_ENTRY *le = NULL;
	struct ATTRIB *attr = NULL;
	struct ATTR_FILE_NAME *fname;
>>>>>>> wip

	while ((attr = ni_find_attr(ni, attr, &le, ATTR_NAME, NULL, 0, NULL,
				    NULL))) {
		fname = resident_data_ex(attr, SIZEOF_ATTRIBUTE_FILENAME);
		if (!fname)
			continue;

		return d_obtain_alias(
			ntfs_iget5(inode->i_sb, &fname->home, NULL));
	}

	return ERR_PTR(-ENOENT);
}

<<<<<<< HEAD
const struct inode_operations ntfs_dir_inode_operations = {
	.lookup = ntfs_lookup,
	.create = ntfs_create,
	.link = ntfs_link,
	.unlink = ntfs_unlink,
	.symlink = ntfs_symlink,
	.mkdir = ntfs_mkdir,
	.rmdir = ntfs_rmdir,
	.rename = ntfs_rename,
	.permission = ntfs_permission,
	.get_acl = ntfs_get_acl,
	.set_acl = ntfs_set_acl,
	.setattr = ntfs_setattr,
	.getattr = ntfs_getattr,
	.listxattr = ntfs_listxattr,
	.atomic_open = ntfs_atomic_open,
};
=======
// clang-format off
const struct inode_operations ntfs_dir_inode_operations = {
	.lookup		= ntfs_lookup,
	.create		= ntfs_create,
	.link		= ntfs_link,
	.unlink		= ntfs_unlink,
	.symlink	= ntfs_symlink,
	.mkdir		= ntfs_mkdir,
	.rmdir		= ntfs_rmdir,
	.mknod		= ntfs_mknod,
	.rename		= ntfs_rename,
	.permission	= ntfs_permission,
	.get_acl	= ntfs_get_acl,
	.set_acl	= ntfs_set_acl,
	.setattr	= ntfs3_setattr,
	.getattr	= ntfs_getattr,
	.listxattr	= ntfs_listxattr,
	.fiemap		= ntfs_fiemap,
};

const struct inode_operations ntfs_special_inode_operations = {
	.setattr	= ntfs3_setattr,
	.getattr	= ntfs_getattr,
	.listxattr	= ntfs_listxattr,
	.get_acl	= ntfs_get_acl,
	.set_acl	= ntfs_set_acl,
};
// clang-format on
>>>>>>> wip
