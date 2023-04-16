// SPDX-License-Identifier: GPL-2.0
/*
<<<<<<< HEAD
 *  linux/fs/ntfs3/xattr.c
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
#include <linux/nls.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/xattr.h>

#include "debug.h"
#include "ntfs.h"
#include "ntfs_fs.h"

<<<<<<< HEAD
#define SYSTEM_DOS_ATTRIB "system.dos_attrib"
#define SYSTEM_NTFS_ATTRIB "system.ntfs_attrib"
#define SYSTEM_NTFS_ATTRIB_BE "system.ntfs_attrib_be"
#define SAMBA_PROCESS_NAME "smbd"
#define USER_DOSATTRIB "user.DOSATTRIB"

static inline size_t unpacked_ea_size(const EA_FULL *ea)
{
	return !ea->size ? DwordAlign(offsetof(EA_FULL, name) + 1 +
				      ea->name_len + le16_to_cpu(ea->elength)) :
			   le32_to_cpu(ea->size);
}

static inline size_t packed_ea_size(const EA_FULL *ea)
{
	return offsetof(EA_FULL, name) + 1 - offsetof(EA_FULL, flags) +
	       ea->name_len + le16_to_cpu(ea->elength);
=======
// clang-format off
#define SYSTEM_DOS_ATTRIB    "system.dos_attrib"
#define SYSTEM_NTFS_ATTRIB   "system.ntfs_attrib"
#define SYSTEM_NTFS_SECURITY "system.ntfs_security"
// clang-format on

static inline size_t unpacked_ea_size(const struct EA_FULL *ea)
{
	return ea->size ? le32_to_cpu(ea->size)
			: ALIGN(struct_size(ea, name,
					    1 + ea->name_len +
						    le16_to_cpu(ea->elength)),
				4);
}

static inline size_t packed_ea_size(const struct EA_FULL *ea)
{
	return struct_size(ea, name,
			   1 + ea->name_len + le16_to_cpu(ea->elength)) -
	       offsetof(struct EA_FULL, flags);
>>>>>>> wip
}

/*
 * find_ea
 *
<<<<<<< HEAD
 * assume there is at least one xattr in the list
 */
static inline bool find_ea(const EA_FULL *ea_all, u32 bytes, const char *name,
			   u8 name_len, u32 *off)
=======
 * Assume there is at least one xattr in the list.
 */
static inline bool find_ea(const struct EA_FULL *ea_all, u32 bytes,
			   const char *name, u8 name_len, u32 *off)
>>>>>>> wip
{
	*off = 0;

	if (!ea_all || !bytes)
		return false;

	for (;;) {
<<<<<<< HEAD
		const EA_FULL *ea = Add2Ptr(ea_all, *off);
=======
		const struct EA_FULL *ea = Add2Ptr(ea_all, *off);
>>>>>>> wip
		u32 next_off = *off + unpacked_ea_size(ea);

		if (next_off > bytes)
			return false;

		if (ea->name_len == name_len &&
		    !memcmp(ea->name, name, name_len))
			return true;

		*off = next_off;
		if (next_off >= bytes)
			return false;
	}
}

/*
<<<<<<< HEAD
 * ntfs_read_ea
 *
 * reads all xattrs
 * ea - new allocated memory
 * info - pointer into resident data
 */
static int ntfs_read_ea(ntfs_inode *ni, EA_FULL **ea, size_t add_bytes,
			const EA_INFO **info)
{
	int err;
	ATTR_LIST_ENTRY *le = NULL;
	ATTRIB *attr_info, *attr_ea;
=======
 * ntfs_read_ea - Read all extended attributes.
 * @ea:		New allocated memory.
 * @info:	Pointer into resident data.
 */
static int ntfs_read_ea(struct ntfs_inode *ni, struct EA_FULL **ea,
			size_t add_bytes, const struct EA_INFO **info)
{
	int err;
	struct ATTR_LIST_ENTRY *le = NULL;
	struct ATTRIB *attr_info, *attr_ea;
>>>>>>> wip
	void *ea_p;
	u32 size;

	static_assert(le32_to_cpu(ATTR_EA_INFO) < le32_to_cpu(ATTR_EA));

	*ea = NULL;
	*info = NULL;

	attr_info =
		ni_find_attr(ni, NULL, &le, ATTR_EA_INFO, NULL, 0, NULL, NULL);
	attr_ea =
		ni_find_attr(ni, attr_info, &le, ATTR_EA, NULL, 0, NULL, NULL);

	if (!attr_ea || !attr_info)
		return 0;

<<<<<<< HEAD
	*info = resident_data_ex(attr_info, sizeof(EA_INFO));
	if (!*info)
		return -EINVAL;

	/* Check Ea limit */
	size = le32_to_cpu((*info)->size);
	if (size > MAX_EA_DATA_SIZE || size + add_bytes > MAX_EA_DATA_SIZE)
		return -EINVAL;

	/* Allocate memory for packed Ea */
	ea_p = ntfs_alloc(size + add_bytes, 0);
=======
	*info = resident_data_ex(attr_info, sizeof(struct EA_INFO));
	if (!*info)
		return -EINVAL;

	/* Check Ea limit. */
	size = le32_to_cpu((*info)->size);
	if (size > ni->mi.sbi->ea_max_size)
		return -EFBIG;

	if (attr_size(attr_ea) > ni->mi.sbi->ea_max_size)
		return -EFBIG;

	/* Allocate memory for packed Ea. */
	ea_p = kmalloc(size + add_bytes, GFP_NOFS);
>>>>>>> wip
	if (!ea_p)
		return -ENOMEM;

	if (attr_ea->non_res) {
		struct runs_tree run;

		run_init(&run);

<<<<<<< HEAD
		err = attr_load_runs(attr_ea, ni, &run);
=======
		err = attr_load_runs(attr_ea, ni, &run, NULL);
>>>>>>> wip
		if (!err)
			err = ntfs_read_run_nb(ni->mi.sbi, &run, 0, ea_p, size,
					       NULL);
		run_close(&run);

		if (err)
			goto out;
	} else {
		void *p = resident_data_ex(attr_ea, size);

		if (!p) {
			err = -EINVAL;
			goto out;
		}
		memcpy(ea_p, p, size);
	}

	memset(Add2Ptr(ea_p, size), 0, add_bytes);
	*ea = ea_p;
	return 0;

out:
<<<<<<< HEAD
	ntfs_free(ea_p);
=======
	kfree(ea_p);
>>>>>>> wip
	*ea = NULL;
	return err;
}

/*
<<<<<<< HEAD
 * ntfs_listxattr_hlp
 *
 * copy a list of xattrs names into the buffer
 * provided, or compute the buffer size required
 */
static int ntfs_listxattr_hlp(ntfs_inode *ni, char *buffer,
			      size_t bytes_per_buffer, size_t *bytes)
{
	const EA_INFO *info;
	EA_FULL *ea_all = NULL;
	const EA_FULL *ea;
	u32 off, size;
	int err;

	*bytes = 0;
=======
 * ntfs_list_ea
 *
 * Copy a list of xattrs names into the buffer
 * provided, or compute the buffer size required.
 *
 * Return:
 * * Number of bytes used / required on
 * * -ERRNO - on failure
 */
static ssize_t ntfs_list_ea(struct ntfs_inode *ni, char *buffer,
			    size_t bytes_per_buffer)
{
	const struct EA_INFO *info;
	struct EA_FULL *ea_all = NULL;
	const struct EA_FULL *ea;
	u32 off, size;
	int err;
	size_t ret;
>>>>>>> wip

	err = ntfs_read_ea(ni, &ea_all, 0, &info);
	if (err)
		return err;

<<<<<<< HEAD
	if (!info)
=======
	if (!info || !ea_all)
>>>>>>> wip
		return 0;

	size = le32_to_cpu(info->size);

<<<<<<< HEAD
	if (!ea_all)
		return 0;

	/* Enumerate all xattrs */
	off = 0;
next_ea:
	if (off >= size)
		goto out;

	ea = Add2Ptr(ea_all, off);

	if (!buffer)
		goto skip_ea;

	if (*bytes + ea->name_len + 1 > bytes_per_buffer) {
		err = -ERANGE;
		goto out;
	}

	memcpy(buffer + *bytes, ea->name, ea->name_len);
	buffer[*bytes + ea->name_len] = 0;

skip_ea:
	*bytes += ea->name_len + 1;
	off += unpacked_ea_size(ea);
	goto next_ea;

out:
	ntfs_free(ea_all);
	return err;
}

/*
 * ntfs_get_ea
 *
 * reads xattr
 */
static int ntfs_get_ea(ntfs_inode *ni, const char *name, size_t name_len,
		       void *buffer, size_t bytes_per_buffer, u32 *len)
{
	const EA_INFO *info;
	EA_FULL *ea_all = NULL;
	const EA_FULL *ea;
	u32 off;
	int err;

	*len = 0;
=======
	/* Enumerate all xattrs. */
	for (ret = 0, off = 0; off < size; off += unpacked_ea_size(ea)) {
		ea = Add2Ptr(ea_all, off);

		if (buffer) {
			if (ret + ea->name_len + 1 > bytes_per_buffer) {
				err = -ERANGE;
				goto out;
			}

			memcpy(buffer + ret, ea->name, ea->name_len);
			buffer[ret + ea->name_len] = 0;
		}

		ret += ea->name_len + 1;
	}

out:
	kfree(ea_all);
	return err ? err : ret;
}

static int ntfs_get_ea(struct inode *inode, const char *name, size_t name_len,
		       void *buffer, size_t size, size_t *required)
{
	struct ntfs_inode *ni = ntfs_i(inode);
	const struct EA_INFO *info;
	struct EA_FULL *ea_all = NULL;
	const struct EA_FULL *ea;
	u32 off, len;
	int err;

	if (!(ni->ni_flags & NI_FLAG_EA))
		return -ENODATA;

	if (!required)
		ni_lock(ni);

	len = 0;
>>>>>>> wip

	if (name_len > 255) {
		err = -ENAMETOOLONG;
		goto out;
	}

	err = ntfs_read_ea(ni, &ea_all, 0, &info);
	if (err)
		goto out;

	if (!info)
		goto out;

<<<<<<< HEAD
	/* Enumerate all xattrs */
=======
	/* Enumerate all xattrs. */
>>>>>>> wip
	if (!find_ea(ea_all, le32_to_cpu(info->size), name, name_len, &off)) {
		err = -ENODATA;
		goto out;
	}
	ea = Add2Ptr(ea_all, off);

<<<<<<< HEAD
	*len = le16_to_cpu(ea->elength);
=======
	len = le16_to_cpu(ea->elength);
>>>>>>> wip
	if (!buffer) {
		err = 0;
		goto out;
	}

<<<<<<< HEAD
	if (*len > bytes_per_buffer) {
		err = -ERANGE;
		goto out;
	}
	memcpy(buffer, ea->name + ea->name_len + 1, *len);
	err = 0;

out:
	ntfs_free(ea_all);

	return err;
}

static noinline int ntfs_getxattr_hlp(struct inode *inode, const char *name,
				      void *value, size_t size,
				      size_t *required)
{
	ntfs_inode *ni = ntfs_i(inode);
	int err;
	u32 len;

	if (!(ni->ni_flags & NI_FLAG_EA))
		return -ENODATA;

	if (!required)
		ni_lock(ni);

	err = ntfs_get_ea(ni, name, strlen(name), value, size, &len);
	if (!err)
		err = len;
	else if (-ERANGE == err && required)
		*required = len;

	if (!required)
		ni_unlock(ni);

	return err;
}

static noinline int ntfs_set_ea(struct inode *inode, const char *name,
				const void *value, size_t val_size, int flags,
				int locked)
{
	ntfs_inode *ni = ntfs_i(inode);
	ntfs_sb_info *sbi = ni->mi.sbi;
	int err;
	EA_INFO ea_info;
	const EA_INFO *info;
	EA_FULL *new_ea;
	EA_FULL *ea_all = NULL;
	size_t name_len, add;
	u32 off, size;
	ATTRIB *attr;
	ATTR_LIST_ENTRY *le;
	mft_inode *mi;
=======
	if (len > size) {
		err = -ERANGE;
		if (required)
			*required = len;
		goto out;
	}

	memcpy(buffer, ea->name + ea->name_len + 1, len);
	err = 0;

out:
	kfree(ea_all);
	if (!required)
		ni_unlock(ni);

	return err ? err : len;
}

static noinline int ntfs_set_ea(struct inode *inode, const char *name,
				size_t name_len, const void *value,
				size_t val_size, int flags, int locked)
{
	struct ntfs_inode *ni = ntfs_i(inode);
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	int err;
	struct EA_INFO ea_info;
	const struct EA_INFO *info;
	struct EA_FULL *new_ea;
	struct EA_FULL *ea_all = NULL;
	size_t add, new_pack;
	u32 off, size;
	__le16 size_pack;
	struct ATTRIB *attr;
	struct ATTR_LIST_ENTRY *le;
	struct mft_inode *mi;
>>>>>>> wip
	struct runs_tree ea_run;
	u64 new_sz;
	void *p;

	if (!locked)
		ni_lock(ni);

	run_init(&ea_run);
<<<<<<< HEAD
	name_len = strlen(name);
=======
>>>>>>> wip

	if (name_len > 255) {
		err = -ENAMETOOLONG;
		goto out;
	}

<<<<<<< HEAD
	add = DwordAlign(offsetof(EA_FULL, name) + 1 + name_len + val_size);
=======
	add = ALIGN(struct_size(ea_all, name, 1 + name_len + val_size), 4);
>>>>>>> wip

	err = ntfs_read_ea(ni, &ea_all, add, &info);
	if (err)
		goto out;

	if (!info) {
		memset(&ea_info, 0, sizeof(ea_info));
		size = 0;
<<<<<<< HEAD
	} else {
		memcpy(&ea_info, info, sizeof(ea_info));
		size = le32_to_cpu(ea_info.size);
	}

	if (info && find_ea(ea_all, size, name, name_len, &off)) {
		EA_FULL *ea;
=======
		size_pack = 0;
	} else {
		memcpy(&ea_info, info, sizeof(ea_info));
		size = le32_to_cpu(ea_info.size);
		size_pack = ea_info.size_pack;
	}

	if (info && find_ea(ea_all, size, name, name_len, &off)) {
		struct EA_FULL *ea;
>>>>>>> wip
		size_t ea_sz;

		if (flags & XATTR_CREATE) {
			err = -EEXIST;
			goto out;
		}

<<<<<<< HEAD
		/* Remove current xattr */
		ea = Add2Ptr(ea_all, off);
=======
		ea = Add2Ptr(ea_all, off);

		/*
		 * Check simple case when we try to insert xattr with the same value
		 * e.g. ntfs_save_wsl_perm
		 */
		if (val_size && le16_to_cpu(ea->elength) == val_size &&
		    !memcmp(ea->name + ea->name_len + 1, value, val_size)) {
			/* xattr already contains the required value. */
			goto out;
		}

		/* Remove current xattr. */
>>>>>>> wip
		if (ea->flags & FILE_NEED_EA)
			le16_add_cpu(&ea_info.count, -1);

		ea_sz = unpacked_ea_size(ea);

		le16_add_cpu(&ea_info.size_pack, 0 - packed_ea_size(ea));

		memmove(ea, Add2Ptr(ea, ea_sz), size - off - ea_sz);

		size -= ea_sz;
		memset(Add2Ptr(ea_all, size), 0, ea_sz);

		ea_info.size = cpu_to_le32(size);

<<<<<<< HEAD
		if ((flags & XATTR_REPLACE) && !val_size)
			goto update_ea;
=======
		if ((flags & XATTR_REPLACE) && !val_size) {
			/* Remove xattr. */
			goto update_ea;
		}
>>>>>>> wip
	} else {
		if (flags & XATTR_REPLACE) {
			err = -ENODATA;
			goto out;
		}

		if (!ea_all) {
<<<<<<< HEAD
			ea_all = ntfs_alloc(add, 1);
=======
			ea_all = kzalloc(add, GFP_NOFS);
>>>>>>> wip
			if (!ea_all) {
				err = -ENOMEM;
				goto out;
			}
		}
	}

<<<<<<< HEAD
	/* append new xattr */
=======
	/* Append new xattr. */
>>>>>>> wip
	new_ea = Add2Ptr(ea_all, size);
	new_ea->size = cpu_to_le32(add);
	new_ea->flags = 0;
	new_ea->name_len = name_len;
	new_ea->elength = cpu_to_le16(val_size);
	memcpy(new_ea->name, name, name_len);
	new_ea->name[name_len] = 0;
	memcpy(new_ea->name + name_len + 1, value, val_size);
<<<<<<< HEAD

	le16_add_cpu(&ea_info.size_pack, packed_ea_size(new_ea));
	size += add;
=======
	new_pack = le16_to_cpu(ea_info.size_pack) + packed_ea_size(new_ea);

	/* Should fit into 16 bits. */
	if (new_pack > 0xffff) {
		err = -EFBIG; // -EINVAL?
		goto out;
	}
	ea_info.size_pack = cpu_to_le16(new_pack);

	/* New size of ATTR_EA. */
	size += add;
	if (size > sbi->ea_max_size) {
		err = -EFBIG; // -EINVAL?
		goto out;
	}
>>>>>>> wip
	ea_info.size = cpu_to_le32(size);

update_ea:

	if (!info) {
<<<<<<< HEAD
		/* Create xattr */
=======
		/* Create xattr. */
>>>>>>> wip
		if (!size) {
			err = 0;
			goto out;
		}

<<<<<<< HEAD
		err = ni_insert_resident(ni, sizeof(EA_INFO), ATTR_EA_INFO,
					 NULL, 0, NULL, NULL);
		if (err)
			goto out;

		err = ni_insert_resident(ni, 0, ATTR_EA, NULL, 0, NULL, NULL);
=======
		err = ni_insert_resident(ni, sizeof(struct EA_INFO),
					 ATTR_EA_INFO, NULL, 0, NULL, NULL,
					 NULL);
		if (err)
			goto out;

		err = ni_insert_resident(ni, 0, ATTR_EA, NULL, 0, NULL, NULL,
					 NULL);
>>>>>>> wip
		if (err)
			goto out;
	}

	new_sz = size;
	err = attr_set_size(ni, ATTR_EA, NULL, 0, &ea_run, new_sz, &new_sz,
			    false, NULL);
	if (err)
		goto out;

	le = NULL;
	attr = ni_find_attr(ni, NULL, &le, ATTR_EA_INFO, NULL, 0, NULL, &mi);
	if (!attr) {
		err = -EINVAL;
		goto out;
	}

	if (!size) {
<<<<<<< HEAD
		/* delete xattr, ATTR_EA_INFO */
		err = ni_remove_attr_le(ni, attr, le);
		if (err)
			goto out;
	} else {
		p = resident_data_ex(attr, sizeof(EA_INFO));
=======
		/* Delete xattr, ATTR_EA_INFO */
		ni_remove_attr_le(ni, attr, mi, le);
	} else {
		p = resident_data_ex(attr, sizeof(struct EA_INFO));
>>>>>>> wip
		if (!p) {
			err = -EINVAL;
			goto out;
		}
<<<<<<< HEAD
		memcpy(p, &ea_info, sizeof(EA_INFO));
=======
		memcpy(p, &ea_info, sizeof(struct EA_INFO));
>>>>>>> wip
		mi->dirty = true;
	}

	le = NULL;
	attr = ni_find_attr(ni, NULL, &le, ATTR_EA, NULL, 0, NULL, &mi);
	if (!attr) {
		err = -EINVAL;
		goto out;
	}

	if (!size) {
<<<<<<< HEAD
		/* delete xattr, ATTR_EA */
		err = ni_remove_attr_le(ni, attr, le);
		if (err)
			goto out;
=======
		/* Delete xattr, ATTR_EA */
		ni_remove_attr_le(ni, attr, mi, le);
>>>>>>> wip
	} else if (attr->non_res) {
		err = ntfs_sb_write_run(sbi, &ea_run, 0, ea_all, size);
		if (err)
			goto out;
	} else {
		p = resident_data_ex(attr, size);
		if (!p) {
			err = -EINVAL;
			goto out;
		}
		memcpy(p, ea_all, size);
		mi->dirty = true;
	}

<<<<<<< HEAD
	ni->ni_flags |= NI_FLAG_UPDATE_PARENT;
	mark_inode_dirty(&ni->vfs_inode);

	/* Check if we delete the last xattr */
	if (val_size || flags != XATTR_REPLACE ||
	    ntfs_listxattr_hlp(ni, NULL, 0, &val_size) || val_size) {
		ni->ni_flags |= NI_FLAG_EA;
	} else {
		ni->ni_flags &= ~NI_FLAG_EA;
	}
=======
	/* Check if we delete the last xattr. */
	if (size)
		ni->ni_flags |= NI_FLAG_EA;
	else
		ni->ni_flags &= ~NI_FLAG_EA;

	if (ea_info.size_pack != size_pack)
		ni->ni_flags |= NI_FLAG_UPDATE_PARENT;
	mark_inode_dirty(&ni->vfs_inode);
>>>>>>> wip

out:
	if (!locked)
		ni_unlock(ni);

	run_close(&ea_run);
<<<<<<< HEAD
	ntfs_free(ea_all);
=======
	kfree(ea_all);
>>>>>>> wip

	return err;
}

<<<<<<< HEAD
=======
#ifdef CONFIG_NTFS3_FS_POSIX_ACL
>>>>>>> wip
static inline void ntfs_posix_acl_release(struct posix_acl *acl)
{
	if (acl && refcount_dec_and_test(&acl->a_refcount))
		kfree(acl);
}

static struct posix_acl *ntfs_get_acl_ex(struct inode *inode, int type,
					 int locked)
{
<<<<<<< HEAD
	ntfs_inode *ni = ntfs_i(inode);
	const char *name;
=======
	struct ntfs_inode *ni = ntfs_i(inode);
	const char *name;
	size_t name_len;
>>>>>>> wip
	struct posix_acl *acl;
	size_t req;
	int err;
	void *buf;

<<<<<<< HEAD
=======
	/* Allocate PATH_MAX bytes. */
>>>>>>> wip
	buf = __getname();
	if (!buf)
		return ERR_PTR(-ENOMEM);

<<<<<<< HEAD
	/* Possible values of 'type' was already checked above */
	name = type == ACL_TYPE_ACCESS ? XATTR_NAME_POSIX_ACL_ACCESS :
					 XATTR_NAME_POSIX_ACL_DEFAULT;
=======
	/* Possible values of 'type' was already checked above. */
	if (type == ACL_TYPE_ACCESS) {
		name = XATTR_NAME_POSIX_ACL_ACCESS;
		name_len = sizeof(XATTR_NAME_POSIX_ACL_ACCESS) - 1;
	} else {
		name = XATTR_NAME_POSIX_ACL_DEFAULT;
		name_len = sizeof(XATTR_NAME_POSIX_ACL_DEFAULT) - 1;
	}
>>>>>>> wip

	if (!locked)
		ni_lock(ni);

<<<<<<< HEAD
	err = ntfs_getxattr_hlp(inode, name, buf, PATH_MAX, &req);
=======
	err = ntfs_get_ea(inode, name, name_len, buf, PATH_MAX, &req);
>>>>>>> wip

	if (!locked)
		ni_unlock(ni);

<<<<<<< HEAD
	/* Translate extended attribute to acl */
	if (err > 0) {
=======
	/* Translate extended attribute to acl. */
	if (err >= 0) {
>>>>>>> wip
		acl = posix_acl_from_xattr(&init_user_ns, buf, err);
		if (!IS_ERR(acl))
			set_cached_acl(inode, type, acl);
	} else {
		acl = err == -ENODATA ? NULL : ERR_PTR(err);
	}

	__putname(buf);

	return acl;
}

/*
<<<<<<< HEAD
 * ntfs_get_acl
 *
 * inode_operations::get_acl
 */
struct posix_acl *ntfs_get_acl(struct inode *inode, int type)
{
	struct posix_acl *acl;
	ntfs_inode *ni = ntfs_i(inode);

	ni_lock(ni);

	acl = ntfs_get_acl_ex(inode, type, 0);

	ni_unlock(ni);

	return acl;
}

static int ntfs_set_acl_ex(struct inode *inode, struct posix_acl *acl, int type,
			   int locked)
{
	const char *name;
	size_t size;
=======
 * ntfs_get_acl - inode_operations::get_acl
 */
struct posix_acl *ntfs_get_acl(struct inode *inode, int type)
{
	/* TODO: init_user_ns? */
	return ntfs_get_acl_ex(inode, type, 0);
}

static noinline int ntfs_set_acl_ex(struct inode *inode, struct posix_acl *acl,
				    int type, int locked)
{
	const char *name;
	size_t size, name_len;
>>>>>>> wip
	void *value = NULL;
	int err = 0;

	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;

	switch (type) {
	case ACL_TYPE_ACCESS:
		if (acl) {
			umode_t mode = inode->i_mode;

			err = posix_acl_equiv_mode(acl, &mode);
			if (err < 0)
				return err;

			if (inode->i_mode != mode) {
				inode->i_mode = mode;
				mark_inode_dirty(inode);
			}

			if (!err) {
				/*
<<<<<<< HEAD
				 * acl can be exactly represented in the
				 * traditional file mode permission bits
				 */
				acl = NULL;
				goto out;
			}
		}
		name = XATTR_NAME_POSIX_ACL_ACCESS;
=======
				 * ACL can be exactly represented in the
				 * traditional file mode permission bits.
				 */
				acl = NULL;
			}
		}
		name = XATTR_NAME_POSIX_ACL_ACCESS;
		name_len = sizeof(XATTR_NAME_POSIX_ACL_ACCESS) - 1;
>>>>>>> wip
		break;

	case ACL_TYPE_DEFAULT:
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
		name = XATTR_NAME_POSIX_ACL_DEFAULT;
<<<<<<< HEAD
=======
		name_len = sizeof(XATTR_NAME_POSIX_ACL_DEFAULT) - 1;
>>>>>>> wip
		break;

	default:
		return -EINVAL;
	}

<<<<<<< HEAD
	if (!acl)
		goto out;

	size = posix_acl_xattr_size(acl->a_count);
	value = ntfs_alloc(size, 0);
	if (!value)
		return -ENOMEM;

	err = posix_acl_to_xattr(&init_user_ns, acl, value, size);
	if (err)
		goto out;

	err = ntfs_set_ea(inode, name, value, size, 0, locked);
	if (err)
		goto out;

out:
	if (!err)
		set_cached_acl(inode, type, acl);

=======
	if (!acl) {
		size = 0;
		value = NULL;
	} else {
		size = posix_acl_xattr_size(acl->a_count);
		value = kmalloc(size, GFP_NOFS);
		if (!value)
			return -ENOMEM;

		err = posix_acl_to_xattr(&init_user_ns, acl, value, size);
		if (err < 0)
			goto out;
	}

	err = ntfs_set_ea(inode, name, name_len, value, size, 0, locked);
	if (!err)
		set_cached_acl(inode, type, acl);

out:
>>>>>>> wip
	kfree(value);

	return err;
}

/*
<<<<<<< HEAD
 * ntfs_set_acl
 *
 * inode_operations::set_acl
 */
int ntfs_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int err;
	ntfs_inode *ni = ntfs_i(inode);

	ni_lock(ni);

	err = ntfs_set_acl_ex(inode, acl, type, 0);

	ni_unlock(ni);

	return err;
=======
 * ntfs_set_acl - inode_operations::set_acl
 */
int ntfs_set_acl(struct inode *inode,
		 struct posix_acl *acl, int type)
{
	return ntfs_set_acl_ex(inode, acl, type, 0);
>>>>>>> wip
}

static int ntfs_xattr_get_acl(struct inode *inode, int type, void *buffer,
			      size_t size)
{
<<<<<<< HEAD
	struct super_block *sb = inode->i_sb;
	ntfs_sb_info *sbi = sb->s_fs_info;
	struct posix_acl *acl;
	int err;

	if (!sbi->options.acl)
		return -EOPNOTSUPP;
=======
	struct posix_acl *acl;
	int err;

	if (!(inode->i_sb->s_flags & SB_POSIXACL)) {
		ntfs_inode_warn(inode, "add mount option \"acl\" to use acl");
		return -EOPNOTSUPP;
	}
>>>>>>> wip

	acl = ntfs_get_acl(inode, type);
	if (IS_ERR(acl))
		return PTR_ERR(acl);

	if (!acl)
		return -ENODATA;

	err = posix_acl_to_xattr(&init_user_ns, acl, buffer, size);
	ntfs_posix_acl_release(acl);

	return err;
}

static int ntfs_xattr_set_acl(struct inode *inode, int type, const void *value,
			      size_t size)
{
<<<<<<< HEAD
	struct super_block *sb = inode->i_sb;
	ntfs_sb_info *sbi = sb->s_fs_info;
	struct posix_acl *acl;
	int err;

	if (!sbi->options.acl)
		return -EOPNOTSUPP;
=======
	struct posix_acl *acl;
	int err;

	if (!(inode->i_sb->s_flags & SB_POSIXACL)) {
		ntfs_inode_warn(inode, "add mount option \"acl\" to use acl");
		return -EOPNOTSUPP;
	}
>>>>>>> wip

	if (!inode_owner_or_capable(inode))
		return -EPERM;

<<<<<<< HEAD
	if (!value)
		return 0;

	acl = posix_acl_from_xattr(&init_user_ns, value, size);
	if (IS_ERR(acl))
		return PTR_ERR(acl);

	if (acl) {
		err = posix_acl_valid(sb->s_user_ns, acl);
		if (err)
			goto release_and_out;
=======
	if (!value) {
		acl = NULL;
	} else {
		acl = posix_acl_from_xattr(&init_user_ns, value, size);
		if (IS_ERR(acl))
			return PTR_ERR(acl);

		if (acl) {
			err = posix_acl_valid(&init_user_ns, acl);
			if (err)
				goto release_and_out;
		}
>>>>>>> wip
	}

	err = ntfs_set_acl(inode, acl, type);

release_and_out:
	ntfs_posix_acl_release(acl);
	return err;
}

/*
<<<<<<< HEAD
 * ntfs_acl_chmod
 *
 * helper for 'ntfs_setattr'
=======
 * ntfs_init_acl - Initialize the ACLs of a new inode.
 *
 * Called from ntfs_create_inode().
 */
int ntfs_init_acl(struct inode *inode,
		  struct inode *dir)
{
	struct posix_acl *default_acl, *acl;
	int err;

	/*
	 * TODO: Refactoring lock.
	 * ni_lock(dir) ... -> posix_acl_create(dir,...) -> ntfs_get_acl -> ni_lock(dir)
	 */
	inode->i_default_acl = NULL;

	default_acl = ntfs_get_acl_ex(dir, ACL_TYPE_DEFAULT, 1);

	if (!default_acl || default_acl == ERR_PTR(-EOPNOTSUPP)) {
		inode->i_mode &= ~current_umask();
		err = 0;
		goto out;
	}

	if (IS_ERR(default_acl)) {
		err = PTR_ERR(default_acl);
		goto out;
	}

	acl = default_acl;
	err = __posix_acl_create(&acl, GFP_NOFS, &inode->i_mode);
	if (err < 0)
		goto out1;
	if (!err) {
		posix_acl_release(acl);
		acl = NULL;
	}

	if (!S_ISDIR(inode->i_mode)) {
		posix_acl_release(default_acl);
		default_acl = NULL;
	}

	if (default_acl)
		err = ntfs_set_acl_ex(inode, default_acl,
				      ACL_TYPE_DEFAULT, 1);

	if (!acl)
		inode->i_acl = NULL;
	else if (!err)
		err = ntfs_set_acl_ex(inode, acl, ACL_TYPE_ACCESS,
				      1);

	posix_acl_release(acl);
out1:
	posix_acl_release(default_acl);

out:
	return err;
}
#endif

/*
 * ntfs_acl_chmod - Helper for ntfs3_setattr().
>>>>>>> wip
 */
int ntfs_acl_chmod(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
<<<<<<< HEAD
	ntfs_sb_info *sbi = sb->s_fs_info;
	int err;

	if (!sbi->options.acl)
=======

	if (!(sb->s_flags & SB_POSIXACL))
>>>>>>> wip
		return 0;

	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;

<<<<<<< HEAD
	err = posix_acl_chmod(inode, inode->i_mode);

	return err;
}

/*
 * ntfs_permission
 *
 * inode_operations::permission
 */
int ntfs_permission(struct inode *inode, int mask)
{
	struct super_block *sb = inode->i_sb;
	ntfs_sb_info *sbi = sb->s_fs_info;
	int err;

	if (sbi->options.no_acs_rules) {
		/* "no access rules" mode - allow all changes */
		return 0;
	}

	err = generic_permission(inode, mask);

	return err;
}

/*
 * ntfs_listxattr
 *
 * inode_operations::listxattr
=======
	return posix_acl_chmod(inode, inode->i_mode);
}

/*
 * ntfs_permission - inode_operations::permission
 */
int ntfs_permission(struct inode *inode,
		    int mask)
{
	if (ntfs_sb(inode->i_sb)->options.no_acs_rules) {
		/* "No access rules" mode - Allow all changes. */
		return 0;
	}

	return generic_permission(inode, mask);
}

/*
 * ntfs_listxattr - inode_operations::listxattr
>>>>>>> wip
 */
ssize_t ntfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct inode *inode = d_inode(dentry);
<<<<<<< HEAD
	ntfs_inode *ni = ntfs_i(inode);
	ssize_t ret = -1;
	int err;

	if (!(ni->ni_flags & NI_FLAG_EA)) {
		ret = 0;
		goto out;
=======
	struct ntfs_inode *ni = ntfs_i(inode);
	ssize_t ret;

	if (!(ni->ni_flags & NI_FLAG_EA)) {
		/* no xattr in file */
		return 0;
>>>>>>> wip
	}

	ni_lock(ni);

<<<<<<< HEAD
	err = ntfs_listxattr_hlp(ni, buffer, size, (size_t *)&ret);

	ni_unlock(ni);

	if (err)
		ret = err;
out:

=======
	ret = ntfs_list_ea(ni, buffer, size);

	ni_unlock(ni);

>>>>>>> wip
	return ret;
}

static int ntfs_getxattr(const struct xattr_handler *handler, struct dentry *de,
			 struct inode *inode, const char *name, void *buffer,
<<<<<<< HEAD
			 size_t size)
{
	int err;
	ntfs_inode *ni = ntfs_i(inode);
	struct super_block *sb = inode->i_sb;
	ntfs_sb_info *sbi = sb->s_fs_info;
	size_t name_len = strlen(name);

	/* Dispatch request */
	if (name_len == sizeof(SYSTEM_DOS_ATTRIB) - 1 &&
	    !memcmp(name, SYSTEM_DOS_ATTRIB, sizeof(SYSTEM_DOS_ATTRIB))) {
		/* system.dos_attrib */
		if (!buffer)
			err = sizeof(u8);
		else if (size < sizeof(u8))
			err = -ENODATA;
		else {
=======
			 size_t size, int flags)
{
	int err;
	struct ntfs_inode *ni = ntfs_i(inode);
	size_t name_len = strlen(name);

	/* Dispatch request. */
	if (name_len == sizeof(SYSTEM_DOS_ATTRIB) - 1 &&
	    !memcmp(name, SYSTEM_DOS_ATTRIB, sizeof(SYSTEM_DOS_ATTRIB))) {
		/* system.dos_attrib */
		if (!buffer) {
			err = sizeof(u8);
		} else if (size < sizeof(u8)) {
			err = -ENODATA;
		} else {
>>>>>>> wip
			err = sizeof(u8);
			*(u8 *)buffer = le32_to_cpu(ni->std_fa);
		}
		goto out;
	}

	if (name_len == sizeof(SYSTEM_NTFS_ATTRIB) - 1 &&
	    !memcmp(name, SYSTEM_NTFS_ATTRIB, sizeof(SYSTEM_NTFS_ATTRIB))) {
		/* system.ntfs_attrib */
<<<<<<< HEAD
		if (!buffer)
			err = sizeof(u32);
		else if (size < sizeof(u32))
			err = -ENODATA;
		else {
=======
		if (!buffer) {
			err = sizeof(u32);
		} else if (size < sizeof(u32)) {
			err = -ENODATA;
		} else {
>>>>>>> wip
			err = sizeof(u32);
			*(u32 *)buffer = le32_to_cpu(ni->std_fa);
		}
		goto out;
	}

<<<<<<< HEAD
	if (name_len == sizeof(SYSTEM_NTFS_ATTRIB_BE) - 1 &&
	    !memcmp(name, SYSTEM_NTFS_ATTRIB_BE,
		    sizeof(SYSTEM_NTFS_ATTRIB_BE))) {
		/* system.ntfs_attrib_be */
		if (!buffer)
			err = sizeof(u32);
		else if (size < sizeof(u32))
			err = -ENODATA;
		else {
			err = sizeof(u32);
			*(__be32 *)buffer =
				cpu_to_be32(le32_to_cpu(ni->std_fa));
		}
		goto out;
	}

	if (name_len == sizeof(USER_DOSATTRIB) - 1 &&
	    !memcmp(current->comm, SAMBA_PROCESS_NAME,
		    sizeof(SAMBA_PROCESS_NAME)) &&
	    !memcmp(name, USER_DOSATTRIB, sizeof(USER_DOSATTRIB))) {
		/* user.DOSATTRIB */
		if (!buffer)
			err = 5;
		else if (size < 5)
			err = -ENODATA;
		else {
			err = sprintf((char *)buffer, "0x%x",
				      le32_to_cpu(ni->std_fa) & 0xff) +
			      1;
		}
		goto out;
	}

=======
	if (name_len == sizeof(SYSTEM_NTFS_SECURITY) - 1 &&
	    !memcmp(name, SYSTEM_NTFS_SECURITY, sizeof(SYSTEM_NTFS_SECURITY))) {
		/* system.ntfs_security*/
		struct SECURITY_DESCRIPTOR_RELATIVE *sd = NULL;
		size_t sd_size = 0;

		if (!is_ntfs3(ni->mi.sbi)) {
			/* We should get nt4 security. */
			err = -EINVAL;
			goto out;
		} else if (le32_to_cpu(ni->std_security_id) <
			   SECURITY_ID_FIRST) {
			err = -ENOENT;
			goto out;
		}

		err = ntfs_get_security_by_id(ni->mi.sbi, ni->std_security_id,
					      &sd, &sd_size);
		if (err)
			goto out;

		if (!is_sd_valid(sd, sd_size)) {
			ntfs_inode_warn(
				inode,
				"looks like you get incorrect security descriptor id=%u",
				ni->std_security_id);
		}

		if (!buffer) {
			err = sd_size;
		} else if (size < sd_size) {
			err = -ENODATA;
		} else {
			err = sd_size;
			memcpy(buffer, sd, sd_size);
		}
		kfree(sd);
		goto out;
	}

#ifdef CONFIG_NTFS3_FS_POSIX_ACL
>>>>>>> wip
	if ((name_len == sizeof(XATTR_NAME_POSIX_ACL_ACCESS) - 1 &&
	     !memcmp(name, XATTR_NAME_POSIX_ACL_ACCESS,
		     sizeof(XATTR_NAME_POSIX_ACL_ACCESS))) ||
	    (name_len == sizeof(XATTR_NAME_POSIX_ACL_DEFAULT) - 1 &&
	     !memcmp(name, XATTR_NAME_POSIX_ACL_DEFAULT,
		     sizeof(XATTR_NAME_POSIX_ACL_DEFAULT)))) {
<<<<<<< HEAD
		err = sbi->options.acl ?
			      ntfs_xattr_get_acl(
				      inode,
				      name_len == sizeof(XATTR_NAME_POSIX_ACL_ACCESS) -
							      1 ?
					      ACL_TYPE_ACCESS :
					      ACL_TYPE_DEFAULT,
				      buffer, size) :
			      -EOPNOTSUPP;
		goto out;
	}

	err = ntfs_getxattr_hlp(inode, name, buffer, size, NULL);
=======
		/* TODO: init_user_ns? */
		err = ntfs_xattr_get_acl(
			inode,
			name_len == sizeof(XATTR_NAME_POSIX_ACL_ACCESS) - 1
				? ACL_TYPE_ACCESS
				: ACL_TYPE_DEFAULT,
			buffer, size);
		goto out;
	}
#endif
	/* Deal with NTFS extended attribute. */
	err = ntfs_get_ea(inode, name, name_len, buffer, size, NULL);
>>>>>>> wip

out:
	return err;
}

/*
<<<<<<< HEAD
 * ntfs_setxattr
 *
 * inode_operations::setxattr
=======
 * ntfs_setxattr - inode_operations::setxattr
>>>>>>> wip
 */
static noinline int ntfs_setxattr(const struct xattr_handler *handler,
				  struct dentry *de, struct inode *inode,
				  const char *name, const void *value,
				  size_t size, int flags)
{
	int err = -EINVAL;
<<<<<<< HEAD
	ntfs_inode *ni = ntfs_i(inode);
	size_t name_len = strlen(name);
	u32 attrib = 0; /* not necessary just to suppress warnings */
	struct super_block *sb = inode->i_sb;
	ntfs_sb_info *sbi = sb->s_fs_info;

	/* Dispatch request */
=======
	struct ntfs_inode *ni = ntfs_i(inode);
	size_t name_len = strlen(name);
	enum FILE_ATTRIBUTE new_fa;

	/* Dispatch request. */
>>>>>>> wip
	if (name_len == sizeof(SYSTEM_DOS_ATTRIB) - 1 &&
	    !memcmp(name, SYSTEM_DOS_ATTRIB, sizeof(SYSTEM_DOS_ATTRIB))) {
		if (sizeof(u8) != size)
			goto out;
<<<<<<< HEAD
		attrib = *(u8 *)value;
		goto set_dos_attr;
=======
		new_fa = cpu_to_le32(*(u8 *)value);
		goto set_new_fa;
>>>>>>> wip
	}

	if (name_len == sizeof(SYSTEM_NTFS_ATTRIB) - 1 &&
	    !memcmp(name, SYSTEM_NTFS_ATTRIB, sizeof(SYSTEM_NTFS_ATTRIB))) {
<<<<<<< HEAD
		if (sizeof(u32) != size)
			goto out;
		attrib = *(u32 *)value;
		goto set_dos_attr;
	}

	if (name_len == sizeof(SYSTEM_NTFS_ATTRIB_BE) - 1 &&
	    !memcmp(name, SYSTEM_NTFS_ATTRIB_BE,
		    sizeof(SYSTEM_NTFS_ATTRIB_BE))) {
		if (sizeof(u32) != size)
			goto out;
		attrib = be32_to_cpu(*(__be32 *)value);
		goto set_dos_attr;
	}

	if (name_len == sizeof(USER_DOSATTRIB) - 1 &&
	    !memcmp(current->comm, SAMBA_PROCESS_NAME,
		    sizeof(SAMBA_PROCESS_NAME)) &&
	    !memcmp(name, USER_DOSATTRIB, sizeof(USER_DOSATTRIB))) {
		if (size < 4 || ((char *)value)[size - 1])
			goto out;

		/*
		 * The input value must be string in form 0x%x with last zero
		 * This means that the 'size' must be 4, 5, ...
		 *  E.g: 0x1 - 4 bytes, 0x20 - 5 bytes
		 */
		if (sscanf((char *)value, "0x%x", &attrib) != 1)
			goto out;

set_dos_attr:
		if (!value)
			goto out;

		ni->std_fa = cpu_to_le32(attrib);
		mark_inode_dirty(inode);
=======
		if (size != sizeof(u32))
			goto out;
		new_fa = cpu_to_le32(*(u32 *)value);

		if (S_ISREG(inode->i_mode)) {
			/* Process compressed/sparsed in special way. */
			ni_lock(ni);
			err = ni_new_attr_flags(ni, new_fa);
			ni_unlock(ni);
			if (err)
				goto out;
		}
set_new_fa:
		/*
		 * Thanks Mark Harmstone:
		 * Keep directory bit consistency.
		 */
		if (S_ISDIR(inode->i_mode))
			new_fa |= FILE_ATTRIBUTE_DIRECTORY;
		else
			new_fa &= ~FILE_ATTRIBUTE_DIRECTORY;

		if (ni->std_fa != new_fa) {
			ni->std_fa = new_fa;
			if (new_fa & FILE_ATTRIBUTE_READONLY)
				inode->i_mode &= ~0222;
			else
				inode->i_mode |= 0222;
			/* Std attribute always in primary record. */
			ni->mi.dirty = true;
			mark_inode_dirty(inode);
		}
>>>>>>> wip
		err = 0;

		goto out;
	}

<<<<<<< HEAD
=======
	if (name_len == sizeof(SYSTEM_NTFS_SECURITY) - 1 &&
	    !memcmp(name, SYSTEM_NTFS_SECURITY, sizeof(SYSTEM_NTFS_SECURITY))) {
		/* system.ntfs_security*/
		__le32 security_id;
		bool inserted;
		struct ATTR_STD_INFO5 *std;

		if (!is_ntfs3(ni->mi.sbi)) {
			/*
			 * We should replace ATTR_SECURE.
			 * Skip this way cause it is nt4 feature.
			 */
			err = -EINVAL;
			goto out;
		}

		if (!is_sd_valid(value, size)) {
			err = -EINVAL;
			ntfs_inode_warn(
				inode,
				"you try to set invalid security descriptor");
			goto out;
		}

		err = ntfs_insert_security(ni->mi.sbi, value, size,
					   &security_id, &inserted);
		if (err)
			goto out;

		ni_lock(ni);
		std = ni_std5(ni);
		if (!std) {
			err = -EINVAL;
		} else if (std->security_id != security_id) {
			std->security_id = ni->std_security_id = security_id;
			/* Std attribute always in primary record. */
			ni->mi.dirty = true;
			mark_inode_dirty(&ni->vfs_inode);
		}
		ni_unlock(ni);
		goto out;
	}

#ifdef CONFIG_NTFS3_FS_POSIX_ACL
>>>>>>> wip
	if ((name_len == sizeof(XATTR_NAME_POSIX_ACL_ACCESS) - 1 &&
	     !memcmp(name, XATTR_NAME_POSIX_ACL_ACCESS,
		     sizeof(XATTR_NAME_POSIX_ACL_ACCESS))) ||
	    (name_len == sizeof(XATTR_NAME_POSIX_ACL_DEFAULT) - 1 &&
	     !memcmp(name, XATTR_NAME_POSIX_ACL_DEFAULT,
		     sizeof(XATTR_NAME_POSIX_ACL_DEFAULT)))) {
<<<<<<< HEAD
		err = sbi->options.acl ?
			      ntfs_xattr_set_acl(
				      inode,
				      name_len == sizeof(XATTR_NAME_POSIX_ACL_ACCESS) -
							      1 ?
					      ACL_TYPE_ACCESS :
					      ACL_TYPE_DEFAULT,
				      value, size) :
			      -EOPNOTSUPP;
		goto out;
	}

	err = ntfs_set_ea(inode, name, value, size, flags, 0);
=======
		err = ntfs_xattr_set_acl(
			inode,
			name_len == sizeof(XATTR_NAME_POSIX_ACL_ACCESS) - 1
				? ACL_TYPE_ACCESS
				: ACL_TYPE_DEFAULT,
			value, size);
		goto out;
	}
#endif
	/* Deal with NTFS extended attribute. */
	err = ntfs_set_ea(inode, name, name_len, value, size, flags, 0);
>>>>>>> wip

out:
	return err;
}

<<<<<<< HEAD
static bool ntfs_xattr_user_list(struct dentry *dentry)
{
	return 1;
}

static const struct xattr_handler ntfs_xattr_handler = {
	.prefix = "",
	.get = ntfs_getxattr,
	.set = ntfs_setxattr,
	.list = ntfs_xattr_user_list,
};

const struct xattr_handler *ntfs_xattr_handlers[] = { &ntfs_xattr_handler,
						      NULL };
=======
/*
 * ntfs_save_wsl_perm
 *
 * save uid/gid/mode in xattr
 */
int ntfs_save_wsl_perm(struct inode *inode)
{
	int err;
	__le32 value;

	value = cpu_to_le32(i_uid_read(inode));
	err = ntfs_set_ea(inode, "$LXUID", sizeof("$LXUID") - 1, &value,
			  sizeof(value), 0, 0);
	if (err)
		goto out;

	value = cpu_to_le32(i_gid_read(inode));
	err = ntfs_set_ea(inode, "$LXGID", sizeof("$LXGID") - 1, &value,
			  sizeof(value), 0, 0);
	if (err)
		goto out;

	value = cpu_to_le32(inode->i_mode);
	err = ntfs_set_ea(inode, "$LXMOD", sizeof("$LXMOD") - 1, &value,
			  sizeof(value), 0, 0);
	if (err)
		goto out;

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		value = cpu_to_le32(inode->i_rdev);
		err = ntfs_set_ea(inode, "$LXDEV", sizeof("$LXDEV") - 1, &value,
				  sizeof(value), 0, 0);
		if (err)
			goto out;
	}

out:
	/* In case of error should we delete all WSL xattr? */
	return err;
}

/*
 * ntfs_get_wsl_perm
 *
 * get uid/gid/mode from xattr
 * it is called from ntfs_iget5->ntfs_read_mft
 */
void ntfs_get_wsl_perm(struct inode *inode)
{
	size_t sz;
	__le32 value[3];

	if (ntfs_get_ea(inode, "$LXUID", sizeof("$LXUID") - 1, &value[0],
			sizeof(value[0]), &sz) == sizeof(value[0]) &&
	    ntfs_get_ea(inode, "$LXGID", sizeof("$LXGID") - 1, &value[1],
			sizeof(value[1]), &sz) == sizeof(value[1]) &&
	    ntfs_get_ea(inode, "$LXMOD", sizeof("$LXMOD") - 1, &value[2],
			sizeof(value[2]), &sz) == sizeof(value[2])) {
		i_uid_write(inode, (uid_t)le32_to_cpu(value[0]));
		i_gid_write(inode, (gid_t)le32_to_cpu(value[1]));
		inode->i_mode = le32_to_cpu(value[2]);

		if (ntfs_get_ea(inode, "$LXDEV", sizeof("$$LXDEV") - 1,
				&value[0], sizeof(value),
				&sz) == sizeof(value[0])) {
			inode->i_rdev = le32_to_cpu(value[0]);
		}
	}
}

static bool ntfs_xattr_user_list(struct dentry *dentry)
{
	return true;
}

// clang-format off
static const struct xattr_handler ntfs_xattr_handler = {
	.prefix	= "",
	.get	= ntfs_getxattr,
	.set	= ntfs_setxattr,
	.list	= ntfs_xattr_user_list,
};

const struct xattr_handler *ntfs_xattr_handlers[] = {
	&ntfs_xattr_handler,
	NULL,
};
// clang-format on
>>>>>>> wip
