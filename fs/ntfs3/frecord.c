// SPDX-License-Identifier: GPL-2.0
/*
<<<<<<< HEAD
 *  linux/fs/ntfs3/frecord.c
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
<<<<<<< HEAD
#include <linux/fs.h>
#include <linux/nls.h>
#include <linux/sched/signal.h>
=======
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/nls.h>
#include <linux/vmalloc.h>
>>>>>>> wip

#include "debug.h"
#include "ntfs.h"
#include "ntfs_fs.h"
<<<<<<< HEAD

static inline void get_mi_ref(const mft_inode *mi, MFT_REF *ref)
{
#ifdef NTFS3_64BIT_CLUSTER
	ref->low = cpu_to_le32(mi->rno);
	ref->high = cpu_to_le16(mi->rno >> 32);
#else
	ref->low = cpu_to_le32(mi->rno);
	ref->high = 0;
#endif
	ref->seq = mi->mrec->seq;
}

static mft_inode *ni_ins_mi(ntfs_inode *ni, struct rb_root *tree, CLST ino,
			    struct rb_node *ins)
=======
#ifdef CONFIG_NTFS3_LZX_XPRESS
#include "lib/lib.h"
#endif

static struct mft_inode *ni_ins_mi(struct ntfs_inode *ni, struct rb_root *tree,
				   CLST ino, struct rb_node *ins)
>>>>>>> wip
{
	struct rb_node **p = &tree->rb_node;
	struct rb_node *pr = NULL;

	while (*p) {
<<<<<<< HEAD
		mft_inode *mi;

		pr = *p;
		mi = rb_entry(pr, mft_inode, node);
=======
		struct mft_inode *mi;

		pr = *p;
		mi = rb_entry(pr, struct mft_inode, node);
>>>>>>> wip
		if (mi->rno > ino)
			p = &pr->rb_left;
		else if (mi->rno < ino)
			p = &pr->rb_right;
		else
			return mi;
	}

	if (!ins)
		return NULL;

	rb_link_node(ins, pr, p);
	rb_insert_color(ins, tree);
<<<<<<< HEAD
	return rb_entry(ins, mft_inode, node);
}

/*
 * ni_find_mi
 *
 * finds mft_inode by record number
 */
static mft_inode *ni_find_mi(ntfs_inode *ni, CLST rno)
=======
	return rb_entry(ins, struct mft_inode, node);
}

/*
 * ni_find_mi - Find mft_inode by record number.
 */
static struct mft_inode *ni_find_mi(struct ntfs_inode *ni, CLST rno)
>>>>>>> wip
{
	return ni_ins_mi(ni, &ni->mi_tree, rno, NULL);
}

/*
<<<<<<< HEAD
 * ni_add_mi
 *
 * adds new mft_inode into ntfs_inode
 */
static void ni_add_mi(ntfs_inode *ni, mft_inode *mi)
=======
 * ni_add_mi - Add new mft_inode into ntfs_inode.
 */
static void ni_add_mi(struct ntfs_inode *ni, struct mft_inode *mi)
>>>>>>> wip
{
	ni_ins_mi(ni, &ni->mi_tree, mi->rno, &mi->node);
}

/*
<<<<<<< HEAD
 * ni_remove_mi
 *
 * removes mft_inode from ntfs_inode
 */
void ni_remove_mi(ntfs_inode *ni, mft_inode *mi)
=======
 * ni_remove_mi - Remove mft_inode from ntfs_inode.
 */
void ni_remove_mi(struct ntfs_inode *ni, struct mft_inode *mi)
>>>>>>> wip
{
	rb_erase(&mi->node, &ni->mi_tree);
}

/*
<<<<<<< HEAD
 * ni_std
 *
 * returns pointer into std_info from primary record
 */
ATTR_STD_INFO *ni_std(ntfs_inode *ni)
{
	const ATTRIB *attr;

	attr = mi_find_attr(&ni->mi, NULL, ATTR_STD, NULL, 0, NULL);

	return attr ? resident_data_ex(attr, sizeof(ATTR_STD_INFO)) : NULL;
}

/*
 * ni_clear
 *
 * clears resources allocated by ntfs_inode
 */
void ni_clear(ntfs_inode *ni)
{
	struct rb_node *node;

	if (!ni->vfs_inode.i_nlink)
=======
 * ni_std - Return: Pointer into std_info from primary record.
 */
struct ATTR_STD_INFO *ni_std(struct ntfs_inode *ni)
{
	const struct ATTRIB *attr;

	attr = mi_find_attr(&ni->mi, NULL, ATTR_STD, NULL, 0, NULL);
	return attr ? resident_data_ex(attr, sizeof(struct ATTR_STD_INFO))
		    : NULL;
}

/*
 * ni_std5
 *
 * Return: Pointer into std_info from primary record.
 */
struct ATTR_STD_INFO5 *ni_std5(struct ntfs_inode *ni)
{
	const struct ATTRIB *attr;

	attr = mi_find_attr(&ni->mi, NULL, ATTR_STD, NULL, 0, NULL);

	return attr ? resident_data_ex(attr, sizeof(struct ATTR_STD_INFO5))
		    : NULL;
}

/*
 * ni_clear - Clear resources allocated by ntfs_inode.
 */
void ni_clear(struct ntfs_inode *ni)
{
	struct rb_node *node;

	if (!ni->vfs_inode.i_nlink && is_rec_inuse(ni->mi.mrec))
>>>>>>> wip
		ni_delete_all(ni);

	al_destroy(ni);

	for (node = rb_first(&ni->mi_tree); node;) {
		struct rb_node *next = rb_next(node);
<<<<<<< HEAD
		mft_inode *mi = rb_entry(node, mft_inode, node);
=======
		struct mft_inode *mi = rb_entry(node, struct mft_inode, node);
>>>>>>> wip

		rb_erase(node, &ni->mi_tree);
		mi_put(mi);
		node = next;
	}

<<<<<<< HEAD
	/* bad inode always has mode == S_IFREG */
	if (ni->ni_flags & NI_FLAG_DIR)
		indx_clear(&ni->dir);
	else
		run_close(&ni->file.run);
=======
	/* Bad inode always has mode == S_IFREG. */
	if (ni->ni_flags & NI_FLAG_DIR)
		indx_clear(&ni->dir);
	else {
		run_close(&ni->file.run);
#ifdef CONFIG_NTFS3_LZX_XPRESS
		if (ni->file.offs_page) {
			/* On-demand allocated page for offsets. */
			put_page(ni->file.offs_page);
			ni->file.offs_page = NULL;
		}
#endif
	}
>>>>>>> wip

	mi_clear(&ni->mi);
}

/*
<<<<<<< HEAD
 * ni_load_mi_ex
 *
 * finds mft_inode by record number.
 */
int ni_load_mi_ex(ntfs_inode *ni, CLST rno, mft_inode **mi)
{
	int err;
	mft_inode *r;
=======
 * ni_load_mi_ex - Find mft_inode by record number.
 */
int ni_load_mi_ex(struct ntfs_inode *ni, CLST rno, struct mft_inode **mi)
{
	int err;
	struct mft_inode *r;
>>>>>>> wip

	r = ni_find_mi(ni, rno);
	if (r)
		goto out;

	err = mi_get(ni->mi.sbi, rno, &r);
	if (err)
		return err;

	ni_add_mi(ni, r);

out:
	if (mi)
		*mi = r;
	return 0;
}

/*
<<<<<<< HEAD
 * ni_load_mi
 *
 * load mft_inode corresponded list_entry
 */
int ni_load_mi(ntfs_inode *ni, ATTR_LIST_ENTRY *le, mft_inode **mi)
=======
 * ni_load_mi - Load mft_inode corresponded list_entry.
 */
int ni_load_mi(struct ntfs_inode *ni, const struct ATTR_LIST_ENTRY *le,
	       struct mft_inode **mi)
>>>>>>> wip
{
	CLST rno;

	if (!le) {
		*mi = &ni->mi;
		return 0;
	}

	rno = ino_get(&le->ref);
	if (rno == ni->mi.rno) {
		*mi = &ni->mi;
		return 0;
	}
	return ni_load_mi_ex(ni, rno, mi);
}

/*
 * ni_find_attr
 *
<<<<<<< HEAD
 * returns attribute and record this attribute belongs to
 */
ATTRIB *ni_find_attr(ntfs_inode *ni, ATTRIB *attr, ATTR_LIST_ENTRY **le_o,
		     ATTR_TYPE type, const __le16 *name, u8 name_len,
		     const CLST *vcn, mft_inode **mi)
{
	ATTR_LIST_ENTRY *le;
	mft_inode *m;
=======
 * Return: Attribute and record this attribute belongs to.
 */
struct ATTRIB *ni_find_attr(struct ntfs_inode *ni, struct ATTRIB *attr,
			    struct ATTR_LIST_ENTRY **le_o, enum ATTR_TYPE type,
			    const __le16 *name, u8 name_len, const CLST *vcn,
			    struct mft_inode **mi)
{
	struct ATTR_LIST_ENTRY *le;
	struct mft_inode *m;
>>>>>>> wip

	if (!ni->attr_list.size ||
	    (!name_len && (type == ATTR_LIST || type == ATTR_STD))) {
		if (le_o)
			*le_o = NULL;
		if (mi)
			*mi = &ni->mi;

<<<<<<< HEAD
		/* Look for required attribute in primary record */
		return mi_find_attr(&ni->mi, attr, type, name, name_len, NULL);
	}

	/* first look for list entry of required type */
=======
		/* Look for required attribute in primary record. */
		return mi_find_attr(&ni->mi, attr, type, name, name_len, NULL);
	}

	/* First look for list entry of required type. */
>>>>>>> wip
	le = al_find_ex(ni, le_o ? *le_o : NULL, type, name, name_len, vcn);
	if (!le)
		return NULL;

	if (le_o)
		*le_o = le;

<<<<<<< HEAD
	/* Load record that contains this attribute */
	if (ni_load_mi(ni, le, &m))
		return NULL;

	/* Look for required attribute */
=======
	/* Load record that contains this attribute. */
	if (ni_load_mi(ni, le, &m))
		return NULL;

	/* Look for required attribute. */
>>>>>>> wip
	attr = mi_find_attr(m, NULL, type, name, name_len, &le->id);

	if (!attr)
		goto out;

	if (!attr->non_res) {
		if (vcn && *vcn)
			goto out;
	} else if (!vcn) {
		if (attr->nres.svcn)
			goto out;
	} else if (le64_to_cpu(attr->nres.svcn) > *vcn ||
		   *vcn > le64_to_cpu(attr->nres.evcn)) {
		goto out;
	}

	if (mi)
		*mi = m;
	return attr;

out:
	ntfs_set_state(ni->mi.sbi, NTFS_DIRTY_ERROR);
	return NULL;
}

/*
<<<<<<< HEAD
 * ni_enum_attr_ex
 *
 * enumerates attributes in ntfs_inode
 */
ATTRIB *ni_enum_attr_ex(ntfs_inode *ni, ATTRIB *attr, ATTR_LIST_ENTRY **le)
{
	mft_inode *mi;
	ATTR_LIST_ENTRY *le2;
=======
 * ni_enum_attr_ex - Enumerates attributes in ntfs_inode.
 */
struct ATTRIB *ni_enum_attr_ex(struct ntfs_inode *ni, struct ATTRIB *attr,
			       struct ATTR_LIST_ENTRY **le,
			       struct mft_inode **mi)
{
	struct mft_inode *mi2;
	struct ATTR_LIST_ENTRY *le2;
>>>>>>> wip

	/* Do we have an attribute list? */
	if (!ni->attr_list.size) {
		*le = NULL;
<<<<<<< HEAD
		/* Enum attributes in primary record */
		return mi_enum_attr(&ni->mi, attr);
	}

	/* get next list entry */
=======
		if (mi)
			*mi = &ni->mi;
		/* Enum attributes in primary record. */
		return mi_enum_attr(&ni->mi, attr);
	}

	/* Get next list entry. */
>>>>>>> wip
	le2 = *le = al_enumerate(ni, attr ? *le : NULL);
	if (!le2)
		return NULL;

<<<<<<< HEAD
	/* Load record that contains the required atribute */
	if (ni_load_mi(ni, le2, &mi))
		return NULL;

	/* Find attribute in loaded record */
	attr = rec_find_attr_le(mi, le2);

	return attr;
}

/*
 * ni_load_attr
 *
 * loads attribute that contains given vcn
 */
ATTRIB *ni_load_attr(ntfs_inode *ni, ATTR_TYPE type, const __le16 *name,
		     u8 name_len, CLST vcn, mft_inode **pmi)
{
	ATTR_LIST_ENTRY *le;
	ATTRIB *attr;
	mft_inode *mi;
	ATTR_LIST_ENTRY *next;
=======
	/* Load record that contains the required attribute. */
	if (ni_load_mi(ni, le2, &mi2))
		return NULL;

	if (mi)
		*mi = mi2;

	/* Find attribute in loaded record. */
	return rec_find_attr_le(mi2, le2);
}

/*
 * ni_load_attr - Load attribute that contains given VCN.
 */
struct ATTRIB *ni_load_attr(struct ntfs_inode *ni, enum ATTR_TYPE type,
			    const __le16 *name, u8 name_len, CLST vcn,
			    struct mft_inode **pmi)
{
	struct ATTR_LIST_ENTRY *le;
	struct ATTRIB *attr;
	struct mft_inode *mi;
	struct ATTR_LIST_ENTRY *next;
>>>>>>> wip

	if (!ni->attr_list.size) {
		if (pmi)
			*pmi = &ni->mi;
		return mi_find_attr(&ni->mi, NULL, type, name, name_len, NULL);
	}

	le = al_find_ex(ni, NULL, type, name, name_len, NULL);
<<<<<<< HEAD

=======
>>>>>>> wip
	if (!le)
		return NULL;

	/*
<<<<<<< HEAD
	 * Unfortunately ATTR_LIST_ENTRY contains only start vcn
	 * So to find the ATTRIB segment that contains Vcn we should
	 * enumerate some entries
	 */
	if (!vcn)
		goto load_rec;

next_le:
	next = al_find_ex(ni, le, type, name, name_len, NULL);
	if (!next || le64_to_cpu(next->vcn) > vcn)
		goto load_rec;

	le = next;
	goto next_le;

load_rec:
=======
	 * Unfortunately ATTR_LIST_ENTRY contains only start VCN.
	 * So to find the ATTRIB segment that contains 'vcn' we should
	 * enumerate some entries.
	 */
	if (vcn) {
		for (;; le = next) {
			next = al_find_ex(ni, le, type, name, name_len, NULL);
			if (!next || le64_to_cpu(next->vcn) > vcn)
				break;
		}
	}

>>>>>>> wip
	if (ni_load_mi(ni, le, &mi))
		return NULL;

	if (pmi)
		*pmi = mi;

	attr = mi_find_attr(mi, NULL, type, name, name_len, &le->id);
	if (!attr)
		return NULL;

	if (!attr->non_res)
		return attr;

	if (le64_to_cpu(attr->nres.svcn) <= vcn &&
	    vcn <= le64_to_cpu(attr->nres.evcn))
		return attr;

	return NULL;
}

/*
<<<<<<< HEAD
 * ni_load_all_mi
 *
 * loads all subrecords
 */
int ni_load_all_mi(ntfs_inode *ni)
{
	int err;
	ATTR_LIST_ENTRY *le;
=======
 * ni_load_all_mi - Load all subrecords.
 */
int ni_load_all_mi(struct ntfs_inode *ni)
{
	int err;
	struct ATTR_LIST_ENTRY *le;
>>>>>>> wip

	if (!ni->attr_list.size)
		return 0;

	le = NULL;

	while ((le = al_enumerate(ni, le))) {
		CLST rno = ino_get(&le->ref);

		if (rno == ni->mi.rno)
			continue;

		err = ni_load_mi_ex(ni, rno, NULL);
		if (err)
			return err;
	}

	return 0;
}

/*
<<<<<<< HEAD
 * ni_add_subrecord
 *
 * allocate + format + attach a new subrecord
 */
bool ni_add_subrecord(ntfs_inode *ni, CLST rno, mft_inode **mi)
{
	mft_inode *m;

	m = ntfs_alloc(sizeof(mft_inode), 1);
=======
 * ni_add_subrecord - Allocate + format + attach a new subrecord.
 */
bool ni_add_subrecord(struct ntfs_inode *ni, CLST rno, struct mft_inode **mi)
{
	struct mft_inode *m;

	m = kzalloc(sizeof(struct mft_inode), GFP_NOFS);
>>>>>>> wip
	if (!m)
		return false;

	if (mi_format_new(m, ni->mi.sbi, rno, 0, ni->mi.rno == MFT_REC_MFT)) {
		mi_put(m);
		return false;
	}

<<<<<<< HEAD
	get_mi_ref(&ni->mi, &m->mrec->parent_ref);
=======
	mi_get_ref(&ni->mi, &m->mrec->parent_ref);
>>>>>>> wip

	ni_add_mi(ni, m);
	*mi = m;
	return true;
}

/*
<<<<<<< HEAD
 * ni_remove_attr
 *
 * removes all attributes for the given type/name/id
 */
int ni_remove_attr(ntfs_inode *ni, ATTR_TYPE type, const __le16 *name,
		   size_t name_len, bool base_only, const __le16 *id)
{
	int err;
	ATTRIB *attr;
	ATTR_LIST_ENTRY *le;
	mft_inode *mi;
=======
 * ni_remove_attr - Remove all attributes for the given type/name/id.
 */
int ni_remove_attr(struct ntfs_inode *ni, enum ATTR_TYPE type,
		   const __le16 *name, size_t name_len, bool base_only,
		   const __le16 *id)
{
	int err;
	struct ATTRIB *attr;
	struct ATTR_LIST_ENTRY *le;
	struct mft_inode *mi;
>>>>>>> wip
	u32 type_in;
	int diff;

	if (base_only || type == ATTR_LIST || !ni->attr_list.size) {
		attr = mi_find_attr(&ni->mi, NULL, type, name, name_len, id);
		if (!attr)
			return -ENOENT;

<<<<<<< HEAD
		mi_remove_attr(&ni->mi, attr);
=======
		mi_remove_attr(ni, &ni->mi, attr);
>>>>>>> wip
		return 0;
	}

	type_in = le32_to_cpu(type);
	le = NULL;

	for (;;) {
		le = al_enumerate(ni, le);
		if (!le)
			return 0;

next_le2:
		diff = le32_to_cpu(le->type) - type_in;
		if (diff < 0)
			continue;

		if (diff > 0)
			return 0;

		if (le->name_len != name_len)
			continue;

		if (name_len &&
		    memcmp(le_name(le), name, name_len * sizeof(short)))
			continue;

		if (id && le->id != *id)
			continue;
		err = ni_load_mi(ni, le, &mi);
		if (err)
			return err;

		al_remove_le(ni, le);

		attr = mi_find_attr(mi, NULL, type, name, name_len, id);
		if (!attr)
			return -ENOENT;

<<<<<<< HEAD
		mi_remove_attr(mi, attr);
=======
		mi_remove_attr(ni, mi, attr);
>>>>>>> wip

		if (PtrOffset(ni->attr_list.le, le) >= ni->attr_list.size)
			return 0;
		goto next_le2;
	}
}

/*
<<<<<<< HEAD
 * ni_ins_new_attr
 *
 * inserts the attribute into record
 * Returns not full constructed attribute or NULL if not possible to create
 */
static ATTRIB *ni_ins_new_attr(ntfs_inode *ni, mft_inode *mi,
			       ATTR_LIST_ENTRY *le, ATTR_TYPE type,
			       const __le16 *name, u8 name_len, u32 asize,
			       u16 name_off, CLST svcn)
{
	int err;
	ATTRIB *attr;
	bool le_added = false;
	MFT_REF ref;

	get_mi_ref(mi, &ref);
=======
 * ni_ins_new_attr - Insert the attribute into record.
 *
 * Return: Not full constructed attribute or NULL if not possible to create.
 */
static struct ATTRIB *
ni_ins_new_attr(struct ntfs_inode *ni, struct mft_inode *mi,
		struct ATTR_LIST_ENTRY *le, enum ATTR_TYPE type,
		const __le16 *name, u8 name_len, u32 asize, u16 name_off,
		CLST svcn, struct ATTR_LIST_ENTRY **ins_le)
{
	int err;
	struct ATTRIB *attr;
	bool le_added = false;
	struct MFT_REF ref;

	mi_get_ref(mi, &ref);
>>>>>>> wip

	if (type != ATTR_LIST && !le && ni->attr_list.size) {
		err = al_add_le(ni, type, name, name_len, svcn, cpu_to_le16(-1),
				&ref, &le);
<<<<<<< HEAD
		if (err)
			return NULL;
=======
		if (err) {
			/* No memory or no space. */
			return NULL;
		}
>>>>>>> wip
		le_added = true;

		/*
		 * al_add_le -> attr_set_size (list) -> ni_expand_list
		 * which moves some attributes out of primary record
		 * this means that name may point into moved memory
<<<<<<< HEAD
		 * reinit 'name' from le
=======
		 * reinit 'name' from le.
>>>>>>> wip
		 */
		name = le->name;
	}

	attr = mi_insert_attr(mi, type, name, name_len, asize, name_off);
	if (!attr) {
		if (le_added)
			al_remove_le(ni, le);
		return NULL;
	}

<<<<<<< HEAD
	if (type == ATTR_LIST)
		goto out;
=======
	if (type == ATTR_LIST) {
		/* Attr list is not in list entry array. */
		goto out;
	}
>>>>>>> wip

	if (!le)
		goto out;

<<<<<<< HEAD
	/* Update ATTRIB Id and record reference */
=======
	/* Update ATTRIB Id and record reference. */
>>>>>>> wip
	le->id = attr->id;
	ni->attr_list.dirty = true;
	le->ref = ref;

out:
<<<<<<< HEAD

=======
	if (ins_le)
		*ins_le = le;
>>>>>>> wip
	return attr;
}

/*
<<<<<<< HEAD
 * ni_create_attr_list
 *
 * generates an attribute list for this primary record
 */
int ni_create_attr_list(ntfs_inode *ni)
{
	ntfs_sb_info *sbi = ni->mi.sbi;
	int err;
	u32 lsize;
	ATTRIB *attr;
	ATTRIB *arr_move[3];
	ATTR_LIST_ENTRY *le, *le_b[3];
	MFT_REC *rec;
	bool is_mft;
	CLST rno = 0;
	mft_inode *mi;
=======
 * ni_repack
 *
 * Random write access to sparsed or compressed file may result to
 * not optimized packed runs.
 * Here is the place to optimize it.
 */
static int ni_repack(struct ntfs_inode *ni)
{
	int err = 0;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	struct mft_inode *mi, *mi_p = NULL;
	struct ATTRIB *attr = NULL, *attr_p;
	struct ATTR_LIST_ENTRY *le = NULL, *le_p;
	CLST alloc = 0;
	u8 cluster_bits = sbi->cluster_bits;
	CLST svcn, evcn = 0, svcn_p, evcn_p, next_svcn;
	u32 roff, rs = sbi->record_size;
	struct runs_tree run;

	run_init(&run);

	while ((attr = ni_enum_attr_ex(ni, attr, &le, &mi))) {
		if (!attr->non_res)
			continue;

		svcn = le64_to_cpu(attr->nres.svcn);
		if (svcn != le64_to_cpu(le->vcn)) {
			err = -EINVAL;
			break;
		}

		if (!svcn) {
			alloc = le64_to_cpu(attr->nres.alloc_size) >>
				cluster_bits;
			mi_p = NULL;
		} else if (svcn != evcn + 1) {
			err = -EINVAL;
			break;
		}

		evcn = le64_to_cpu(attr->nres.evcn);

		if (svcn > evcn + 1) {
			err = -EINVAL;
			break;
		}

		if (!mi_p) {
			/* Do not try if not enogh free space. */
			if (le32_to_cpu(mi->mrec->used) + 8 >= rs)
				continue;

			/* Do not try if last attribute segment. */
			if (evcn + 1 == alloc)
				continue;
			run_close(&run);
		}

		roff = le16_to_cpu(attr->nres.run_off);
		err = run_unpack(&run, sbi, ni->mi.rno, svcn, evcn, svcn,
				 Add2Ptr(attr, roff),
				 le32_to_cpu(attr->size) - roff);
		if (err < 0)
			break;

		if (!mi_p) {
			mi_p = mi;
			attr_p = attr;
			svcn_p = svcn;
			evcn_p = evcn;
			le_p = le;
			err = 0;
			continue;
		}

		/*
		 * Run contains data from two records: mi_p and mi
		 * Try to pack in one.
		 */
		err = mi_pack_runs(mi_p, attr_p, &run, evcn + 1 - svcn_p);
		if (err)
			break;

		next_svcn = le64_to_cpu(attr_p->nres.evcn) + 1;

		if (next_svcn >= evcn + 1) {
			/* We can remove this attribute segment. */
			al_remove_le(ni, le);
			mi_remove_attr(NULL, mi, attr);
			le = le_p;
			continue;
		}

		attr->nres.svcn = le->vcn = cpu_to_le64(next_svcn);
		mi->dirty = true;
		ni->attr_list.dirty = true;

		if (evcn + 1 == alloc) {
			err = mi_pack_runs(mi, attr, &run,
					   evcn + 1 - next_svcn);
			if (err)
				break;
			mi_p = NULL;
		} else {
			mi_p = mi;
			attr_p = attr;
			svcn_p = next_svcn;
			evcn_p = evcn;
			le_p = le;
			run_truncate_head(&run, next_svcn);
		}
	}

	if (err) {
		ntfs_inode_warn(&ni->vfs_inode, "repack problem");
		ntfs_set_state(sbi, NTFS_DIRTY_ERROR);

		/* Pack loaded but not packed runs. */
		if (mi_p)
			mi_pack_runs(mi_p, attr_p, &run, evcn_p + 1 - svcn_p);
	}

	run_close(&run);
	return err;
}

/*
 * ni_try_remove_attr_list
 *
 * Can we remove attribute list?
 * Check the case when primary record contains enough space for all attributes.
 */
static int ni_try_remove_attr_list(struct ntfs_inode *ni)
{
	int err = 0;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	struct ATTRIB *attr, *attr_list, *attr_ins;
	struct ATTR_LIST_ENTRY *le;
	struct mft_inode *mi;
	u32 asize, free;
	struct MFT_REF ref;
	__le16 id;

	if (!ni->attr_list.dirty)
		return 0;

	err = ni_repack(ni);
	if (err)
		return err;

	attr_list = mi_find_attr(&ni->mi, NULL, ATTR_LIST, NULL, 0, NULL);
	if (!attr_list)
		return 0;

	asize = le32_to_cpu(attr_list->size);

	/* Free space in primary record without attribute list. */
	free = sbi->record_size - le32_to_cpu(ni->mi.mrec->used) + asize;
	mi_get_ref(&ni->mi, &ref);

	le = NULL;
	while ((le = al_enumerate(ni, le))) {
		if (!memcmp(&le->ref, &ref, sizeof(ref)))
			continue;

		if (le->vcn)
			return 0;

		mi = ni_find_mi(ni, ino_get(&le->ref));
		if (!mi)
			return 0;

		attr = mi_find_attr(mi, NULL, le->type, le_name(le),
				    le->name_len, &le->id);
		if (!attr)
			return 0;

		asize = le32_to_cpu(attr->size);
		if (asize > free)
			return 0;

		free -= asize;
	}

	/* It seems that attribute list can be removed from primary record. */
	mi_remove_attr(NULL, &ni->mi, attr_list);

	/*
	 * Repeat the cycle above and move all attributes to primary record.
	 * It should be success!
	 */
	le = NULL;
	while ((le = al_enumerate(ni, le))) {
		if (!memcmp(&le->ref, &ref, sizeof(ref)))
			continue;

		mi = ni_find_mi(ni, ino_get(&le->ref));

		attr = mi_find_attr(mi, NULL, le->type, le_name(le),
				    le->name_len, &le->id);
		asize = le32_to_cpu(attr->size);

		/* Insert into primary record. */
		attr_ins = mi_insert_attr(&ni->mi, le->type, le_name(le),
					  le->name_len, asize,
					  le16_to_cpu(attr->name_off));
		id = attr_ins->id;

		/* Copy all except id. */
		memcpy(attr_ins, attr, asize);
		attr_ins->id = id;

		/* Remove from original record. */
		mi_remove_attr(NULL, mi, attr);
	}

	run_deallocate(sbi, &ni->attr_list.run, true);
	run_close(&ni->attr_list.run);
	ni->attr_list.size = 0;
	kfree(ni->attr_list.le);
	ni->attr_list.le = NULL;
	ni->attr_list.dirty = false;

	return 0;
}

/*
 * ni_create_attr_list - Generates an attribute list for this primary record.
 */
int ni_create_attr_list(struct ntfs_inode *ni)
{
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	int err;
	u32 lsize;
	struct ATTRIB *attr;
	struct ATTRIB *arr_move[7];
	struct ATTR_LIST_ENTRY *le, *le_b[7];
	struct MFT_REC *rec;
	bool is_mft;
	CLST rno = 0;
	struct mft_inode *mi;
>>>>>>> wip
	u32 free_b, nb, to_free, rs;
	u16 sz;

	is_mft = ni->mi.rno == MFT_REC_MFT;
	rec = ni->mi.mrec;
	rs = sbi->record_size;

	/*
<<<<<<< HEAD
	 * Skip estimating exact memory requirement
	 * Looks like one record_size is always enough
	 */
	le = ntfs_alloc(al_aligned(rs), 0);
=======
	 * Skip estimating exact memory requirement.
	 * Looks like one record_size is always enough.
	 */
	le = kmalloc(al_aligned(rs), GFP_NOFS);
>>>>>>> wip
	if (!le) {
		err = -ENOMEM;
		goto out;
	}

<<<<<<< HEAD
	get_mi_ref(&ni->mi, &le->ref);
=======
	mi_get_ref(&ni->mi, &le->ref);
>>>>>>> wip
	ni->attr_list.le = le;

	attr = NULL;
	nb = 0;
	free_b = 0;
	attr = NULL;

	for (; (attr = mi_enum_attr(&ni->mi, attr)); le = Add2Ptr(le, sz)) {
		sz = le_size(attr->name_len);
<<<<<<< HEAD
		WARN_ON(PtrOffset(ni->attr_list.le, le) + sz > rs);

		le->type = attr->type;
		le->size = cpu_to_le16(sz);
		le->name_len = attr->name_len;
		le->name_off = offsetof(ATTR_LIST_ENTRY, name);
		le->vcn = 0;
		if (le != ni->attr_list.le)
			le->ref = ((ATTR_LIST_ENTRY *)ni->attr_list.le)->ref;
=======
		le->type = attr->type;
		le->size = cpu_to_le16(sz);
		le->name_len = attr->name_len;
		le->name_off = offsetof(struct ATTR_LIST_ENTRY, name);
		le->vcn = 0;
		if (le != ni->attr_list.le)
			le->ref = ni->attr_list.le->ref;
>>>>>>> wip
		le->id = attr->id;

		if (attr->name_len)
			memcpy(le->name, attr_name(attr),
			       sizeof(short) * attr->name_len);
		else if (attr->type == ATTR_STD)
			continue;
		else if (attr->type == ATTR_LIST)
			continue;
		else if (is_mft && attr->type == ATTR_DATA)
			continue;

		if (!nb || nb < ARRAY_SIZE(arr_move)) {
			le_b[nb] = le;
			arr_move[nb++] = attr;
			free_b += le32_to_cpu(attr->size);
		}
	}

	lsize = PtrOffset(ni->attr_list.le, le);
	ni->attr_list.size = lsize;

	to_free = le32_to_cpu(rec->used) + lsize + SIZEOF_RESIDENT;
<<<<<<< HEAD
	if (to_free <= rs)
		to_free = 0;
	else {
=======
	if (to_free <= rs) {
		to_free = 0;
	} else {
>>>>>>> wip
		to_free -= rs;

		if (to_free > free_b) {
			err = -EINVAL;
			goto out1;
		}
	}

<<<<<<< HEAD
	/* Allocate child mft. */
=======
	/* Allocate child MFT. */
>>>>>>> wip
	err = ntfs_look_free_mft(sbi, &rno, is_mft, ni, &mi);
	if (err)
		goto out1;

<<<<<<< HEAD
	/* Call 'mi_remove_attr' in reverse order to keep pointers 'arr_move' valid */
	while (to_free > 0) {
		ATTRIB *b = arr_move[--nb];
=======
	/* Call mi_remove_attr() in reverse order to keep pointers 'arr_move' valid. */
	while (to_free > 0) {
		struct ATTRIB *b = arr_move[--nb];
>>>>>>> wip
		u32 asize = le32_to_cpu(b->size);
		u16 name_off = le16_to_cpu(b->name_off);

		attr = mi_insert_attr(mi, b->type, Add2Ptr(b, name_off),
				      b->name_len, asize, name_off);
		WARN_ON(!attr);

<<<<<<< HEAD
		get_mi_ref(mi, &le_b[nb]->ref);
		le_b[nb]->id = attr->id;

		/* copy all except id */
		memcpy(attr, b, asize);
		attr->id = le_b[nb]->id;

		WARN_ON(!mi_remove_attr(&ni->mi, b));
=======
		mi_get_ref(mi, &le_b[nb]->ref);
		le_b[nb]->id = attr->id;

		/* Copy all except id. */
		memcpy(attr, b, asize);
		attr->id = le_b[nb]->id;

		/* Remove from primary record. */
		WARN_ON(!mi_remove_attr(NULL, &ni->mi, b));
>>>>>>> wip

		if (to_free <= asize)
			break;
		to_free -= asize;
		WARN_ON(!nb);
	}

	attr = mi_insert_attr(&ni->mi, ATTR_LIST, NULL, 0,
			      lsize + SIZEOF_RESIDENT, SIZEOF_RESIDENT);
	WARN_ON(!attr);

	attr->non_res = 0;
	attr->flags = 0;
	attr->res.data_size = cpu_to_le32(lsize);
	attr->res.data_off = SIZEOF_RESIDENT_LE;
	attr->res.flags = 0;
	attr->res.res = 0;

	memcpy(resident_data_ex(attr, lsize), ni->attr_list.le, lsize);

	ni->attr_list.dirty = false;

	mark_inode_dirty(&ni->vfs_inode);
	goto out;

out1:
<<<<<<< HEAD
	ntfs_free(ni->attr_list.le);
=======
	kfree(ni->attr_list.le);
>>>>>>> wip
	ni->attr_list.le = NULL;
	ni->attr_list.size = 0;

out:
	return err;
}

/*
<<<<<<< HEAD
 * ni_ins_attr_ext
 *
 * This method adds an external attribute to the ntfs_inode.
 */
static int ni_ins_attr_ext(ntfs_inode *ni, ATTR_LIST_ENTRY *le, ATTR_TYPE type,
			   const __le16 *name, u8 name_len, u32 asize,
			   CLST svcn, u16 name_off, bool force_ext,
			   ATTRIB **ins_attr, mft_inode **ins_mi)
{
	ATTRIB *attr;
	mft_inode *mi;
	MFT_REC *rec;
=======
 * ni_ins_attr_ext - Add an external attribute to the ntfs_inode.
 */
static int ni_ins_attr_ext(struct ntfs_inode *ni, struct ATTR_LIST_ENTRY *le,
			   enum ATTR_TYPE type, const __le16 *name, u8 name_len,
			   u32 asize, CLST svcn, u16 name_off, bool force_ext,
			   struct ATTRIB **ins_attr, struct mft_inode **ins_mi,
			   struct ATTR_LIST_ENTRY **ins_le)
{
	struct ATTRIB *attr;
	struct mft_inode *mi;
>>>>>>> wip
	CLST rno;
	u64 vbo;
	struct rb_node *node;
	int err;
	bool is_mft, is_mft_data;
<<<<<<< HEAD
	ntfs_sb_info *sbi = ni->mi.sbi;

	rec = ni->mi.mrec;
=======
	struct ntfs_sb_info *sbi = ni->mi.sbi;

>>>>>>> wip
	is_mft = ni->mi.rno == MFT_REC_MFT;
	is_mft_data = is_mft && type == ATTR_DATA && !name_len;

	if (asize > sbi->max_bytes_per_attr) {
		err = -EINVAL;
		goto out;
	}

	/*
<<<<<<< HEAD
	 * standard information and attr_list cannot be made external.
	 * The Log File cannot have any external attributes
=======
	 * Standard information and attr_list cannot be made external.
	 * The Log File cannot have any external attributes.
>>>>>>> wip
	 */
	if (type == ATTR_STD || type == ATTR_LIST ||
	    ni->mi.rno == MFT_REC_LOG) {
		err = -EINVAL;
		goto out;
	}

<<<<<<< HEAD
	/* Create attribute list if it is not already existed */
=======
	/* Create attribute list if it is not already existed. */
>>>>>>> wip
	if (!ni->attr_list.size) {
		err = ni_create_attr_list(ni);
		if (err)
			goto out;
	}

<<<<<<< HEAD
	vbo = is_mft_data ? (svcn << sbi->cluster_bits) : 0;
=======
	vbo = is_mft_data ? ((u64)svcn << sbi->cluster_bits) : 0;
>>>>>>> wip

	if (force_ext)
		goto insert_ext;

	/* Load all subrecords into memory. */
	err = ni_load_all_mi(ni);
	if (err)
		goto out;

<<<<<<< HEAD
	/* Check each of loaded subrecord */
	for (node = rb_first(&ni->mi_tree); node; node = rb_next(node)) {
		mi = rb_entry(node, mft_inode, node);
=======
	/* Check each of loaded subrecord. */
	for (node = rb_first(&ni->mi_tree); node; node = rb_next(node)) {
		mi = rb_entry(node, struct mft_inode, node);
>>>>>>> wip

		if (is_mft_data &&
		    (mi_enum_attr(mi, NULL) ||
		     vbo <= ((u64)mi->rno << sbi->record_bits))) {
<<<<<<< HEAD
			/* We can't accept this record 'case MFT's bootstrapping */
=======
			/* We can't accept this record 'cause MFT's bootstrapping. */
>>>>>>> wip
			continue;
		}
		if (is_mft &&
		    mi_find_attr(mi, NULL, ATTR_DATA, NULL, 0, NULL)) {
			/*
			 * This child record already has a ATTR_DATA.
			 * So it can't accept any other records.
			 */
			continue;
		}

		if ((type != ATTR_NAME || name_len) &&
		    mi_find_attr(mi, NULL, type, name, name_len, NULL)) {
<<<<<<< HEAD
			/* Only indexed attributes can share same record */
			continue;
		}

		/* Try to insert attribute into this subrecord */
		attr = ni_ins_new_attr(ni, mi, le, type, name, name_len, asize,
				       name_off, svcn);
=======
			/* Only indexed attributes can share same record. */
			continue;
		}

		/* Try to insert attribute into this subrecord. */
		attr = ni_ins_new_attr(ni, mi, le, type, name, name_len, asize,
				       name_off, svcn, ins_le);
>>>>>>> wip
		if (!attr)
			continue;

		if (ins_attr)
			*ins_attr = attr;
<<<<<<< HEAD
=======
		if (ins_mi)
			*ins_mi = mi;
>>>>>>> wip
		return 0;
	}

insert_ext:
<<<<<<< HEAD
	/* We have to allocate a new child subrecord*/
=======
	/* We have to allocate a new child subrecord. */
>>>>>>> wip
	err = ntfs_look_free_mft(sbi, &rno, is_mft_data, ni, &mi);
	if (err)
		goto out;

	if (is_mft_data && vbo <= ((u64)rno << sbi->record_bits)) {
		err = -EINVAL;
		goto out1;
	}

	attr = ni_ins_new_attr(ni, mi, le, type, name, name_len, asize,
<<<<<<< HEAD
			       name_off, svcn);
=======
			       name_off, svcn, ins_le);
>>>>>>> wip
	if (!attr)
		goto out2;

	if (ins_attr)
		*ins_attr = attr;
	if (ins_mi)
		*ins_mi = mi;

	return 0;

out2:
	ni_remove_mi(ni, mi);
	mi_put(mi);
	err = -EINVAL;

out1:
	ntfs_mark_rec_free(sbi, rno);

out:
	return err;
}

/*
<<<<<<< HEAD
 * ni_insert_attr
 *
 * inserts an attribute into the file.
=======
 * ni_insert_attr - Insert an attribute into the file.
>>>>>>> wip
 *
 * If the primary record has room, it will just insert the attribute.
 * If not, it may make the attribute external.
 * For $MFT::Data it may make room for the attribute by
 * making other attributes external.
 *
 * NOTE:
 * The ATTR_LIST and ATTR_STD cannot be made external.
<<<<<<< HEAD
 * This function does not fill new attribute full
 * It only fills 'size'/'type'/'id'/'name_len' fields
 */
static int ni_insert_attr(ntfs_inode *ni, ATTR_TYPE type, const __le16 *name,
			  u8 name_len, u32 asize, u16 name_off, CLST svcn,
			  ATTRIB **ins_attr, mft_inode **ins_mi)
{
	ntfs_sb_info *sbi = ni->mi.sbi;
	int err;
	ATTRIB *attr, *eattr;
	MFT_REC *rec;
	bool is_mft;
	ATTR_LIST_ENTRY *le;
=======
 * This function does not fill new attribute full.
 * It only fills 'size'/'type'/'id'/'name_len' fields.
 */
static int ni_insert_attr(struct ntfs_inode *ni, enum ATTR_TYPE type,
			  const __le16 *name, u8 name_len, u32 asize,
			  u16 name_off, CLST svcn, struct ATTRIB **ins_attr,
			  struct mft_inode **ins_mi,
			  struct ATTR_LIST_ENTRY **ins_le)
{
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	int err;
	struct ATTRIB *attr, *eattr;
	struct MFT_REC *rec;
	bool is_mft;
	struct ATTR_LIST_ENTRY *le;
>>>>>>> wip
	u32 list_reserve, max_free, free, used, t32;
	__le16 id;
	u16 t16;

	is_mft = ni->mi.rno == MFT_REC_MFT;
	rec = ni->mi.mrec;

	list_reserve = SIZEOF_NONRESIDENT + 3 * (1 + 2 * sizeof(u32));
	used = le32_to_cpu(rec->used);
	free = sbi->record_size - used;

	if (is_mft && type != ATTR_LIST) {
<<<<<<< HEAD
		/* Reserve space for the ATTRIB List. */
=======
		/* Reserve space for the ATTRIB list. */
>>>>>>> wip
		if (free < list_reserve)
			free = 0;
		else
			free -= list_reserve;
	}

<<<<<<< HEAD
	if (asize > free)
		goto insert_ext;

	attr = ni_ins_new_attr(ni, &ni->mi, NULL, type, name, name_len, asize,
			       name_off, svcn);
	if (attr) {
		if (ins_attr)
			*ins_attr = attr;
		if (ins_mi)
			*ins_mi = &ni->mi;
		err = 0;
		goto out;
	}

insert_ext:
	if (!is_mft || type != ATTR_DATA || svcn) {
		/* This ATTRIB will be external. */
		err = ni_ins_attr_ext(ni, NULL, type, name, name_len, asize,
				      svcn, name_off, false, ins_attr, ins_mi);
=======
	if (asize <= free) {
		attr = ni_ins_new_attr(ni, &ni->mi, NULL, type, name, name_len,
				       asize, name_off, svcn, ins_le);
		if (attr) {
			if (ins_attr)
				*ins_attr = attr;
			if (ins_mi)
				*ins_mi = &ni->mi;
			err = 0;
			goto out;
		}
	}

	if (!is_mft || type != ATTR_DATA || svcn) {
		/* This ATTRIB will be external. */
		err = ni_ins_attr_ext(ni, NULL, type, name, name_len, asize,
				      svcn, name_off, false, ins_attr, ins_mi,
				      ins_le);
>>>>>>> wip
		goto out;
	}

	/*
<<<<<<< HEAD
	 * Here we have: "is_mft && type == ATTR_DATA && !svcn
=======
	 * Here we have: "is_mft && type == ATTR_DATA && !svcn"
>>>>>>> wip
	 *
	 * The first chunk of the $MFT::Data ATTRIB must be the base record.
	 * Evict as many other attributes as possible.
	 */
	max_free = free;

<<<<<<< HEAD
	/* Estimate the result of moving all possible attributes away.*/
=======
	/* Estimate the result of moving all possible attributes away. */
>>>>>>> wip
	attr = NULL;

	while ((attr = mi_enum_attr(&ni->mi, attr))) {
		if (attr->type == ATTR_STD)
			continue;
		if (attr->type == ATTR_LIST)
			continue;
		max_free += le32_to_cpu(attr->size);
	}

	if (max_free < asize + list_reserve) {
<<<<<<< HEAD
		/* Impossible to insert this attribute into primary record */
=======
		/* Impossible to insert this attribute into primary record. */
>>>>>>> wip
		err = -EINVAL;
		goto out;
	}

<<<<<<< HEAD
	/* Start real attribute moving */
	attr = NULL;
next_move:

	attr = mi_enum_attr(&ni->mi, attr);
	if (!attr) {
		/* We should never be here 'cause we have already check this case */
		err = -EINVAL;
		goto out;
	}

	/* Skip attributes that MUST be primary record */
	if (attr->type == ATTR_STD)
		goto next_move;
	if (attr->type == ATTR_LIST)
		goto next_move;

	le = NULL;
	if (ni->attr_list.size) {
		le = al_find_le(ni, NULL, attr);
		if (!le) {
			/* Really this is a serious bug */
			err = -EINVAL;
			goto out;
		}
	}

	t32 = le32_to_cpu(attr->size);
	t16 = le16_to_cpu(attr->name_off);
	err = ni_ins_attr_ext(ni, le, attr->type, Add2Ptr(attr, t16),
			      attr->name_len, t32, attr_svcn(attr), t16, false,
			      &eattr, NULL);
	if (err)
		return err;

	id = eattr->id;
	memcpy(eattr, attr, t32);
	eattr->id = id;

	/* remove attrib from primary record */
	mi_remove_attr(&ni->mi, attr);

	/* attr now points to next attribute */
	if (attr->type == ATTR_END)
		goto out;

	/* Try to insert when the free space is enough */
	if (asize + list_reserve > sbi->record_size - le32_to_cpu(rec->used))
		goto next_move;

	attr = ni_ins_new_attr(ni, &ni->mi, NULL, type, name, name_len, asize,
			       name_off, svcn);
=======
	/* Start real attribute moving. */
	attr = NULL;

	for (;;) {
		attr = mi_enum_attr(&ni->mi, attr);
		if (!attr) {
			/* We should never be here 'cause we have already check this case. */
			err = -EINVAL;
			goto out;
		}

		/* Skip attributes that MUST be primary record. */
		if (attr->type == ATTR_STD || attr->type == ATTR_LIST)
			continue;

		le = NULL;
		if (ni->attr_list.size) {
			le = al_find_le(ni, NULL, attr);
			if (!le) {
				/* Really this is a serious bug. */
				err = -EINVAL;
				goto out;
			}
		}

		t32 = le32_to_cpu(attr->size);
		t16 = le16_to_cpu(attr->name_off);
		err = ni_ins_attr_ext(ni, le, attr->type, Add2Ptr(attr, t16),
				      attr->name_len, t32, attr_svcn(attr), t16,
				      false, &eattr, NULL, NULL);
		if (err)
			return err;

		id = eattr->id;
		memcpy(eattr, attr, t32);
		eattr->id = id;

		/* Remove from primary record. */
		mi_remove_attr(NULL, &ni->mi, attr);

		/* attr now points to next attribute. */
		if (attr->type == ATTR_END)
			goto out;
	}
	while (asize + list_reserve > sbi->record_size - le32_to_cpu(rec->used))
		;

	attr = ni_ins_new_attr(ni, &ni->mi, NULL, type, name, name_len, asize,
			       name_off, svcn, ins_le);
>>>>>>> wip
	if (!attr) {
		err = -EINVAL;
		goto out;
	}

	if (ins_attr)
		*ins_attr = attr;
	if (ins_mi)
		*ins_mi = &ni->mi;

out:
	return err;
}

<<<<<<< HEAD
/*
 * ni_expand_mft_list
 *
 * This method splits ATTR_DATA of $MFT
 */
static int ni_expand_mft_list(ntfs_inode *ni)
=======
/* ni_expand_mft_list - Split ATTR_DATA of $MFT. */
static int ni_expand_mft_list(struct ntfs_inode *ni)
>>>>>>> wip
{
	int err = 0;
	struct runs_tree *run = &ni->file.run;
	u32 asize, run_size, done = 0;
<<<<<<< HEAD
	ATTRIB *attr;
	struct rb_node *node;
	CLST mft_min, mft_new, svcn, evcn, plen;
	mft_inode *mi, *mi_min, *mi_new;
	ntfs_sb_info *sbi = ni->mi.sbi;

	/* Find the nearest Mft */
=======
	struct ATTRIB *attr;
	struct rb_node *node;
	CLST mft_min, mft_new, svcn, evcn, plen;
	struct mft_inode *mi, *mi_min, *mi_new;
	struct ntfs_sb_info *sbi = ni->mi.sbi;

	/* Find the nearest MFT. */
>>>>>>> wip
	mft_min = 0;
	mft_new = 0;
	mi_min = NULL;

	for (node = rb_first(&ni->mi_tree); node; node = rb_next(node)) {
<<<<<<< HEAD
		mi = rb_entry(node, mft_inode, node);
=======
		mi = rb_entry(node, struct mft_inode, node);
>>>>>>> wip

		attr = mi_enum_attr(mi, NULL);

		if (!attr) {
			mft_min = mi->rno;
			mi_min = mi;
			break;
		}
	}

	if (ntfs_look_free_mft(sbi, &mft_new, true, ni, &mi_new)) {
		mft_new = 0;
<<<<<<< HEAD
		// really this is not critical
=======
		/* Really this is not critical. */
>>>>>>> wip
	} else if (mft_min > mft_new) {
		mft_min = mft_new;
		mi_min = mi_new;
	} else {
		ntfs_mark_rec_free(sbi, mft_new);
		mft_new = 0;
		ni_remove_mi(ni, mi_new);
	}

	attr = mi_find_attr(&ni->mi, NULL, ATTR_DATA, NULL, 0, NULL);
	if (!attr) {
		err = -EINVAL;
		goto out;
	}

	asize = le32_to_cpu(attr->size);

	evcn = le64_to_cpu(attr->nres.evcn);
	svcn = bytes_to_cluster(sbi, (u64)(mft_min + 1) << sbi->record_bits);
	if (evcn + 1 >= svcn) {
		err = -EINVAL;
		goto out;
	}

	/*
<<<<<<< HEAD
	 * split primary attribute [0 evcn] in two parts [0 svcn) + [svcn evcn]
	 *
	 * Update first part of ATTR_DATA in 'primary MFT
=======
	 * Split primary attribute [0 evcn] in two parts [0 svcn) + [svcn evcn].
	 *
	 * Update first part of ATTR_DATA in 'primary MFT.
>>>>>>> wip
	 */
	err = run_pack(run, 0, svcn, Add2Ptr(attr, SIZEOF_NONRESIDENT),
		       asize - SIZEOF_NONRESIDENT, &plen);
	if (err < 0)
		goto out;

<<<<<<< HEAD
	run_size = QuadAlign(err);
=======
	run_size = ALIGN(err, 8);
>>>>>>> wip
	err = 0;

	if (plen < svcn) {
		err = -EINVAL;
		goto out;
	}

	attr->nres.evcn = cpu_to_le64(svcn - 1);
	attr->size = cpu_to_le32(run_size + SIZEOF_NONRESIDENT);
<<<<<<< HEAD
	/* 'done' - how many bytes of primary MFT becomes free */
	done = asize - run_size - SIZEOF_NONRESIDENT;
	le32_sub_cpu(&ni->mi.mrec->used, done);

	/* Estimate the size of second part: run_buf=NULL */
=======
	/* 'done' - How many bytes of primary MFT becomes free. */
	done = asize - run_size - SIZEOF_NONRESIDENT;
	le32_sub_cpu(&ni->mi.mrec->used, done);

	/* Estimate the size of second part: run_buf=NULL. */
>>>>>>> wip
	err = run_pack(run, svcn, evcn + 1 - svcn, NULL, sbi->record_size,
		       &plen);
	if (err < 0)
		goto out;

<<<<<<< HEAD
	run_size = QuadAlign(err);
=======
	run_size = ALIGN(err, 8);
>>>>>>> wip
	err = 0;

	if (plen < evcn + 1 - svcn) {
		err = -EINVAL;
		goto out;
	}

	/*
<<<<<<< HEAD
	 * This function may implicitly call expand attr_list
	 * Insert second part of ATTR_DATA in 'mi_min'
	 */
	attr = ni_ins_new_attr(ni, mi_min, NULL, ATTR_DATA, NULL, 0,
			       SIZEOF_NONRESIDENT + run_size,
			       SIZEOF_NONRESIDENT, svcn);
=======
	 * This function may implicitly call expand attr_list.
	 * Insert second part of ATTR_DATA in 'mi_min'.
	 */
	attr = ni_ins_new_attr(ni, mi_min, NULL, ATTR_DATA, NULL, 0,
			       SIZEOF_NONRESIDENT + run_size,
			       SIZEOF_NONRESIDENT, svcn, NULL);
>>>>>>> wip
	if (!attr) {
		err = -EINVAL;
		goto out;
	}

	attr->non_res = 1;
	attr->name_off = SIZEOF_NONRESIDENT_LE;
	attr->flags = 0;

	run_pack(run, svcn, evcn + 1 - svcn, Add2Ptr(attr, SIZEOF_NONRESIDENT),
		 run_size, &plen);

	attr->nres.svcn = cpu_to_le64(svcn);
	attr->nres.evcn = cpu_to_le64(evcn);
	attr->nres.run_off = cpu_to_le16(SIZEOF_NONRESIDENT);

out:
	if (mft_new) {
		ntfs_mark_rec_free(sbi, mft_new);
		ni_remove_mi(ni, mi_new);
	}

	return !err && !done ? -EOPNOTSUPP : err;
}

/*
<<<<<<< HEAD
 * ni_expand_list
 *
 * This method moves all possible attributes out of primary record
 */
int ni_expand_list(ntfs_inode *ni)
{
	int err = 0;
	u32 asize, done = 0;
	ATTRIB *attr, *ins_attr;
	ATTR_LIST_ENTRY *le;
	bool is_mft;
	MFT_REF ref;

	is_mft = ni->mi.rno == MFT_REC_MFT;

	get_mi_ref(&ni->mi, &ref);
=======
 * ni_expand_list - Move all possible attributes out of primary record.
 */
int ni_expand_list(struct ntfs_inode *ni)
{
	int err = 0;
	u32 asize, done = 0;
	struct ATTRIB *attr, *ins_attr;
	struct ATTR_LIST_ENTRY *le;
	bool is_mft = ni->mi.rno == MFT_REC_MFT;
	struct MFT_REF ref;

	mi_get_ref(&ni->mi, &ref);
>>>>>>> wip
	le = NULL;

	while ((le = al_enumerate(ni, le))) {
		if (le->type == ATTR_STD)
			continue;

<<<<<<< HEAD
		if (memcmp(&ref, &le->ref, sizeof(MFT_REF)))
=======
		if (memcmp(&ref, &le->ref, sizeof(struct MFT_REF)))
>>>>>>> wip
			continue;

		if (is_mft && le->type == ATTR_DATA)
			continue;

<<<<<<< HEAD
		/* Find attribute in primary record */
=======
		/* Find attribute in primary record. */
>>>>>>> wip
		attr = rec_find_attr_le(&ni->mi, le);
		if (!attr) {
			err = -EINVAL;
			goto out;
		}

		asize = le32_to_cpu(attr->size);

<<<<<<< HEAD
		/* Always insert into new record to avoid collisions (deep recursive) */
		err = ni_ins_attr_ext(ni, le, attr->type, attr_name(attr),
				      attr->name_len, asize, attr_svcn(attr),
				      le16_to_cpu(attr->name_off), true,
				      &ins_attr, NULL);
=======
		/* Always insert into new record to avoid collisions (deep recursive). */
		err = ni_ins_attr_ext(ni, le, attr->type, attr_name(attr),
				      attr->name_len, asize, attr_svcn(attr),
				      le16_to_cpu(attr->name_off), true,
				      &ins_attr, NULL, NULL);
>>>>>>> wip

		if (err)
			goto out;

		memcpy(ins_attr, attr, asize);
		ins_attr->id = le->id;
<<<<<<< HEAD
		mi_remove_attr(&ni->mi, attr);
=======
		/* Remove from primary record. */
		mi_remove_attr(NULL, &ni->mi, attr);
>>>>>>> wip

		done += asize;
		goto out;
	}

	if (!is_mft) {
<<<<<<< HEAD
		err = -EFBIG; /* attr list is too big(?) */
		goto out;
	}

	/* split mft data as much as possible */
=======
		err = -EFBIG; /* Attr list is too big(?) */
		goto out;
	}

	/* Split MFT data as much as possible. */
>>>>>>> wip
	err = ni_expand_mft_list(ni);
	if (err)
		goto out;

out:
	return !err && !done ? -EOPNOTSUPP : err;
}

/*
<<<<<<< HEAD
 * ni_insert_nonresident
 *
 * inserts new nonresident attribute
 */
int ni_insert_nonresident(ntfs_inode *ni, ATTR_TYPE type, const __le16 *name,
			  u8 name_len, const struct runs_tree *run, CLST svcn,
			  CLST len, __le16 flags, ATTRIB **new_attr,
			  mft_inode **mi)
{
	int err;
	CLST plen;
	ATTRIB *attr;
	bool is_ext =
		(flags & (ATTR_FLAG_SPARSED | ATTR_FLAG_COMPRESSED)) && !svcn;
	u32 name_size = QuadAlign(name_len * sizeof(short));
	u32 name_off = is_ext ? SIZEOF_NONRESIDENT_EX : SIZEOF_NONRESIDENT;
	u32 run_off = name_off + name_size;
	u32 run_size, asize;
	ntfs_sb_info *sbi = ni->mi.sbi;
=======
 * ni_insert_nonresident - Insert new nonresident attribute.
 */
int ni_insert_nonresident(struct ntfs_inode *ni, enum ATTR_TYPE type,
			  const __le16 *name, u8 name_len,
			  const struct runs_tree *run, CLST svcn, CLST len,
			  __le16 flags, struct ATTRIB **new_attr,
			  struct mft_inode **mi)
{
	int err;
	CLST plen;
	struct ATTRIB *attr;
	bool is_ext =
		(flags & (ATTR_FLAG_SPARSED | ATTR_FLAG_COMPRESSED)) && !svcn;
	u32 name_size = ALIGN(name_len * sizeof(short), 8);
	u32 name_off = is_ext ? SIZEOF_NONRESIDENT_EX : SIZEOF_NONRESIDENT;
	u32 run_off = name_off + name_size;
	u32 run_size, asize;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
>>>>>>> wip

	err = run_pack(run, svcn, len, NULL, sbi->max_bytes_per_attr - run_off,
		       &plen);
	if (err < 0)
		goto out;

<<<<<<< HEAD
	run_size = QuadAlign(err);
=======
	run_size = ALIGN(err, 8);
>>>>>>> wip

	if (plen < len) {
		err = -EINVAL;
		goto out;
	}

	asize = run_off + run_size;

	if (asize > sbi->max_bytes_per_attr) {
		err = -EINVAL;
		goto out;
	}

	err = ni_insert_attr(ni, type, name, name_len, asize, name_off, svcn,
<<<<<<< HEAD
			     &attr, mi);
=======
			     &attr, mi, NULL);
>>>>>>> wip

	if (err)
		goto out;

	attr->non_res = 1;
	attr->name_off = cpu_to_le16(name_off);
	attr->flags = flags;

	run_pack(run, svcn, len, Add2Ptr(attr, run_off), run_size, &plen);

	attr->nres.svcn = cpu_to_le64(svcn);
	attr->nres.evcn = cpu_to_le64((u64)svcn + len - 1);

	err = 0;
	if (new_attr)
		*new_attr = attr;

	*(__le64 *)&attr->nres.run_off = cpu_to_le64(run_off);

	attr->nres.alloc_size =
		svcn ? 0 : cpu_to_le64((u64)len << ni->mi.sbi->cluster_bits);
	attr->nres.data_size = attr->nres.alloc_size;
	attr->nres.valid_size = attr->nres.alloc_size;

	if (is_ext) {
		if (flags & ATTR_FLAG_COMPRESSED)
			attr->nres.c_unit = COMPRESSION_UNIT;
		attr->nres.total_size = attr->nres.alloc_size;
	}

out:
	return err;
}

/*
<<<<<<< HEAD
 * ni_insert_resident
 *
 * inserts new resident attribute
 */
int ni_insert_resident(ntfs_inode *ni, u32 data_size, ATTR_TYPE type,
		       const __le16 *name, u8 name_len, ATTRIB **new_attr,
		       mft_inode **mi)
{
	int err;
	u32 name_size = QuadAlign(name_len * sizeof(short));
	u32 asize = SIZEOF_RESIDENT + name_size + QuadAlign(data_size);
	ATTRIB *attr;

	err = ni_insert_attr(ni, type, name, name_len, asize, SIZEOF_RESIDENT,
			     0, &attr, mi);
=======
 * ni_insert_resident - Inserts new resident attribute.
 */
int ni_insert_resident(struct ntfs_inode *ni, u32 data_size,
		       enum ATTR_TYPE type, const __le16 *name, u8 name_len,
		       struct ATTRIB **new_attr, struct mft_inode **mi,
		       struct ATTR_LIST_ENTRY **le)
{
	int err;
	u32 name_size = ALIGN(name_len * sizeof(short), 8);
	u32 asize = SIZEOF_RESIDENT + name_size + ALIGN(data_size, 8);
	struct ATTRIB *attr;

	err = ni_insert_attr(ni, type, name, name_len, asize, SIZEOF_RESIDENT,
			     0, &attr, mi, le);
>>>>>>> wip
	if (err)
		return err;

	attr->non_res = 0;
	attr->flags = 0;

	attr->res.data_size = cpu_to_le32(data_size);
	attr->res.data_off = cpu_to_le16(SIZEOF_RESIDENT + name_size);
<<<<<<< HEAD
	if (type == ATTR_NAME)
		attr->res.flags = RESIDENT_FLAG_INDEXED;
=======
	if (type == ATTR_NAME) {
		attr->res.flags = RESIDENT_FLAG_INDEXED;

		/* is_attr_indexed(attr)) == true */
		le16_add_cpu(&ni->mi.mrec->hard_links, +1);
		ni->mi.dirty = true;
	}
>>>>>>> wip
	attr->res.res = 0;

	if (new_attr)
		*new_attr = attr;
<<<<<<< HEAD
=======

>>>>>>> wip
	return 0;
}

/*
<<<<<<< HEAD
 * ni_remove_attr_le
 *
 * removes attribute from record
 */
int ni_remove_attr_le(ntfs_inode *ni, ATTRIB *attr, ATTR_LIST_ENTRY *le)
{
	int err;
	mft_inode *mi;

	err = ni_load_mi(ni, le, &mi);
	if (err)
		return err;

	mi_remove_attr(mi, attr);

	if (le)
		al_remove_le(ni, le);

	return 0;
}

/*
 * ni_delete_all
 *
 * removes all attributes and frees allocates space
 * ntfs_evict_inode->ntfs_clear_inode->ni_delete_all (if no links)
 */
int ni_delete_all(ntfs_inode *ni)
{
	int err;
	ATTR_LIST_ENTRY *le = NULL;
	ATTRIB *attr = NULL;
=======
 * ni_remove_attr_le - Remove attribute from record.
 */
void ni_remove_attr_le(struct ntfs_inode *ni, struct ATTRIB *attr,
		       struct mft_inode *mi, struct ATTR_LIST_ENTRY *le)
{
	mi_remove_attr(ni, mi, attr);

	if (le)
		al_remove_le(ni, le);
}

/*
 * ni_delete_all - Remove all attributes and frees allocates space.
 *
 * ntfs_evict_inode->ntfs_clear_inode->ni_delete_all (if no links).
 */
int ni_delete_all(struct ntfs_inode *ni)
{
	int err;
	struct ATTR_LIST_ENTRY *le = NULL;
	struct ATTRIB *attr = NULL;
>>>>>>> wip
	struct rb_node *node;
	u16 roff;
	u32 asize;
	CLST svcn, evcn;
<<<<<<< HEAD
	ntfs_sb_info *sbi = ni->mi.sbi;
	bool nt5 = is_nt5(sbi);
	MFT_REF ref;

next_attr:
	attr = ni_enum_attr_ex(ni, attr, &le);
	if (!attr)
		goto attr_list;

	if (!nt5 || attr->name_len)
		;
	else if (attr->type == ATTR_REPARSE) {
		get_mi_ref(&ni->mi, &ref);
		err = ntfs_remove_reparse(sbi, 0, &ref);
	} else if (attr->type == ATTR_ID) {
		if (!attr->non_res &&
		    le32_to_cpu(attr->res.data_size) >= sizeof(GUID))
			err = ntfs_objid_remove(sbi, resident_data(attr));
	}

	if (!attr->non_res)
		goto next_attr;

	svcn = le64_to_cpu(attr->nres.svcn);
	evcn = le64_to_cpu(attr->nres.evcn);

	if (evcn + 1 <= svcn)
		goto next_attr;

	asize = le32_to_cpu(attr->size);
	roff = le16_to_cpu(attr->nres.run_off);

	err = run_unpack_ex((struct runs_tree *)(size_t)1, sbi, ni->mi.rno,
			    svcn, evcn, Add2Ptr(attr, roff), asize - roff);
	if (err < 0)
		goto next_attr;
	err = 0;

	goto next_attr;

attr_list:
	if (!ni->attr_list.size)
		goto free_subrecord;

	run_deallocate(ni->mi.sbi, &ni->attr_list.run, true);
	al_destroy(ni);

free_subrecord:
	/* Free all subrecords */
	for (node = rb_first(&ni->mi_tree); node;) {
		struct rb_node *next = rb_next(node);
		mft_inode *mi = rb_entry(node, mft_inode, node);
=======
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	bool nt3 = is_ntfs3(sbi);
	struct MFT_REF ref;

	while ((attr = ni_enum_attr_ex(ni, attr, &le, NULL))) {
		if (!nt3 || attr->name_len) {
			;
		} else if (attr->type == ATTR_REPARSE) {
			mi_get_ref(&ni->mi, &ref);
			ntfs_remove_reparse(sbi, 0, &ref);
		} else if (attr->type == ATTR_ID && !attr->non_res &&
			   le32_to_cpu(attr->res.data_size) >=
				   sizeof(struct GUID)) {
			ntfs_objid_remove(sbi, resident_data(attr));
		}

		if (!attr->non_res)
			continue;

		svcn = le64_to_cpu(attr->nres.svcn);
		evcn = le64_to_cpu(attr->nres.evcn);

		if (evcn + 1 <= svcn)
			continue;

		asize = le32_to_cpu(attr->size);
		roff = le16_to_cpu(attr->nres.run_off);

		/* run==1 means unpack and deallocate. */
		run_unpack_ex(RUN_DEALLOCATE, sbi, ni->mi.rno, svcn, evcn, svcn,
			      Add2Ptr(attr, roff), asize - roff);
	}

	if (ni->attr_list.size) {
		run_deallocate(ni->mi.sbi, &ni->attr_list.run, true);
		al_destroy(ni);
	}

	/* Free all subrecords. */
	for (node = rb_first(&ni->mi_tree); node;) {
		struct rb_node *next = rb_next(node);
		struct mft_inode *mi = rb_entry(node, struct mft_inode, node);
>>>>>>> wip

		clear_rec_inuse(mi->mrec);
		mi->dirty = true;
		mi_write(mi, 0);

		ntfs_mark_rec_free(sbi, mi->rno);
		ni_remove_mi(ni, mi);
		mi_put(mi);
		node = next;
	}

<<<<<<< HEAD
	// Free base record
	clear_rec_inuse(ni->mi.mrec);
	ni->mi.dirty = true;
	err = mi_write(&ni->mi, 0);
=======
	/* Free base record. */
	clear_rec_inuse(ni->mi.mrec);
	ni->mi.dirty = true;
	err = mi_write(&ni->mi, 0);

>>>>>>> wip
	ntfs_mark_rec_free(sbi, ni->mi.rno);

	return err;
}

<<<<<<< HEAD
/*
 * ni_fname_name
 *
 * returns file name attribute by its value
 */
ATTR_FILE_NAME *ni_fname_name(ntfs_inode *ni, const struct cpu_str *uni,
			      const MFT_REF *home_dir, ATTR_LIST_ENTRY **le)
{
	ATTRIB *attr = NULL;
	ATTR_FILE_NAME *fname;

	*le = NULL;

	/* Enumerate all names */
next:
	attr = ni_find_attr(ni, attr, le, ATTR_NAME, NULL, 0, NULL, NULL);
=======
/* ni_fname_name
 *
 * Return: File name attribute by its value.
 */
struct ATTR_FILE_NAME *ni_fname_name(struct ntfs_inode *ni,
				     const struct cpu_str *uni,
				     const struct MFT_REF *home_dir,
				     struct mft_inode **mi,
				     struct ATTR_LIST_ENTRY **le)
{
	struct ATTRIB *attr = NULL;
	struct ATTR_FILE_NAME *fname;

	*le = NULL;

	/* Enumerate all names. */
next:
	attr = ni_find_attr(ni, attr, le, ATTR_NAME, NULL, 0, NULL, mi);
>>>>>>> wip
	if (!attr)
		return NULL;

	fname = resident_data_ex(attr, SIZEOF_ATTRIBUTE_FILENAME);
	if (!fname)
		goto next;

	if (home_dir && memcmp(home_dir, &fname->home, sizeof(*home_dir)))
		goto next;

	if (!uni)
		goto next;

	if (uni->len != fname->name_len)
		goto next;

<<<<<<< HEAD
	if (ntfs_cmp_names_cpu(uni, (struct le_str *)&fname->name_len, NULL))
=======
	if (ntfs_cmp_names_cpu(uni, (struct le_str *)&fname->name_len, NULL,
			       false))
>>>>>>> wip
		goto next;

	return fname;
}

/*
 * ni_fname_type
 *
<<<<<<< HEAD
 * returns file name attribute with given type
 */
ATTR_FILE_NAME *ni_fname_type(ntfs_inode *ni, u8 name_type,
			      ATTR_LIST_ENTRY **le)
{
	ATTRIB *attr = NULL;
	ATTR_FILE_NAME *fname;

	*le = NULL;

	/* Enumerate all names */
next_name:
	attr = ni_find_attr(ni, attr, le, ATTR_NAME, NULL, 0, NULL, NULL);
	if (!attr)
		return NULL;

	fname = resident_data_ex(attr, SIZEOF_ATTRIBUTE_FILENAME);
	if (fname && name_type == fname->type)
		return fname;
	goto next_name;
}

/*
 * ni_init_compress
 *
 * allocates and fill 'compress_ctx'
 * used to decompress lzx and xpress
 */
int ni_init_compress(ntfs_inode *ni, struct COMPRESS_CTX *ctx)
{
	u32 c_format = ((ni->ni_flags & NI_FLAG_COMPRESSED_MASK) >> 8) - 1;
	u32 chunk_bits;

	switch (c_format) {
	case WOF_COMPRESSION_XPRESS4K:
		chunk_bits = 12; // 4k
		break;
	case WOF_COMPRESSION_LZX:
		chunk_bits = 15; // 32k
		break;
	case WOF_COMPRESSION_XPRESS8K:
		chunk_bits = 13; // 8k
		break;
	case WOF_COMPRESSION_XPRESS16K:
		chunk_bits = 14; // 16k
		break;
	default:
		return -EOPNOTSUPP;
	}

	ctx->chunk_bits = chunk_bits;
	ctx->offset_bits = ni->vfs_inode.i_size < 0x100000000ull ?
				   2 :
				   3; // 32 or 64 bits per offsets

	ctx->compress_format = c_format;
	ctx->chunk_size = 1u << chunk_bits;
	ctx->chunk_num = -1;
	ctx->first_chunk = -1;
	ctx->total_chunks = (ni->vfs_inode.i_size - 1) >> chunk_bits;
	ctx->chunk0_off = ctx->total_chunks << ctx->offset_bits;
=======
 * Return: File name attribute with given type.
 */
struct ATTR_FILE_NAME *ni_fname_type(struct ntfs_inode *ni, u8 name_type,
				     struct mft_inode **mi,
				     struct ATTR_LIST_ENTRY **le)
{
	struct ATTRIB *attr = NULL;
	struct ATTR_FILE_NAME *fname;

	*le = NULL;

	if (FILE_NAME_POSIX == name_type)
		return NULL;

	/* Enumerate all names. */
	for (;;) {
		attr = ni_find_attr(ni, attr, le, ATTR_NAME, NULL, 0, NULL, mi);
		if (!attr)
			return NULL;

		fname = resident_data_ex(attr, SIZEOF_ATTRIBUTE_FILENAME);
		if (fname && name_type == fname->type)
			return fname;
	}
}

/*
 * ni_new_attr_flags
 *
 * Process compressed/sparsed in special way.
 * NOTE: You need to set ni->std_fa = new_fa
 * after this function to keep internal structures in consistency.
 */
int ni_new_attr_flags(struct ntfs_inode *ni, enum FILE_ATTRIBUTE new_fa)
{
	struct ATTRIB *attr;
	struct mft_inode *mi;
	__le16 new_aflags;
	u32 new_asize;

	attr = ni_find_attr(ni, NULL, NULL, ATTR_DATA, NULL, 0, NULL, &mi);
	if (!attr)
		return -EINVAL;

	new_aflags = attr->flags;

	if (new_fa & FILE_ATTRIBUTE_SPARSE_FILE)
		new_aflags |= ATTR_FLAG_SPARSED;
	else
		new_aflags &= ~ATTR_FLAG_SPARSED;

	if (new_fa & FILE_ATTRIBUTE_COMPRESSED)
		new_aflags |= ATTR_FLAG_COMPRESSED;
	else
		new_aflags &= ~ATTR_FLAG_COMPRESSED;

	if (new_aflags == attr->flags)
		return 0;

	if ((new_aflags & (ATTR_FLAG_COMPRESSED | ATTR_FLAG_SPARSED)) ==
	    (ATTR_FLAG_COMPRESSED | ATTR_FLAG_SPARSED)) {
		ntfs_inode_warn(&ni->vfs_inode,
				"file can't be sparsed and compressed");
		return -EOPNOTSUPP;
	}

	if (!attr->non_res)
		goto out;

	if (attr->nres.data_size) {
		ntfs_inode_warn(
			&ni->vfs_inode,
			"one can change sparsed/compressed only for empty files");
		return -EOPNOTSUPP;
	}

	/* Resize nonresident empty attribute in-place only. */
	new_asize = (new_aflags & (ATTR_FLAG_COMPRESSED | ATTR_FLAG_SPARSED))
			    ? (SIZEOF_NONRESIDENT_EX + 8)
			    : (SIZEOF_NONRESIDENT + 8);

	if (!mi_resize_attr(mi, attr, new_asize - le32_to_cpu(attr->size)))
		return -EOPNOTSUPP;

	if (new_aflags & ATTR_FLAG_SPARSED) {
		attr->name_off = SIZEOF_NONRESIDENT_EX_LE;
		/* Windows uses 16 clusters per frame but supports one cluster per frame too. */
		attr->nres.c_unit = 0;
		ni->vfs_inode.i_mapping->a_ops = &ntfs_aops;
	} else if (new_aflags & ATTR_FLAG_COMPRESSED) {
		attr->name_off = SIZEOF_NONRESIDENT_EX_LE;
		/* The only allowed: 16 clusters per frame. */
		attr->nres.c_unit = NTFS_LZNT_CUNIT;
		ni->vfs_inode.i_mapping->a_ops = &ntfs_aops_cmpr;
	} else {
		attr->name_off = SIZEOF_NONRESIDENT_LE;
		/* Normal files. */
		attr->nres.c_unit = 0;
		ni->vfs_inode.i_mapping->a_ops = &ntfs_aops;
	}
	attr->nres.run_off = attr->name_off;
out:
	attr->flags = new_aflags;
	mi->dirty = true;
>>>>>>> wip

	return 0;
}

/*
 * ni_parse_reparse
 *
<<<<<<< HEAD
 * buffer is at least 24 bytes
 */
enum REPARSE_SIGN ni_parse_reparse(ntfs_inode *ni, ATTRIB *attr, void *buffer)
{
	const REPARSE_DATA_BUFFER *rp = NULL;
	u32 c_format;
	u16 len;
	typeof(rp->CompressReparseBuffer) *cmpr;

	/* Try to estimate reparse point */
	if (!attr->non_res) {
		rp = resident_data_ex(attr, sizeof(REPARSE_DATA_BUFFER));
	} else if (le64_to_cpu(attr->nres.data_size) >=
		   sizeof(REPARSE_DATA_BUFFER)) {
=======
 * Buffer is at least 24 bytes.
 */
enum REPARSE_SIGN ni_parse_reparse(struct ntfs_inode *ni, struct ATTRIB *attr,
				   void *buffer)
{
	const struct REPARSE_DATA_BUFFER *rp = NULL;
	u8 bits;
	u16 len;
	typeof(rp->CompressReparseBuffer) *cmpr;

	static_assert(sizeof(struct REPARSE_DATA_BUFFER) <= 24);

	/* Try to estimate reparse point. */
	if (!attr->non_res) {
		rp = resident_data_ex(attr, sizeof(struct REPARSE_DATA_BUFFER));
	} else if (le64_to_cpu(attr->nres.data_size) >=
		   sizeof(struct REPARSE_DATA_BUFFER)) {
>>>>>>> wip
		struct runs_tree run;

		run_init(&run);

		if (!attr_load_runs_vcn(ni, ATTR_REPARSE, NULL, 0, &run, 0) &&
		    !ntfs_read_run_nb(ni->mi.sbi, &run, 0, buffer,
<<<<<<< HEAD
				      sizeof(REPARSE_DATA_BUFFER), NULL)) {
=======
				      sizeof(struct REPARSE_DATA_BUFFER),
				      NULL)) {
>>>>>>> wip
			rp = buffer;
		}

		run_close(&run);
	}

	if (!rp)
		return REPARSE_NONE;

	len = le16_to_cpu(rp->ReparseDataLength);
	switch (rp->ReparseTag) {
	case (IO_REPARSE_TAG_MICROSOFT | IO_REPARSE_TAG_SYMBOLIC_LINK):
<<<<<<< HEAD
		break; /* Symbolic link */
	case IO_REPARSE_TAG_MOUNT_POINT:
		break; /* Mount points and junctions */
	case IO_REPARSE_TAG_SYMLINK:
		break;
	case IO_REPARSE_TAG_COMPRESS:
=======
		break; /* Symbolic link. */
	case IO_REPARSE_TAG_MOUNT_POINT:
		break; /* Mount points and junctions. */
	case IO_REPARSE_TAG_SYMLINK:
		break;
	case IO_REPARSE_TAG_COMPRESS:
		/*
		 * WOF - Windows Overlay Filter - Used to compress files with
		 * LZX/Xpress.
		 *
		 * Unlike native NTFS file compression, the Windows
		 * Overlay Filter supports only read operations. This means
		 * that it doesn't need to sector-align each compressed chunk,
		 * so the compressed data can be packed more tightly together.
		 * If you open the file for writing, the WOF just decompresses
		 * the entire file, turning it back into a plain file.
		 *
		 * Ntfs3 driver decompresses the entire file only on write or
		 * change size requests.
		 */

>>>>>>> wip
		cmpr = &rp->CompressReparseBuffer;
		if (len < sizeof(*cmpr) ||
		    cmpr->WofVersion != WOF_CURRENT_VERSION ||
		    cmpr->WofProvider != WOF_PROVIDER_SYSTEM ||
		    cmpr->ProviderVer != WOF_PROVIDER_CURRENT_VERSION) {
			return REPARSE_NONE;
		}
<<<<<<< HEAD
		c_format = le32_to_cpu(cmpr->CompressionFormat);
		if (c_format > 3)
			return REPARSE_NONE;

		ni->ni_flags |= (c_format + 1) << 8;
=======

		switch (cmpr->CompressionFormat) {
		case WOF_COMPRESSION_XPRESS4K:
			bits = 0xc; // 4k
			break;
		case WOF_COMPRESSION_XPRESS8K:
			bits = 0xd; // 8k
			break;
		case WOF_COMPRESSION_XPRESS16K:
			bits = 0xe; // 16k
			break;
		case WOF_COMPRESSION_LZX32K:
			bits = 0xf; // 32k
			break;
		default:
			bits = 0x10; // 64k
			break;
		}
		ni_set_ext_compress_bits(ni, bits);
>>>>>>> wip
		return REPARSE_COMPRESSED;

	case IO_REPARSE_TAG_DEDUP:
		ni->ni_flags |= NI_FLAG_DEDUPLICATED;
		return REPARSE_DEDUPLICATED;

	default:
		if (rp->ReparseTag & IO_REPARSE_TAG_NAME_SURROGATE)
			break;

		return REPARSE_NONE;
	}

<<<<<<< HEAD
	/* Looks like normal symlink */
=======
	/* Looks like normal symlink. */
>>>>>>> wip
	return REPARSE_LINK;
}

/*
<<<<<<< HEAD
 * When decompressing, we typically obtain more than one page per reference.
 * We inject the additional pages into the page cache.
 */
int ni_readpage_cmpr(ntfs_inode *ni, struct page *page)
{
	int err;
	ntfs_sb_info *sbi = ni->mi.sbi;
	struct address_space *mapping = page->mapping;
	ATTR_LIST_ENTRY *le;
	ATTRIB *attr;
	u8 frame_bits;
	u32 frame_size, i, idx;
	CLST frame, clst_data;
	struct page *pg;
	pgoff_t index = page->index, end_index;
	u64 vbo = (u64)index << PAGE_SHIFT;
	u32 pages_per_frame = 0;
	struct page **pages = NULL;
	char *frame_buf = NULL;
	char *frame_unc;
	u32 cmpr_size, unc_size;
	u64 frame_vbo, valid_size;
	size_t unc_size_fin;
	struct COMPRESS_CTX *ctx = NULL;
	bool is_compr = false;

	end_index = (ni->vfs_inode.i_size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	if (index >= end_index) {
=======
 * ni_fiemap - Helper for file_fiemap().
 *
 * Assumed ni_lock.
 * TODO: Less aggressive locks.
 */
int ni_fiemap(struct ntfs_inode *ni, struct fiemap_extent_info *fieinfo,
	      __u64 vbo, __u64 len)
{
	int err = 0;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	u8 cluster_bits = sbi->cluster_bits;
	struct runs_tree *run;
	struct rw_semaphore *run_lock;
	struct ATTRIB *attr;
	CLST vcn = vbo >> cluster_bits;
	CLST lcn, clen;
	u64 valid = ni->i_valid;
	u64 lbo, bytes;
	u64 end, alloc_size;
	size_t idx = -1;
	u32 flags;
	bool ok;

	if (S_ISDIR(ni->vfs_inode.i_mode)) {
		run = &ni->dir.alloc_run;
		attr = ni_find_attr(ni, NULL, NULL, ATTR_ALLOC, I30_NAME,
				    ARRAY_SIZE(I30_NAME), NULL, NULL);
		run_lock = &ni->dir.run_lock;
	} else {
		run = &ni->file.run;
		attr = ni_find_attr(ni, NULL, NULL, ATTR_DATA, NULL, 0, NULL,
				    NULL);
		if (!attr) {
			err = -EINVAL;
			goto out;
		}
		if (is_attr_compressed(attr)) {
			/* Unfortunately cp -r incorrectly treats compressed clusters. */
			err = -EOPNOTSUPP;
			ntfs_inode_warn(
				&ni->vfs_inode,
				"fiemap is not supported for compressed file (cp -r)");
			goto out;
		}
		run_lock = &ni->file.run_lock;
	}

	if (!attr || !attr->non_res) {
		err = fiemap_fill_next_extent(
			fieinfo, 0, 0,
			attr ? le32_to_cpu(attr->res.data_size) : 0,
			FIEMAP_EXTENT_DATA_INLINE | FIEMAP_EXTENT_LAST |
				FIEMAP_EXTENT_MERGED);
		goto out;
	}

	end = vbo + len;
	alloc_size = le64_to_cpu(attr->nres.alloc_size);
	if (end > alloc_size)
		end = alloc_size;

	down_read(run_lock);

	while (vbo < end) {
		if (idx == -1) {
			ok = run_lookup_entry(run, vcn, &lcn, &clen, &idx);
		} else {
			CLST vcn_next = vcn;

			ok = run_get_entry(run, ++idx, &vcn, &lcn, &clen) &&
			     vcn == vcn_next;
			if (!ok)
				vcn = vcn_next;
		}

		if (!ok) {
			up_read(run_lock);
			down_write(run_lock);

			err = attr_load_runs_vcn(ni, attr->type,
						 attr_name(attr),
						 attr->name_len, run, vcn);

			up_write(run_lock);
			down_read(run_lock);

			if (err)
				break;

			ok = run_lookup_entry(run, vcn, &lcn, &clen, &idx);

			if (!ok) {
				err = -EINVAL;
				break;
			}
		}

		if (!clen) {
			err = -EINVAL; // ?
			break;
		}

		if (lcn == SPARSE_LCN) {
			vcn += clen;
			vbo = (u64)vcn << cluster_bits;
			continue;
		}

		flags = FIEMAP_EXTENT_MERGED;
		if (S_ISDIR(ni->vfs_inode.i_mode)) {
			;
		} else if (is_attr_compressed(attr)) {
			CLST clst_data;

			err = attr_is_frame_compressed(
				ni, attr, vcn >> attr->nres.c_unit, &clst_data);
			if (err)
				break;
			if (clst_data < NTFS_LZNT_CLUSTERS)
				flags |= FIEMAP_EXTENT_ENCODED;
		} else if (is_attr_encrypted(attr)) {
			flags |= FIEMAP_EXTENT_DATA_ENCRYPTED;
		}

		vbo = (u64)vcn << cluster_bits;
		bytes = (u64)clen << cluster_bits;
		lbo = (u64)lcn << cluster_bits;

		vcn += clen;

		if (vbo + bytes >= end) {
			bytes = end - vbo;
			flags |= FIEMAP_EXTENT_LAST;
		}

		if (vbo + bytes <= valid) {
			;
		} else if (vbo >= valid) {
			flags |= FIEMAP_EXTENT_UNWRITTEN;
		} else {
			/* vbo < valid && valid < vbo + bytes */
			u64 dlen = valid - vbo;

			err = fiemap_fill_next_extent(fieinfo, vbo, lbo, dlen,
						      flags);
			if (err < 0)
				break;
			if (err == 1) {
				err = 0;
				break;
			}

			vbo = valid;
			bytes -= dlen;
			if (!bytes)
				continue;

			lbo += dlen;
			flags |= FIEMAP_EXTENT_UNWRITTEN;
		}

		err = fiemap_fill_next_extent(fieinfo, vbo, lbo, bytes, flags);
		if (err < 0)
			break;
		if (err == 1) {
			err = 0;
			break;
		}

		vbo += bytes;
	}

	up_read(run_lock);

out:
	return err;
}

/*
 * ni_readpage_cmpr
 *
 * When decompressing, we typically obtain more than one page per reference.
 * We inject the additional pages into the page cache.
 */
int ni_readpage_cmpr(struct ntfs_inode *ni, struct page *page)
{
	int err;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	struct address_space *mapping = page->mapping;
	pgoff_t index = page->index;
	u64 frame_vbo, vbo = (u64)index << PAGE_SHIFT;
	struct page **pages = NULL; /* Array of at most 16 pages. stack? */
	u8 frame_bits;
	CLST frame;
	u32 i, idx, frame_size, pages_per_frame;
	gfp_t gfp_mask;
	struct page *pg;

	if (vbo >= ni->vfs_inode.i_size) {
>>>>>>> wip
		SetPageUptodate(page);
		err = 0;
		goto out;
	}

<<<<<<< HEAD
	le = NULL;
	attr = ni_find_attr(ni, NULL, &le, ATTR_DATA, NULL, 0, NULL, NULL);
	if (!attr) {
		err = -ENOENT;
		goto out;
	}

	WARN_ON(!attr->non_res);

	if (ni->ni_flags & NI_FLAG_COMPRESSED_MASK) {
		ctx = ntfs_alloc(sizeof(*ctx), 1);
		if (!ctx) {
			err = -ENOMEM;
			goto out;
		}
		err = ni_init_compress(ni, ctx);
		if (err)
			goto out;

		frame_bits = ctx->chunk_bits;
		frame_size = ctx->chunk_size;
		frame = vbo >> frame_bits;
		frame_vbo = (u64)frame << frame_bits;

		/* TODO: port lzx/xpress */
		err = -EOPNOTSUPP;
		goto out;
	} else if (is_attr_compressed(attr)) {
		if (sbi->cluster_size > NTFS_LZNT_MAX_CLUSTER) {
			err = -EOPNOTSUPP;
			goto out;
		}

		if (attr->nres.c_unit != NTFS_LZNT_CUNIT) {
			err = -EOPNOTSUPP;
			goto out;
		}

		frame_bits = 4 + sbi->cluster_bits;
		frame_size = 16 << sbi->cluster_bits;
		frame = vbo >> frame_bits;
		frame_vbo = (u64)frame << frame_bits;

		err = attr_is_frame_compressed(ni, attr, frame, &clst_data,
					       &is_compr);
		if (err)
			goto out;
	} else {
		WARN_ON(1);
		err = -EINVAL;
		goto out;
	}

	pages_per_frame = frame_size >> PAGE_SHIFT;
	pages = ntfs_alloc(pages_per_frame * sizeof(*pages), 1);
=======
	if (ni->ni_flags & NI_FLAG_COMPRESSED_MASK) {
		/* Xpress or LZX. */
		frame_bits = ni_ext_compress_bits(ni);
	} else {
		/* LZNT compression. */
		frame_bits = NTFS_LZNT_CUNIT + sbi->cluster_bits;
	}
	frame_size = 1u << frame_bits;
	frame = vbo >> frame_bits;
	frame_vbo = (u64)frame << frame_bits;
	idx = (vbo - frame_vbo) >> PAGE_SHIFT;

	pages_per_frame = frame_size >> PAGE_SHIFT;
	pages = kcalloc(pages_per_frame, sizeof(struct page *), GFP_NOFS);
>>>>>>> wip
	if (!pages) {
		err = -ENOMEM;
		goto out;
	}

<<<<<<< HEAD
	idx = (vbo - frame_vbo) >> PAGE_SHIFT;
	pages[idx] = page;
	index = frame_vbo >> PAGE_SHIFT;
	kmap(page);

	for (i = 0; i < pages_per_frame && index < end_index; i++, index++) {
		if (i == idx)
			continue;

		pg = grab_cache_page_nowait(mapping, index);
		if (!pg)
			continue;

		pages[i] = pg;
		if (!PageDirty(pg) && (!PageUptodate(pg) || PageError(pg)))
			ClearPageError(pg);
		kmap(pg);
	}

	valid_size = ni->i_valid;

	if (frame_vbo >= valid_size || !clst_data) {
		for (i = 0; i < pages_per_frame; i++) {
			pg = pages[i];
			if (!pg || PageDirty(pg) ||
			    (PageUptodate(pg) && !PageError(pg)))
				continue;

			memset(page_address(pg), 0, PAGE_SIZE);
			flush_dcache_page(pg);
			SetPageUptodate(pg);
		}
		err = 0;
		goto out1;
	}

	unc_size = frame_vbo + frame_size > valid_size ?
			   (valid_size - frame_vbo) :
			   frame_size;

	/* read 'clst_data' clusters from disk */
	cmpr_size = clst_data << sbi->cluster_bits;
	frame_buf = ntfs_alloc(cmpr_size, 0);
	if (!frame_buf) {
		err = -ENOMEM;
		goto out1;
	}

	err = ntfs_read_run_nb(sbi, &ni->file.run, frame_vbo, frame_buf,
			       cmpr_size, NULL);
	if (err)
		goto out2;

	spin_lock(&sbi->compress.lock);
	frame_unc = sbi->compress.frame_unc;

	if (!is_compr) {
		unc_size_fin = unc_size;
		frame_unc = frame_buf;
	} else {
		/* decompress: frame_buf -> frame_unc */
		unc_size_fin = decompress_lznt(frame_buf, cmpr_size, frame_unc,
					       frame_size);
		if ((ssize_t)unc_size_fin < 0) {
			err = unc_size_fin;
			goto out3;
		}

		if (!unc_size_fin || unc_size_fin > frame_size) {
			err = -EINVAL;
			goto out3;
		}
	}

	for (i = 0; i < pages_per_frame; i++) {
		u8 *pa;
		u32 use, done;
		loff_t vbo;

		pg = pages[i];
		if (!pg)
			continue;

		if (PageDirty(pg) || (PageUptodate(pg) && !PageError(pg)))
			continue;

		pa = page_address(pg);

		use = 0;
		done = i * PAGE_SIZE;
		vbo = frame_vbo + done;

		if (vbo < valid_size && unc_size_fin > done) {
			use = unc_size_fin - done;
			if (use > PAGE_SIZE)
				use = PAGE_SIZE;
			if (vbo + use > valid_size)
				use = valid_size - vbo;
			memcpy(pa, frame_unc + done, use);
		}

		if (use < PAGE_SIZE)
			memset(pa + use, 0, PAGE_SIZE - use);

		flush_dcache_page(pg);
		SetPageUptodate(pg);
	}

out3:
	spin_unlock(&sbi->compress.lock);

out2:
	ntfs_free(frame_buf);
out1:
	for (i = 0; i < pages_per_frame; i++) {
		pg = pages[i];
		if (i == idx || !pg)
			continue;
		kunmap(pg);
=======
	pages[idx] = page;
	index = frame_vbo >> PAGE_SHIFT;
	gfp_mask = mapping_gfp_mask(mapping);

	for (i = 0; i < pages_per_frame; i++, index++) {
		if (i == idx)
			continue;

		pg = find_or_create_page(mapping, index, gfp_mask);
		if (!pg) {
			err = -ENOMEM;
			goto out1;
		}
		pages[i] = pg;
	}

	err = ni_read_frame(ni, frame_vbo, pages, pages_per_frame);

out1:
	if (err)
		SetPageError(page);

	for (i = 0; i < pages_per_frame; i++) {
		pg = pages[i];
		if (i == idx)
			continue;
>>>>>>> wip
		unlock_page(pg);
		put_page(pg);
	}

<<<<<<< HEAD
	if (err)
		SetPageError(page);
	kunmap(page);

out:
	/* At this point, err contains 0 or -EIO depending on the "critical" page */
	ntfs_free(pages);
	unlock_page(page);

	ntfs_free(ctx);
=======
out:
	/* At this point, err contains 0 or -EIO depending on the "critical" page. */
	kfree(pages);
	unlock_page(page);

	return err;
}

#ifdef CONFIG_NTFS3_LZX_XPRESS
/*
 * ni_decompress_file - Decompress LZX/Xpress compressed file.
 *
 * Remove ATTR_DATA::WofCompressedData.
 * Remove ATTR_REPARSE.
 */
int ni_decompress_file(struct ntfs_inode *ni)
{
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	struct inode *inode = &ni->vfs_inode;
	loff_t i_size = inode->i_size;
	struct address_space *mapping = inode->i_mapping;
	gfp_t gfp_mask = mapping_gfp_mask(mapping);
	struct page **pages = NULL;
	struct ATTR_LIST_ENTRY *le;
	struct ATTRIB *attr;
	CLST vcn, cend, lcn, clen, end;
	pgoff_t index;
	u64 vbo;
	u8 frame_bits;
	u32 i, frame_size, pages_per_frame, bytes;
	struct mft_inode *mi;
	int err;

	/* Clusters for decompressed data. */
	cend = bytes_to_cluster(sbi, i_size);

	if (!i_size)
		goto remove_wof;

	/* Check in advance. */
	if (cend > wnd_zeroes(&sbi->used.bitmap)) {
		err = -ENOSPC;
		goto out;
	}

	frame_bits = ni_ext_compress_bits(ni);
	frame_size = 1u << frame_bits;
	pages_per_frame = frame_size >> PAGE_SHIFT;
	pages = kcalloc(pages_per_frame, sizeof(struct page *), GFP_NOFS);
	if (!pages) {
		err = -ENOMEM;
		goto out;
	}

	/*
	 * Step 1: Decompress data and copy to new allocated clusters.
	 */
	index = 0;
	for (vbo = 0; vbo < i_size; vbo += bytes) {
		u32 nr_pages;
		bool new;

		if (vbo + frame_size > i_size) {
			bytes = i_size - vbo;
			nr_pages = (bytes + PAGE_SIZE - 1) >> PAGE_SHIFT;
		} else {
			nr_pages = pages_per_frame;
			bytes = frame_size;
		}

		end = bytes_to_cluster(sbi, vbo + bytes);

		for (vcn = vbo >> sbi->cluster_bits; vcn < end; vcn += clen) {
			err = attr_data_get_block(ni, vcn, cend - vcn, &lcn,
						  &clen, &new);
			if (err)
				goto out;
		}

		for (i = 0; i < pages_per_frame; i++, index++) {
			struct page *pg;

			pg = find_or_create_page(mapping, index, gfp_mask);
			if (!pg) {
				while (i--) {
					unlock_page(pages[i]);
					put_page(pages[i]);
				}
				err = -ENOMEM;
				goto out;
			}
			pages[i] = pg;
		}

		err = ni_read_frame(ni, vbo, pages, pages_per_frame);

		if (!err) {
			down_read(&ni->file.run_lock);
			err = ntfs_bio_pages(sbi, &ni->file.run, pages,
					     nr_pages, vbo, bytes,
					     REQ_OP_WRITE);
			up_read(&ni->file.run_lock);
		}

		for (i = 0; i < pages_per_frame; i++) {
			unlock_page(pages[i]);
			put_page(pages[i]);
		}

		if (err)
			goto out;

		cond_resched();
	}

remove_wof:
	/*
	 * Step 2: Deallocate attributes ATTR_DATA::WofCompressedData
	 * and ATTR_REPARSE.
	 */
	attr = NULL;
	le = NULL;
	while ((attr = ni_enum_attr_ex(ni, attr, &le, NULL))) {
		CLST svcn, evcn;
		u32 asize, roff;

		if (attr->type == ATTR_REPARSE) {
			struct MFT_REF ref;

			mi_get_ref(&ni->mi, &ref);
			ntfs_remove_reparse(sbi, 0, &ref);
		}

		if (!attr->non_res)
			continue;

		if (attr->type != ATTR_REPARSE &&
		    (attr->type != ATTR_DATA ||
		     attr->name_len != ARRAY_SIZE(WOF_NAME) ||
		     memcmp(attr_name(attr), WOF_NAME, sizeof(WOF_NAME))))
			continue;

		svcn = le64_to_cpu(attr->nres.svcn);
		evcn = le64_to_cpu(attr->nres.evcn);

		if (evcn + 1 <= svcn)
			continue;

		asize = le32_to_cpu(attr->size);
		roff = le16_to_cpu(attr->nres.run_off);

		/*run==1  Means unpack and deallocate. */
		run_unpack_ex(RUN_DEALLOCATE, sbi, ni->mi.rno, svcn, evcn, svcn,
			      Add2Ptr(attr, roff), asize - roff);
	}

	/*
	 * Step 3: Remove attribute ATTR_DATA::WofCompressedData.
	 */
	err = ni_remove_attr(ni, ATTR_DATA, WOF_NAME, ARRAY_SIZE(WOF_NAME),
			     false, NULL);
	if (err)
		goto out;

	/*
	 * Step 4: Remove ATTR_REPARSE.
	 */
	err = ni_remove_attr(ni, ATTR_REPARSE, NULL, 0, false, NULL);
	if (err)
		goto out;

	/*
	 * Step 5: Remove sparse flag from data attribute.
	 */
	attr = ni_find_attr(ni, NULL, NULL, ATTR_DATA, NULL, 0, NULL, &mi);
	if (!attr) {
		err = -EINVAL;
		goto out;
	}

	if (attr->non_res && is_attr_sparsed(attr)) {
		/* Sparsed attribute header is 8 bytes bigger than normal. */
		struct MFT_REC *rec = mi->mrec;
		u32 used = le32_to_cpu(rec->used);
		u32 asize = le32_to_cpu(attr->size);
		u16 roff = le16_to_cpu(attr->nres.run_off);
		char *rbuf = Add2Ptr(attr, roff);

		memmove(rbuf - 8, rbuf, used - PtrOffset(rec, rbuf));
		attr->size = cpu_to_le32(asize - 8);
		attr->flags &= ~ATTR_FLAG_SPARSED;
		attr->nres.run_off = cpu_to_le16(roff - 8);
		attr->nres.c_unit = 0;
		rec->used = cpu_to_le32(used - 8);
		mi->dirty = true;
		ni->std_fa &= ~(FILE_ATTRIBUTE_SPARSE_FILE |
				FILE_ATTRIBUTE_REPARSE_POINT);

		mark_inode_dirty(inode);
	}

	/* Clear cached flag. */
	ni->ni_flags &= ~NI_FLAG_COMPRESSED_MASK;
	if (ni->file.offs_page) {
		put_page(ni->file.offs_page);
		ni->file.offs_page = NULL;
	}
	mapping->a_ops = &ntfs_aops;

out:
	kfree(pages);
	if (err) {
		make_bad_inode(inode);
		ntfs_set_state(sbi, NTFS_DIRTY_ERROR);
	}
>>>>>>> wip

	return err;
}

/*
<<<<<<< HEAD
 * ni_writepage_cmpr
 *
 * helper for ntfs_writepage_cmpr
 */
int ni_writepage_cmpr(struct page *page, int sync)
{
	int err;
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	loff_t i_size = i_size_read(inode);
	ntfs_inode *ni = ntfs_i(inode);
	ntfs_sb_info *sbi = ni->mi.sbi;
	pgoff_t index = page->index, end_index;
	u64 vbo = (u64)index << PAGE_SHIFT;
	u32 pages_per_frame = 0;
	struct page **pages = NULL;
	char *frame_buf = NULL;
	ATTR_LIST_ENTRY *le;
	ATTRIB *attr;
	u8 frame_bits;
	u32 frame_size, i, idx, unc_size;
	CLST frame;
	struct page *pg;
	char *frame_unc;
	u64 frame_vbo;
	size_t cmpr_size_fin, cmpr_size_clst;
	gfp_t mask;

	end_index = (i_size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	if (index >= end_index) {
		SetPageUptodate(page);
		err = 0;
		goto out;
	}

	le = NULL;
	attr = ni_find_attr(ni, NULL, &le, ATTR_DATA, NULL, 0, NULL, NULL);
	if (!attr) {
		err = -ENOENT;
		goto out;
	}

	if (!attr->non_res) {
		WARN_ON(1);
		err = 0;
		goto out;
	}

	if (!is_attr_compressed(attr)) {
		WARN_ON(1);
=======
 * decompress_lzx_xpress - External compression LZX/Xpress.
 */
static int decompress_lzx_xpress(struct ntfs_sb_info *sbi, const char *cmpr,
				 size_t cmpr_size, void *unc, size_t unc_size,
				 u32 frame_size)
{
	int err;
	void *ctx;

	if (cmpr_size == unc_size) {
		/* Frame not compressed. */
		memcpy(unc, cmpr, unc_size);
		return 0;
	}

	err = 0;
	if (frame_size == 0x8000) {
		mutex_lock(&sbi->compress.mtx_lzx);
		/* LZX: Frame compressed. */
		ctx = sbi->compress.lzx;
		if (!ctx) {
			/* Lazy initialize LZX decompress context. */
			ctx = lzx_allocate_decompressor();
			if (!ctx) {
				err = -ENOMEM;
				goto out1;
			}

			sbi->compress.lzx = ctx;
		}

		if (lzx_decompress(ctx, cmpr, cmpr_size, unc, unc_size)) {
			/* Treat all errors as "invalid argument". */
			err = -EINVAL;
		}
out1:
		mutex_unlock(&sbi->compress.mtx_lzx);
	} else {
		/* XPRESS: Frame compressed. */
		mutex_lock(&sbi->compress.mtx_xpress);
		ctx = sbi->compress.xpress;
		if (!ctx) {
			/* Lazy initialize Xpress decompress context. */
			ctx = xpress_allocate_decompressor();
			if (!ctx) {
				err = -ENOMEM;
				goto out2;
			}

			sbi->compress.xpress = ctx;
		}

		if (xpress_decompress(ctx, cmpr, cmpr_size, unc, unc_size)) {
			/* Treat all errors as "invalid argument". */
			err = -EINVAL;
		}
out2:
		mutex_unlock(&sbi->compress.mtx_xpress);
	}
	return err;
}
#endif

/*
 * ni_read_frame
 *
 * Pages - Array of locked pages.
 */
int ni_read_frame(struct ntfs_inode *ni, u64 frame_vbo, struct page **pages,
		  u32 pages_per_frame)
{
	int err;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	u8 cluster_bits = sbi->cluster_bits;
	char *frame_ondisk = NULL;
	char *frame_mem = NULL;
	struct page **pages_disk = NULL;
	struct ATTR_LIST_ENTRY *le = NULL;
	struct runs_tree *run = &ni->file.run;
	u64 valid_size = ni->i_valid;
	u64 vbo_disk;
	size_t unc_size;
	u32 frame_size, i, npages_disk, ondisk_size;
	struct page *pg;
	struct ATTRIB *attr;
	CLST frame, clst_data;

	/*
	 * To simplify decompress algorithm do vmap for source
	 * and target pages.
	 */
	for (i = 0; i < pages_per_frame; i++)
		kmap(pages[i]);

	frame_size = pages_per_frame << PAGE_SHIFT;
	frame_mem = vmap(pages, pages_per_frame, VM_MAP, PAGE_KERNEL);
	if (!frame_mem) {
		err = -ENOMEM;
		goto out;
	}

	attr = ni_find_attr(ni, NULL, &le, ATTR_DATA, NULL, 0, NULL, NULL);
	if (!attr) {
		err = -ENOENT;
		goto out1;
	}

	if (!attr->non_res) {
		u32 data_size = le32_to_cpu(attr->res.data_size);

		memset(frame_mem, 0, frame_size);
		if (frame_vbo < data_size) {
			ondisk_size = data_size - frame_vbo;
			memcpy(frame_mem, resident_data(attr) + frame_vbo,
			       min(ondisk_size, frame_size));
		}
		err = 0;
		goto out1;
	}

	if (frame_vbo >= valid_size) {
		memset(frame_mem, 0, frame_size);
		err = 0;
		goto out1;
	}

	if (ni->ni_flags & NI_FLAG_COMPRESSED_MASK) {
#ifndef CONFIG_NTFS3_LZX_XPRESS
		err = -EOPNOTSUPP;
		goto out1;
#else
		u32 frame_bits = ni_ext_compress_bits(ni);
		u64 frame64 = frame_vbo >> frame_bits;
		u64 frames, vbo_data;

		if (frame_size != (1u << frame_bits)) {
			err = -EINVAL;
			goto out1;
		}
		switch (frame_size) {
		case 0x1000:
		case 0x2000:
		case 0x4000:
		case 0x8000:
			break;
		default:
			/* Unknown compression. */
			err = -EOPNOTSUPP;
			goto out1;
		}

		attr = ni_find_attr(ni, attr, &le, ATTR_DATA, WOF_NAME,
				    ARRAY_SIZE(WOF_NAME), NULL, NULL);
		if (!attr) {
			ntfs_inode_err(
				&ni->vfs_inode,
				"external compressed file should contains data attribute \"WofCompressedData\"");
			err = -EINVAL;
			goto out1;
		}

		if (!attr->non_res) {
			run = NULL;
		} else {
			run = run_alloc();
			if (!run) {
				err = -ENOMEM;
				goto out1;
			}
		}

		frames = (ni->vfs_inode.i_size - 1) >> frame_bits;

		err = attr_wof_frame_info(ni, attr, run, frame64, frames,
					  frame_bits, &ondisk_size, &vbo_data);
		if (err)
			goto out2;

		if (frame64 == frames) {
			unc_size = 1 + ((ni->vfs_inode.i_size - 1) &
					(frame_size - 1));
			ondisk_size = attr_size(attr) - vbo_data;
		} else {
			unc_size = frame_size;
		}

		if (ondisk_size > frame_size) {
			err = -EINVAL;
			goto out2;
		}

		if (!attr->non_res) {
			if (vbo_data + ondisk_size >
			    le32_to_cpu(attr->res.data_size)) {
				err = -EINVAL;
				goto out1;
			}

			err = decompress_lzx_xpress(
				sbi, Add2Ptr(resident_data(attr), vbo_data),
				ondisk_size, frame_mem, unc_size, frame_size);
			goto out1;
		}
		vbo_disk = vbo_data;
		/* Load all runs to read [vbo_disk-vbo_to). */
		err = attr_load_runs_range(ni, ATTR_DATA, WOF_NAME,
					   ARRAY_SIZE(WOF_NAME), run, vbo_disk,
					   vbo_data + ondisk_size);
		if (err)
			goto out2;
		npages_disk = (ondisk_size + (vbo_disk & (PAGE_SIZE - 1)) +
			       PAGE_SIZE - 1) >>
			      PAGE_SHIFT;
#endif
	} else if (is_attr_compressed(attr)) {
		/* LZNT compression. */
		if (sbi->cluster_size > NTFS_LZNT_MAX_CLUSTER) {
			err = -EOPNOTSUPP;
			goto out1;
		}

		if (attr->nres.c_unit != NTFS_LZNT_CUNIT) {
			err = -EOPNOTSUPP;
			goto out1;
		}

		down_write(&ni->file.run_lock);
		run_truncate_around(run, le64_to_cpu(attr->nres.svcn));
		frame = frame_vbo >> (cluster_bits + NTFS_LZNT_CUNIT);
		err = attr_is_frame_compressed(ni, attr, frame, &clst_data);
		up_write(&ni->file.run_lock);
		if (err)
			goto out1;

		if (!clst_data) {
			memset(frame_mem, 0, frame_size);
			goto out1;
		}

		frame_size = sbi->cluster_size << NTFS_LZNT_CUNIT;
		ondisk_size = clst_data << cluster_bits;

		if (clst_data >= NTFS_LZNT_CLUSTERS) {
			/* Frame is not compressed. */
			down_read(&ni->file.run_lock);
			err = ntfs_bio_pages(sbi, run, pages, pages_per_frame,
					     frame_vbo, ondisk_size,
					     REQ_OP_READ);
			up_read(&ni->file.run_lock);
			goto out1;
		}
		vbo_disk = frame_vbo;
		npages_disk = (ondisk_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	} else {
		__builtin_unreachable();
		err = -EINVAL;
		goto out1;
	}

	pages_disk = kzalloc(npages_disk * sizeof(struct page *), GFP_NOFS);
	if (!pages_disk) {
		err = -ENOMEM;
		goto out2;
	}

	for (i = 0; i < npages_disk; i++) {
		pg = alloc_page(GFP_KERNEL);
		if (!pg) {
			err = -ENOMEM;
			goto out3;
		}
		pages_disk[i] = pg;
		lock_page(pg);
		kmap(pg);
	}

	/* Read 'ondisk_size' bytes from disk. */
	down_read(&ni->file.run_lock);
	err = ntfs_bio_pages(sbi, run, pages_disk, npages_disk, vbo_disk,
			     ondisk_size, REQ_OP_READ);
	up_read(&ni->file.run_lock);
	if (err)
		goto out3;

	/*
	 * To simplify decompress algorithm do vmap for source and target pages.
	 */
	frame_ondisk = vmap(pages_disk, npages_disk, VM_MAP, PAGE_KERNEL_RO);
	if (!frame_ondisk) {
		err = -ENOMEM;
		goto out3;
	}

	/* Decompress: Frame_ondisk -> frame_mem. */
#ifdef CONFIG_NTFS3_LZX_XPRESS
	if (run != &ni->file.run) {
		/* LZX or XPRESS */
		err = decompress_lzx_xpress(
			sbi, frame_ondisk + (vbo_disk & (PAGE_SIZE - 1)),
			ondisk_size, frame_mem, unc_size, frame_size);
	} else
#endif
	{
		/* LZNT - Native NTFS compression. */
		unc_size = decompress_lznt(frame_ondisk, ondisk_size, frame_mem,
					   frame_size);
		if ((ssize_t)unc_size < 0)
			err = unc_size;
		else if (!unc_size || unc_size > frame_size)
			err = -EINVAL;
	}
	if (!err && valid_size < frame_vbo + frame_size) {
		size_t ok = valid_size - frame_vbo;

		memset(frame_mem + ok, 0, frame_size - ok);
	}

	vunmap(frame_ondisk);

out3:
	for (i = 0; i < npages_disk; i++) {
		pg = pages_disk[i];
		if (pg) {
			kunmap(pg);
			unlock_page(pg);
			put_page(pg);
		}
	}
	kfree(pages_disk);

out2:
#ifdef CONFIG_NTFS3_LZX_XPRESS
	if (run != &ni->file.run)
		run_free(run);
#endif
out1:
	vunmap(frame_mem);
out:
	for (i = 0; i < pages_per_frame; i++) {
		pg = pages[i];
		kunmap(pg);
		ClearPageError(pg);
		SetPageUptodate(pg);
	}

	return err;
}

/*
 * ni_write_frame
 *
 * Pages - Array of locked pages.
 */
int ni_write_frame(struct ntfs_inode *ni, struct page **pages,
		   u32 pages_per_frame)
{
	int err;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	u8 frame_bits = NTFS_LZNT_CUNIT + sbi->cluster_bits;
	u32 frame_size = sbi->cluster_size << NTFS_LZNT_CUNIT;
	u64 frame_vbo = (u64)pages[0]->index << PAGE_SHIFT;
	CLST frame = frame_vbo >> frame_bits;
	char *frame_ondisk = NULL;
	struct page **pages_disk = NULL;
	struct ATTR_LIST_ENTRY *le = NULL;
	char *frame_mem;
	struct ATTRIB *attr;
	struct mft_inode *mi;
	u32 i;
	struct page *pg;
	size_t compr_size, ondisk_size;
	struct lznt *lznt;

	attr = ni_find_attr(ni, NULL, &le, ATTR_DATA, NULL, 0, NULL, &mi);
	if (!attr) {
		err = -ENOENT;
		goto out;
	}

	if (WARN_ON(!is_attr_compressed(attr))) {
>>>>>>> wip
		err = -EINVAL;
		goto out;
	}

	if (sbi->cluster_size > NTFS_LZNT_MAX_CLUSTER) {
		err = -EOPNOTSUPP;
		goto out;
	}

<<<<<<< HEAD
=======
	if (!attr->non_res) {
		down_write(&ni->file.run_lock);
		err = attr_make_nonresident(ni, attr, le, mi,
					    le32_to_cpu(attr->res.data_size),
					    &ni->file.run, &attr, pages[0]);
		up_write(&ni->file.run_lock);
		if (err)
			goto out;
	}

>>>>>>> wip
	if (attr->nres.c_unit != NTFS_LZNT_CUNIT) {
		err = -EOPNOTSUPP;
		goto out;
	}

<<<<<<< HEAD
	frame_bits = NTFS_LZNT_CUNIT + sbi->cluster_bits;
	frame_size = sbi->cluster_size << NTFS_LZNT_CUNIT;
	frame = vbo >> frame_bits;
	frame_vbo = (u64)frame << frame_bits;
	unc_size = frame_vbo + frame_size > i_size ? (i_size - frame_vbo) :
						     frame_size;

	frame_buf = ntfs_alloc(frame_size, 0);
	if (!frame_buf) {
=======
	pages_disk = kcalloc(pages_per_frame, sizeof(struct page *), GFP_NOFS);
	if (!pages_disk) {
>>>>>>> wip
		err = -ENOMEM;
		goto out;
	}

<<<<<<< HEAD
	pages_per_frame = frame_size >> PAGE_SHIFT;
	pages = ntfs_alloc(pages_per_frame * sizeof(*pages), 1);
	if (!pages) {
		err = -ENOMEM;
		goto out;
	}

	idx = (vbo - frame_vbo) >> PAGE_SHIFT;
	pages[idx] = page;
	index = frame_vbo >> PAGE_SHIFT;
	mask = mapping_gfp_mask(mapping);
	kmap(page);

	for (i = 0; i < pages_per_frame && index < end_index; i++, index++) {
		if (i == idx)
			continue;

		// added FGP_CREAT
		pg = pagecache_get_page(
			mapping, index,
			FGP_LOCK | FGP_NOFS | FGP_CREAT | FGP_NOWAIT, mask);
		if (!pg)
			continue;

		pages[i] = pg;

		if (PageError(pg)) {
			err = -EIO;
			goto out2;
		}

		if (!PageDirty(pg) && !PageUptodate(pg)) {
			memset(page_address(pg), 0, PAGE_SIZE);
			flush_dcache_page(pg);
			SetPageUptodate(pg);
		}

		kmap(pg);
	}

	spin_lock(&sbi->compress.lock);
	frame_unc = sbi->compress.frame_unc;

	for (i = 0; i < pages_per_frame; i++) {
		pg = pages[i];
		if (pg)
			memcpy(frame_unc + i * PAGE_SIZE, page_address(pg),
			       PAGE_SIZE);
		else
			memset(frame_unc + i * PAGE_SIZE, 0, PAGE_SIZE);
	}

	/* compress: frame_unc -> frame_buf */
	cmpr_size_fin = compress_lznt(frame_unc, unc_size, frame_buf,
				      frame_size, sbi->compress.ctx);

	cmpr_size_clst = ntfs_up_cluster(sbi, cmpr_size_fin);
	if (cmpr_size_clst + sbi->cluster_size > frame_size) {
		/* write frame as is */
		memcpy(frame_buf, frame_unc, frame_size);
		cmpr_size_fin = frame_size;
	} else if (cmpr_size_fin) {
		memset(frame_buf + cmpr_size_fin, 0,
		       cmpr_size_clst - cmpr_size_fin);
	}
	spin_unlock(&sbi->compress.lock);

	err = attr_allocate_frame(ni, frame, cmpr_size_fin, ni->i_valid);
	if (err)
		goto out2;

	if (!cmpr_size_clst)
		goto out2;

	err = ntfs_sb_write_run(sbi, &ni->file.run, frame_vbo, frame_buf,
				cmpr_size_clst);
	if (err)
		goto out2;

out2:
	ntfs_free(frame_buf);
	for (i = 0; i < pages_per_frame; i++) {
		pg = pages[i];
		if (!pg || i == idx)
			continue;
		kunmap(pg);
		SetPageUptodate(pg);
		/* clear page dirty so that writepages wouldn't work for us. */
		ClearPageDirty(pg);
		unlock_page(pg);
		put_page(pg);
	}

	if (err)
		SetPageError(page);
	kunmap(page);

out:
	/* At this point, err contains 0 or -EIO depending on the "critical" page */
	ntfs_free(pages);
	set_page_writeback(page);
	unlock_page(page);
	end_page_writeback(page);
=======
	for (i = 0; i < pages_per_frame; i++) {
		pg = alloc_page(GFP_KERNEL);
		if (!pg) {
			err = -ENOMEM;
			goto out1;
		}
		pages_disk[i] = pg;
		lock_page(pg);
		kmap(pg);
	}

	/* To simplify compress algorithm do vmap for source and target pages. */
	frame_ondisk = vmap(pages_disk, pages_per_frame, VM_MAP, PAGE_KERNEL);
	if (!frame_ondisk) {
		err = -ENOMEM;
		goto out1;
	}

	for (i = 0; i < pages_per_frame; i++)
		kmap(pages[i]);

	/* Map in-memory frame for read-only. */
	frame_mem = vmap(pages, pages_per_frame, VM_MAP, PAGE_KERNEL_RO);
	if (!frame_mem) {
		err = -ENOMEM;
		goto out2;
	}

	mutex_lock(&sbi->compress.mtx_lznt);
	lznt = NULL;
	if (!sbi->compress.lznt) {
		/*
		 * LZNT implements two levels of compression:
		 * 0 - Standard compression
		 * 1 - Best compression, requires a lot of cpu
		 * use mount option?
		 */
		lznt = get_lznt_ctx(0);
		if (!lznt) {
			mutex_unlock(&sbi->compress.mtx_lznt);
			err = -ENOMEM;
			goto out3;
		}

		sbi->compress.lznt = lznt;
		lznt = NULL;
	}

	/* Compress: frame_mem -> frame_ondisk */
	compr_size = compress_lznt(frame_mem, frame_size, frame_ondisk,
				   frame_size, sbi->compress.lznt);
	mutex_unlock(&sbi->compress.mtx_lznt);
	kfree(lznt);

	if (compr_size + sbi->cluster_size > frame_size) {
		/* Frame is not compressed. */
		compr_size = frame_size;
		ondisk_size = frame_size;
	} else if (compr_size) {
		/* Frame is compressed. */
		ondisk_size = ntfs_up_cluster(sbi, compr_size);
		memset(frame_ondisk + compr_size, 0, ondisk_size - compr_size);
	} else {
		/* Frame is sparsed. */
		ondisk_size = 0;
	}

	down_write(&ni->file.run_lock);
	run_truncate_around(&ni->file.run, le64_to_cpu(attr->nres.svcn));
	err = attr_allocate_frame(ni, frame, compr_size, ni->i_valid);
	up_write(&ni->file.run_lock);
	if (err)
		goto out2;

	if (!ondisk_size)
		goto out2;

	down_read(&ni->file.run_lock);
	err = ntfs_bio_pages(sbi, &ni->file.run,
			     ondisk_size < frame_size ? pages_disk : pages,
			     pages_per_frame, frame_vbo, ondisk_size,
			     REQ_OP_WRITE);
	up_read(&ni->file.run_lock);

out3:
	vunmap(frame_mem);

out2:
	for (i = 0; i < pages_per_frame; i++)
		kunmap(pages[i]);

	vunmap(frame_ondisk);
out1:
	for (i = 0; i < pages_per_frame; i++) {
		pg = pages_disk[i];
		if (pg) {
			kunmap(pg);
			unlock_page(pg);
			put_page(pg);
		}
	}
	kfree(pages_disk);
out:
	return err;
}

/*
 * ni_remove_name - Removes name 'de' from MFT and from directory.
 * 'de2' and 'undo_step' are used to restore MFT/dir, if error occurs.
 */
int ni_remove_name(struct ntfs_inode *dir_ni, struct ntfs_inode *ni,
		   struct NTFS_DE *de, struct NTFS_DE **de2, int *undo_step)
{
	int err;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	struct ATTR_FILE_NAME *de_name = (struct ATTR_FILE_NAME *)(de + 1);
	struct ATTR_FILE_NAME *fname;
	struct ATTR_LIST_ENTRY *le;
	struct mft_inode *mi;
	u16 de_key_size = le16_to_cpu(de->key_size);
	u8 name_type;

	*undo_step = 0;

	/* Find name in record. */
	mi_get_ref(&dir_ni->mi, &de_name->home);

	fname = ni_fname_name(ni, (struct cpu_str *)&de_name->name_len,
			      &de_name->home, &mi, &le);
	if (!fname)
		return -ENOENT;

	memcpy(&de_name->dup, &fname->dup, sizeof(struct NTFS_DUP_INFO));
	name_type = paired_name(fname->type);

	/* Mark ntfs as dirty. It will be cleared at umount. */
	ntfs_set_state(sbi, NTFS_DIRTY_DIRTY);

	/* Step 1: Remove name from directory. */
	err = indx_delete_entry(&dir_ni->dir, dir_ni, fname, de_key_size, sbi);
	if (err)
		return err;

	/* Step 2: Remove name from MFT. */
	ni_remove_attr_le(ni, attr_from_name(fname), mi, le);

	*undo_step = 2;

	/* Get paired name. */
	fname = ni_fname_type(ni, name_type, &mi, &le);
	if (fname) {
		u16 de2_key_size = fname_full_size(fname);

		*de2 = Add2Ptr(de, 1024);
		(*de2)->key_size = cpu_to_le16(de2_key_size);

		memcpy(*de2 + 1, fname, de2_key_size);

		/* Step 3: Remove paired name from directory. */
		err = indx_delete_entry(&dir_ni->dir, dir_ni, fname,
					de2_key_size, sbi);
		if (err)
			return err;

		/* Step 4: Remove paired name from MFT. */
		ni_remove_attr_le(ni, attr_from_name(fname), mi, le);

		*undo_step = 4;
	}
	return 0;
}

/*
 * ni_remove_name_undo - Paired function for ni_remove_name.
 *
 * Return: True if ok
 */
bool ni_remove_name_undo(struct ntfs_inode *dir_ni, struct ntfs_inode *ni,
			 struct NTFS_DE *de, struct NTFS_DE *de2, int undo_step)
{
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	struct ATTRIB *attr;
	u16 de_key_size = de2 ? le16_to_cpu(de2->key_size) : 0;

	switch (undo_step) {
	case 4:
		if (ni_insert_resident(ni, de_key_size, ATTR_NAME, NULL, 0,
				       &attr, NULL, NULL)) {
			return false;
		}
		memcpy(Add2Ptr(attr, SIZEOF_RESIDENT), de2 + 1, de_key_size);

		mi_get_ref(&ni->mi, &de2->ref);
		de2->size = cpu_to_le16(ALIGN(de_key_size, 8) +
					sizeof(struct NTFS_DE));
		de2->flags = 0;
		de2->res = 0;

		if (indx_insert_entry(&dir_ni->dir, dir_ni, de2, sbi, NULL,
				      1)) {
			return false;
		}
		/* fall through */

	case 2:
		de_key_size = le16_to_cpu(de->key_size);

		if (ni_insert_resident(ni, de_key_size, ATTR_NAME, NULL, 0,
				       &attr, NULL, NULL)) {
			return false;
		}

		memcpy(Add2Ptr(attr, SIZEOF_RESIDENT), de + 1, de_key_size);
		mi_get_ref(&ni->mi, &de->ref);

		if (indx_insert_entry(&dir_ni->dir, dir_ni, de, sbi, NULL, 1)) {
			return false;
		}
	}

	return true;
}

/*
 * ni_add_name - Add new name in MFT and in directory.
 */
int ni_add_name(struct ntfs_inode *dir_ni, struct ntfs_inode *ni,
		struct NTFS_DE *de)
{
	int err;
	struct ATTRIB *attr;
	struct ATTR_LIST_ENTRY *le;
	struct mft_inode *mi;
	struct ATTR_FILE_NAME *de_name = (struct ATTR_FILE_NAME *)(de + 1);
	u16 de_key_size = le16_to_cpu(de->key_size);

	mi_get_ref(&ni->mi, &de->ref);
	mi_get_ref(&dir_ni->mi, &de_name->home);

	/* Insert new name in MFT. */
	err = ni_insert_resident(ni, de_key_size, ATTR_NAME, NULL, 0, &attr,
				 &mi, &le);
	if (err)
		return err;

	memcpy(Add2Ptr(attr, SIZEOF_RESIDENT), de_name, de_key_size);

	/* Insert new name in directory. */
	err = indx_insert_entry(&dir_ni->dir, dir_ni, de, ni->mi.sbi, NULL, 0);
	if (err)
		ni_remove_attr_le(ni, attr, mi, le);
>>>>>>> wip

	return err;
}

/*
<<<<<<< HEAD
 * ni_write_inode
 *
 * write mft base record and all subrecords to disk
 */
int ni_write_inode(struct inode *inode, int sync, const char *hint)
{
	int err = 0, err2;
	ntfs_inode *ni = ntfs_i(inode);
	struct super_block *sb = inode->i_sb;
	ntfs_sb_info *sbi = sb->s_fs_info;
	bool modified, re_dirty = false;
	mft_inode *mi;
	MFT_REC *rec;
	ATTR_STD_INFO *std;
	struct rb_node *node, *next;
	ATTR_LIST_ENTRY *le;
	ATTRIB *attr;
	NTFS_DUP_INFO dup;
	bool is_meta;

	if (is_bad_inode(inode))
		return 0;

	if (!ni_trylock(ni)) {
		/* 'ni' is under modification, skip for now */
		return 0;
	}

	is_meta = ntfs_is_meta_file(sbi, inode->i_ino);
	rec = ni->mi.mrec;

	if (!is_rec_inuse(rec) || (sbi->flags & NTFS_FLAGS_LOG_REPLAING))
		goto write_subrecords;

	if (!inode->i_nlink)
		goto write_subrecords;

	/* update times in standard attribute */
	std = ni_std(ni);
	if (!std) {
		err = -EINVAL;
		goto out;
	}

	modified = false;
	/* Update the access times if they have changed. */
	dup.m_time = kernel2nt(&inode->i_mtime);
	if (std->m_time != dup.m_time) {
		std->m_time = dup.m_time;
		modified = true;
	}

	dup.c_time = kernel2nt(&inode->i_ctime);
	if (std->c_time != dup.c_time) {
		std->c_time = dup.c_time;
		modified = true;
	}

	dup.a_time = kernel2nt(&inode->i_atime);
	if (std->a_time != dup.a_time) {
		std->a_time = dup.a_time;
		modified = true;
	}

	dup.fa = ni->std_fa;
	if (std->fa != dup.fa) {
		std->fa = dup.fa;
		modified = true;
	}

	if (is_meta || (!modified && !(ni->ni_flags & NI_FLAG_UPDATE_PARENT)))
		goto skip_dir_update;

	dup.cr_time = std->cr_time;
	le = NULL;

	if (ni->mi.mrec->flags & RECORD_FLAG_DIR) {
		dup.fa |= FILE_ATTRIBUTE_DIRECTORY;
		attr = NULL;
		dup.alloc_size = 0;
		dup.data_size = 0;
	} else {
		dup.fa &= ~FILE_ATTRIBUTE_DIRECTORY;

		attr = ni_find_attr(ni, NULL, &le, ATTR_DATA, NULL, 0, NULL,
				    &mi);
		if (!attr)
			dup.alloc_size = dup.data_size = 0;
		else if (!attr->non_res) {
			u32 data_size = le32_to_cpu(attr->res.data_size);

			dup.alloc_size = cpu_to_le64(QuadAlign(data_size));
			dup.data_size = cpu_to_le64(data_size);
		} else {
			u64 new_valid = ni->i_valid;
			u64 data_size = le64_to_cpu(attr->nres.data_size);

			dup.alloc_size = is_attr_ext(attr) ?
						 attr->nres.total_size :
						 attr->nres.alloc_size;
			dup.data_size = attr->nres.data_size;

			if (new_valid > data_size)
				new_valid = data_size;
			if (new_valid != le64_to_cpu(attr->nres.valid_size)) {
				attr->nres.valid_size = cpu_to_le64(new_valid);
=======
 * ni_rename - Remove one name and insert new name.
 */
int ni_rename(struct ntfs_inode *dir_ni, struct ntfs_inode *new_dir_ni,
	      struct ntfs_inode *ni, struct NTFS_DE *de, struct NTFS_DE *new_de,
	      bool *is_bad)
{
	int err;
	struct NTFS_DE *de2 = NULL;
	int undo = 0;

	/*
	 * There are two possible ways to rename:
	 * 1) Add new name and remove old name.
	 * 2) Remove old name and add new name.
	 *
	 * In most cases (not all!) adding new name in MFT and in directory can
	 * allocate additional cluster(s).
	 * Second way may result to bad inode if we can't add new name
	 * and then can't restore (add) old name.
	 */

	/*
	 * Way 1 - Add new + remove old.
	 */
	err = ni_add_name(new_dir_ni, ni, new_de);
	if (!err) {
		err = ni_remove_name(dir_ni, ni, de, &de2, &undo);
		if (err && ni_remove_name(new_dir_ni, ni, new_de, &de2, &undo))
			*is_bad = true;
	}

	/*
	 * Way 2 - Remove old + add new.
	 */
	/*
	 *	err = ni_remove_name(dir_ni, ni, de, &de2, &undo);
	 *	if (!err) {
	 *		err = ni_add_name(new_dir_ni, ni, new_de);
	 *		if (err && !ni_remove_name_undo(dir_ni, ni, de, de2, undo))
	 *			*is_bad = true;
	 *	}
	 */

	return err;
}

/*
 * ni_is_dirty - Return: True if 'ni' requires ni_write_inode.
 */
bool ni_is_dirty(struct inode *inode)
{
	struct ntfs_inode *ni = ntfs_i(inode);
	struct rb_node *node;

	if (ni->mi.dirty || ni->attr_list.dirty ||
	    (ni->ni_flags & NI_FLAG_UPDATE_PARENT))
		return true;

	for (node = rb_first(&ni->mi_tree); node; node = rb_next(node)) {
		if (rb_entry(node, struct mft_inode, node)->dirty)
			return true;
	}

	return false;
}

/*
 * ni_update_parent
 *
 * Update duplicate info of ATTR_FILE_NAME in MFT and in parent directories.
 */
static bool ni_update_parent(struct ntfs_inode *ni, struct NTFS_DUP_INFO *dup,
			     int sync)
{
	struct ATTRIB *attr;
	struct mft_inode *mi;
	struct ATTR_LIST_ENTRY *le = NULL;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	struct super_block *sb = sbi->sb;
	bool re_dirty = false;

	if (ni->mi.mrec->flags & RECORD_FLAG_DIR) {
		dup->fa |= FILE_ATTRIBUTE_DIRECTORY;
		attr = NULL;
		dup->alloc_size = 0;
		dup->data_size = 0;
	} else {
		dup->fa &= ~FILE_ATTRIBUTE_DIRECTORY;

		attr = ni_find_attr(ni, NULL, &le, ATTR_DATA, NULL, 0, NULL,
				    &mi);
		if (!attr) {
			dup->alloc_size = dup->data_size = 0;
		} else if (!attr->non_res) {
			u32 data_size = le32_to_cpu(attr->res.data_size);

			dup->alloc_size = cpu_to_le64(ALIGN(data_size, 8));
			dup->data_size = cpu_to_le64(data_size);
		} else {
			u64 new_valid = ni->i_valid;
			u64 data_size = le64_to_cpu(attr->nres.data_size);
			__le64 valid_le;

			dup->alloc_size = is_attr_ext(attr)
						  ? attr->nres.total_size
						  : attr->nres.alloc_size;
			dup->data_size = attr->nres.data_size;

			if (new_valid > data_size)
				new_valid = data_size;

			valid_le = cpu_to_le64(new_valid);
			if (valid_le != attr->nres.valid_size) {
				attr->nres.valid_size = valid_le;
>>>>>>> wip
				mi->dirty = true;
			}
		}
	}

<<<<<<< HEAD
	/* TODO: fill reparse info */
	dup.reparse = 0;
	dup.ea_size = 0;
=======
	/* TODO: Fill reparse info. */
	dup->reparse = 0;
	dup->ea_size = 0;
>>>>>>> wip

	if (ni->ni_flags & NI_FLAG_EA) {
		attr = ni_find_attr(ni, attr, &le, ATTR_EA_INFO, NULL, 0, NULL,
				    NULL);
		if (attr) {
<<<<<<< HEAD
			const EA_INFO *info =
				resident_data_ex(attr, sizeof(EA_INFO));

			dup.ea_size = info->size_pack;
=======
			const struct EA_INFO *info;

			info = resident_data_ex(attr, sizeof(struct EA_INFO));
			dup->ea_size = info->size_pack;
>>>>>>> wip
		}
	}

	attr = NULL;
	le = NULL;

	while ((attr = ni_find_attr(ni, attr, &le, ATTR_NAME, NULL, 0, NULL,
				    &mi))) {
		struct inode *dir;
<<<<<<< HEAD
		ATTR_FILE_NAME *fname;

		fname = resident_data_ex(attr, SIZEOF_ATTRIBUTE_FILENAME);
		if (!fname)
			continue;

		if (!memcmp(&fname->dup, &dup, sizeof(fname->dup)))
			continue;

		dir = ntfs_iget5(sb, &fname->home, NULL);

		if (IS_ERR(dir)) {
			;
		} else if (is_bad_inode(dir)) {
			iput(dir);
		} else {
			ntfs_inode *dir_ni = ntfs_i(dir);

			if (!ni_trylock(dir_ni)) {
				re_dirty = true;
				iput(dir);
				break;
			}

			indx_update_dup(dir_ni, sbi, fname, &dup, sync);

			ni_unlock(dir_ni);
			iput(dir);
		}

		memcpy(&fname->dup, &dup, sizeof(fname->dup));
		mi->dirty = true;
	}

	if (re_dirty)
		ni->ni_flags |= NI_FLAG_UPDATE_PARENT;
	else
		ni->ni_flags &= ~NI_FLAG_UPDATE_PARENT;

skip_dir_update:
	err = al_update(ni);
	if (err)
		goto out;

write_subrecords:
	for (node = rb_first(&ni->mi_tree); node; node = next) {
		mft_inode *mi = rb_entry(node, mft_inode, node);
=======
		struct ATTR_FILE_NAME *fname;

		fname = resident_data_ex(attr, SIZEOF_ATTRIBUTE_FILENAME);
		if (!fname || !memcmp(&fname->dup, dup, sizeof(fname->dup)))
			continue;

		/* ntfs_iget5 may sleep. */
		dir = ntfs_iget5(sb, &fname->home, NULL);
		if (IS_ERR(dir)) {
			ntfs_inode_warn(
				&ni->vfs_inode,
				"failed to open parent directory r=%lx to update",
				(long)ino_get(&fname->home));
			continue;
		}

		if (!is_bad_inode(dir)) {
			struct ntfs_inode *dir_ni = ntfs_i(dir);

			if (!ni_trylock(dir_ni)) {
				re_dirty = true;
			} else {
				indx_update_dup(dir_ni, sbi, fname, dup, sync);
				ni_unlock(dir_ni);
				memcpy(&fname->dup, dup, sizeof(fname->dup));
				mi->dirty = true;
			}
		}
		iput(dir);
	}

	return re_dirty;
}

/*
 * ni_write_inode - Write MFT base record and all subrecords to disk.
 */
int ni_write_inode(struct inode *inode, int sync, const char *hint)
{
	int err = 0, err2;
	struct ntfs_inode *ni = ntfs_i(inode);
	struct super_block *sb = inode->i_sb;
	struct ntfs_sb_info *sbi = sb->s_fs_info;
	bool re_dirty = false;
	struct ATTR_STD_INFO *std;
	struct rb_node *node, *next;
	struct NTFS_DUP_INFO dup;

	if (is_bad_inode(inode) || sb_rdonly(sb))
		return 0;

	if (!ni_trylock(ni)) {
		/* 'ni' is under modification, skip for now. */
		mark_inode_dirty_sync(inode);
		return 0;
	}

	if (is_rec_inuse(ni->mi.mrec) &&
	    !(sbi->flags & NTFS_FLAGS_LOG_REPLAYING) && inode->i_nlink) {
		bool modified = false;

		/* Update times in standard attribute. */
		std = ni_std(ni);
		if (!std) {
			err = -EINVAL;
			goto out;
		}

		/* Update the access times if they have changed. */
		dup.m_time = kernel2nt(&inode->i_mtime);
		if (std->m_time != dup.m_time) {
			std->m_time = dup.m_time;
			modified = true;
		}

		dup.c_time = kernel2nt(&inode->i_ctime);
		if (std->c_time != dup.c_time) {
			std->c_time = dup.c_time;
			modified = true;
		}

		dup.a_time = kernel2nt(&inode->i_atime);
		if (std->a_time != dup.a_time) {
			std->a_time = dup.a_time;
			modified = true;
		}

		dup.fa = ni->std_fa;
		if (std->fa != dup.fa) {
			std->fa = dup.fa;
			modified = true;
		}

		if (modified)
			ni->mi.dirty = true;

		if (!ntfs_is_meta_file(sbi, inode->i_ino) &&
		    (modified || (ni->ni_flags & NI_FLAG_UPDATE_PARENT))
		    /* Avoid __wait_on_freeing_inode(inode). */
		    && (sb->s_flags & SB_ACTIVE)) {
			dup.cr_time = std->cr_time;
			/* Not critical if this function fail. */
			re_dirty = ni_update_parent(ni, &dup, sync);

			if (re_dirty)
				ni->ni_flags |= NI_FLAG_UPDATE_PARENT;
			else
				ni->ni_flags &= ~NI_FLAG_UPDATE_PARENT;
		}

		/* Update attribute list. */
		if (ni->attr_list.size && ni->attr_list.dirty) {
			if (inode->i_ino != MFT_REC_MFT || sync) {
				err = ni_try_remove_attr_list(ni);
				if (err)
					goto out;
			}

			err = al_update(ni);
			if (err)
				goto out;
		}
	}

	for (node = rb_first(&ni->mi_tree); node; node = next) {
		struct mft_inode *mi = rb_entry(node, struct mft_inode, node);
>>>>>>> wip
		bool is_empty;

		next = rb_next(node);

		if (!mi->dirty)
			continue;

		is_empty = !mi_enum_attr(mi, NULL);

		if (is_empty)
			clear_rec_inuse(mi->mrec);

		err2 = mi_write(mi, sync);
		if (!err && err2)
			err = err2;

		if (is_empty) {
			ntfs_mark_rec_free(sbi, mi->rno);
			rb_erase(node, &ni->mi_tree);
			mi_put(mi);
		}
	}

<<<<<<< HEAD
	if (modified || ni->mi.dirty) {
=======
	if (ni->mi.dirty) {
>>>>>>> wip
		err2 = mi_write(&ni->mi, sync);
		if (!err && err2)
			err = err2;
	}
<<<<<<< HEAD

=======
>>>>>>> wip
out:
	ni_unlock(ni);

	if (err) {
<<<<<<< HEAD
		ntfs_error(sb, "%s r=%lx failed, %d.", hint, inode->i_ino, err);
=======
		ntfs_err(sb, "%s r=%lx failed, %d.", hint, inode->i_ino, err);
>>>>>>> wip
		ntfs_set_state(sbi, NTFS_DIRTY_ERROR);
		return err;
	}

<<<<<<< HEAD
	if (re_dirty && (sb->s_flags & SB_ACTIVE))
		mark_inode_dirty_sync(inode);

	if (inode->i_ino < sbi->mft.recs_mirr)
		sbi->flags |= NTFS_FLAGS_MFTMIRR;
=======
	if (re_dirty)
		mark_inode_dirty_sync(inode);

>>>>>>> wip
	return 0;
}
