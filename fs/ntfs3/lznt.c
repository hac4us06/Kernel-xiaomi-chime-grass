// SPDX-License-Identifier: GPL-2.0
/*
<<<<<<< HEAD
 *  linux/fs/ntfs3/lznt.c
 *
 * Copyright (C) 2019-2020 Paragon Software GmbH, All rights reserved.
 *
 */
=======
 *
 * Copyright (C) 2019-2021 Paragon Software GmbH, All rights reserved.
 *
 */

>>>>>>> wip
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/nls.h>
<<<<<<< HEAD
#include <linux/sched/signal.h>
=======
>>>>>>> wip

#include "debug.h"
#include "ntfs.h"
#include "ntfs_fs.h"

<<<<<<< HEAD
/* Dst buffer is too small */
#define LZNT_ERROR_TOOSMALL -2
/* src buffer is zero */
#define LZNT_ERROR_ALL_ZEROS 1
#define LZNT_CHUNK_SIZE 0x1000
=======
// clang-format off
/* Src buffer is zero. */
#define LZNT_ERROR_ALL_ZEROS	1
#define LZNT_CHUNK_SIZE		0x1000
// clang-format on
>>>>>>> wip

struct lznt_hash {
	const u8 *p1;
	const u8 *p2;
};

struct lznt {
	const u8 *unc;
	const u8 *unc_end;
	const u8 *best_match;
	size_t max_len;
	bool std;

	struct lznt_hash hash[LZNT_CHUNK_SIZE];
};

static inline size_t get_match_len(const u8 *ptr, const u8 *end, const u8 *prev,
				   size_t max_len)
{
	size_t len = 0;

	while (ptr + len < end && ptr[len] == prev[len] && ++len < max_len)
		;
	return len;
}

static size_t longest_match_std(const u8 *src, struct lznt *ctx)
{
	size_t hash_index;
	size_t len1 = 0, len2 = 0;
	const u8 **hash;

	hash_index =
		((40543U * ((((src[0] << 4) ^ src[1]) << 4) ^ src[2])) >> 4) &
		(LZNT_CHUNK_SIZE - 1);

	hash = &(ctx->hash[hash_index].p1);

	if (hash[0] >= ctx->unc && hash[0] < src && hash[0][0] == src[0] &&
	    hash[0][1] == src[1] && hash[0][2] == src[2]) {
		len1 = 3;
		if (ctx->max_len > 3)
			len1 += get_match_len(src + 3, ctx->unc_end,
					      hash[0] + 3, ctx->max_len - 3);
	}

	if (hash[1] >= ctx->unc && hash[1] < src && hash[1][0] == src[0] &&
	    hash[1][1] == src[1] && hash[1][2] == src[2]) {
		len2 = 3;
		if (ctx->max_len > 3)
			len2 += get_match_len(src + 3, ctx->unc_end,
					      hash[1] + 3, ctx->max_len - 3);
	}

<<<<<<< HEAD
	/* Compare two matches and select the best one */
	if (len1 < len2) {
		ctx->best_match = hash[1];
		len1 = len2;
	} else
		ctx->best_match = hash[0];
=======
	/* Compare two matches and select the best one. */
	if (len1 < len2) {
		ctx->best_match = hash[1];
		len1 = len2;
	} else {
		ctx->best_match = hash[0];
	}
>>>>>>> wip

	hash[1] = hash[0];
	hash[0] = src;
	return len1;
}

static size_t longest_match_best(const u8 *src, struct lznt *ctx)
{
	size_t max_len;
	const u8 *ptr;

	if (ctx->unc >= src || !ctx->max_len)
		return 0;

	max_len = 0;
	for (ptr = ctx->unc; ptr < src; ++ptr) {
		size_t len =
			get_match_len(src, ctx->unc_end, ptr, ctx->max_len);
		if (len >= max_len) {
			max_len = len;
			ctx->best_match = ptr;
		}
	}

	return max_len >= 3 ? max_len : 0;
}

static const size_t s_max_len[] = {
	0x1002, 0x802, 0x402, 0x202, 0x102, 0x82, 0x42, 0x22, 0x12,
};

static const size_t s_max_off[] = {
	0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000,
};

static inline u16 make_pair(size_t offset, size_t len, size_t index)
{
	return ((offset - 1) << (12 - index)) |
	       ((len - 3) & (((1 << (12 - index)) - 1)));
}

static inline size_t parse_pair(u16 pair, size_t *offset, size_t index)
{
	*offset = 1 + (pair >> (12 - index));
	return 3 + (pair & ((1 << (12 - index)) - 1));
}

<<<<<<< HEAD
// 0x3FFF
#define HeaderOfNonCompressedChunk ((LZNT_CHUNK_SIZE + 2 - 3) | 0x3000)

/*
 * compess_chunk
 *
 * returns one of the tree values:
 * 0 - ok, 'cmpr' contains 'cmpr_chunk_size' bytes of compressed data
 * 1 == LZNT_ERROR_ALL_ZEROS - input buffer is full zero
 * -2 == LZNT_ERROR_TOOSMALL
 */
static inline int compess_chunk(size_t (*match)(const u8 *, struct lznt *),
				const u8 *unc, const u8 *unc_end, u8 *cmpr,
				u8 *cmpr_end, size_t *cmpr_chunk_size,
				struct lznt *ctx)
=======
/*
 * compress_chunk
 *
 * Return:
 * * 0	- Ok, @cmpr contains @cmpr_chunk_size bytes of compressed data.
 * * 1	- Input buffer is full zero.
 * * -2 - The compressed buffer is too small to hold the compressed data.
 */
static inline int compress_chunk(size_t (*match)(const u8 *, struct lznt *),
				 const u8 *unc, const u8 *unc_end, u8 *cmpr,
				 u8 *cmpr_end, size_t *cmpr_chunk_size,
				 struct lznt *ctx)
>>>>>>> wip
{
	size_t cnt = 0;
	size_t idx = 0;
	const u8 *up = unc;
	u8 *cp = cmpr + 3;
	u8 *cp2 = cmpr + 2;
	u8 not_zero = 0;
<<<<<<< HEAD
	/* Control byte of 8-bit values: ( 0 - means byte as is, 1 - short pair ) */
=======
	/* Control byte of 8-bit values: ( 0 - means byte as is, 1 - short pair ). */
>>>>>>> wip
	u8 ohdr = 0;
	u8 *last;
	u16 t16;

	if (unc + LZNT_CHUNK_SIZE < unc_end)
		unc_end = unc + LZNT_CHUNK_SIZE;

	last = min(cmpr + LZNT_CHUNK_SIZE + sizeof(short), cmpr_end);

	ctx->unc = unc;
	ctx->unc_end = unc_end;
	ctx->max_len = s_max_len[0];

	while (up < unc_end) {
		size_t max_len;

		while (unc + s_max_off[idx] < up)
			ctx->max_len = s_max_len[++idx];

<<<<<<< HEAD
		// Find match
=======
		/* Find match. */
>>>>>>> wip
		max_len = up + 3 <= unc_end ? (*match)(up, ctx) : 0;

		if (!max_len) {
			if (cp >= last)
				goto NotCompressed;
			not_zero |= *cp++ = *up++;
		} else if (cp + 1 >= last) {
			goto NotCompressed;
		} else {
			t16 = make_pair(up - ctx->best_match, max_len, idx);
			*cp++ = t16;
			*cp++ = t16 >> 8;

			ohdr |= 1 << cnt;
			up += max_len;
		}

		cnt = (cnt + 1) & 7;
		if (!cnt) {
			*cp2 = ohdr;
			ohdr = 0;
			cp2 = cp;
			cp += 1;
		}
	}

	if (cp2 < last)
		*cp2 = ohdr;
	else
		cp -= 1;

	*cmpr_chunk_size = cp - cmpr;

	t16 = (*cmpr_chunk_size - 3) | 0xB000;
	cmpr[0] = t16;
	cmpr[1] = t16 >> 8;

	return not_zero ? 0 : LZNT_ERROR_ALL_ZEROS;

NotCompressed:

	if ((cmpr + LZNT_CHUNK_SIZE + sizeof(short)) > last)
<<<<<<< HEAD
		return LZNT_ERROR_TOOSMALL;

	/* Copy non cmpr data */
=======
		return -2;

	/*
	 * Copy non cmpr data.
	 * 0x3FFF == ((LZNT_CHUNK_SIZE + 2 - 3) | 0x3000)
	 */
>>>>>>> wip
	cmpr[0] = 0xff;
	cmpr[1] = 0x3f;

	memcpy(cmpr + sizeof(short), unc, LZNT_CHUNK_SIZE);
	*cmpr_chunk_size = LZNT_CHUNK_SIZE + sizeof(short);

	return 0;
}

static inline ssize_t decompress_chunk(u8 *unc, u8 *unc_end, const u8 *cmpr,
				       const u8 *cmpr_end)
{
	u8 *up = unc;
	u8 ch = *cmpr++;
	size_t bit = 0;
	size_t index = 0;
	u16 pair;
	size_t offset, length;

<<<<<<< HEAD
	/* Do decompression until pointers are inside range */
=======
	/* Do decompression until pointers are inside range. */
>>>>>>> wip
	while (up < unc_end && cmpr < cmpr_end) {
		/* Correct index */
		while (unc + s_max_off[index] < up)
			index += 1;

<<<<<<< HEAD
		/* Check the current flag for zero */
		if (!(ch & (1 << bit))) {
			/* Just copy byte */
=======
		/* Check the current flag for zero. */
		if (!(ch & (1 << bit))) {
			/* Just copy byte. */
>>>>>>> wip
			*up++ = *cmpr++;
			goto next;
		}

<<<<<<< HEAD
		/* Check for boundary */
		if (cmpr + 1 >= cmpr_end)
			return -EINVAL;

		/* Read a short from little endian stream */
=======
		/* Check for boundary. */
		if (cmpr + 1 >= cmpr_end)
			return -EINVAL;

		/* Read a short from little endian stream. */
>>>>>>> wip
		pair = cmpr[1];
		pair <<= 8;
		pair |= cmpr[0];

		cmpr += 2;

<<<<<<< HEAD
		/* Translate packed information into offset and length */
		length = parse_pair(pair, &offset, index);

		/* Check offset for boundary */
		if (unc + offset > up)
			return -EINVAL;

		/* Truncate the length if necessary */
=======
		/* Translate packed information into offset and length. */
		length = parse_pair(pair, &offset, index);

		/* Check offset for boundary. */
		if (unc + offset > up)
			return -EINVAL;

		/* Truncate the length if necessary. */
>>>>>>> wip
		if (up + length >= unc_end)
			length = unc_end - up;

		/* Now we copy bytes. This is the heart of LZ algorithm. */
		for (; length > 0; length--, up++)
			*up = *(up - offset);

next:
<<<<<<< HEAD
		/* Advance flag bit value */
=======
		/* Advance flag bit value. */
>>>>>>> wip
		bit = (bit + 1) & 7;

		if (!bit) {
			if (cmpr >= cmpr_end)
				break;

			ch = *cmpr++;
		}
	}

<<<<<<< HEAD
	/* return the size of uncompressed data */
	return up - unc;
}

struct lznt *get_compression_ctx(bool std)
{
	struct lznt *r = ntfs_alloc(
		std ? sizeof(struct lznt) : offsetof(struct lznt, hash), 1);

	if (r)
		r->std = std;
=======
	/* Return the size of uncompressed data. */
	return up - unc;
}

/*
 * get_lznt_ctx
 * @level: 0 - Standard compression.
 * 	   !0 - Best compression, requires a lot of cpu.
 */
struct lznt *get_lznt_ctx(int level)
{
	struct lznt *r = kzalloc(level ? offsetof(struct lznt, hash)
				       : sizeof(struct lznt),
				 GFP_NOFS);

	if (r)
		r->std = !level;
>>>>>>> wip
	return r;
}

/*
<<<<<<< HEAD
 * compress_lznt
 *
 * Compresses "unc" into "cmpr"
 * +x - ok, 'cmpr' contains 'final_compressed_size' bytes of compressed data
 * 0 - input buffer is full zero
=======
 * compress_lznt - Compresses @unc into @cmpr
 *
 * Return:
 * * +x - Ok, @cmpr contains 'final_compressed_size' bytes of compressed data.
 * * 0 - Input buffer is full zero.
>>>>>>> wip
 */
size_t compress_lznt(const void *unc, size_t unc_size, void *cmpr,
		     size_t cmpr_size, struct lznt *ctx)
{
	int err;
	size_t (*match)(const u8 *src, struct lznt *ctx);
	u8 *p = cmpr;
	u8 *end = p + cmpr_size;
	const u8 *unc_chunk = unc;
	const u8 *unc_end = unc_chunk + unc_size;
	bool is_zero = true;

	if (ctx->std) {
		match = &longest_match_std;
		memset(ctx->hash, 0, sizeof(ctx->hash));
	} else {
		match = &longest_match_best;
	}

<<<<<<< HEAD
	/* compression cycle */
	for (; unc_chunk < unc_end; unc_chunk += LZNT_CHUNK_SIZE) {
		cmpr_size = 0;
		err = compess_chunk(match, unc_chunk, unc_end, p, end,
				    &cmpr_size, ctx);
=======
	/* Compression cycle. */
	for (; unc_chunk < unc_end; unc_chunk += LZNT_CHUNK_SIZE) {
		cmpr_size = 0;
		err = compress_chunk(match, unc_chunk, unc_end, p, end,
				     &cmpr_size, ctx);
>>>>>>> wip
		if (err < 0)
			return unc_size;

		if (is_zero && err != LZNT_ERROR_ALL_ZEROS)
			is_zero = false;

		p += cmpr_size;
	}

	if (p <= end - 2)
		p[0] = p[1] = 0;

	return is_zero ? 0 : PtrOffset(cmpr, p);
}

/*
<<<<<<< HEAD
 * decompress_lznt
 *
 * decompresses "cmpr" into "unc"
=======
 * decompress_lznt - Decompress @cmpr into @unc.
>>>>>>> wip
 */
ssize_t decompress_lznt(const void *cmpr, size_t cmpr_size, void *unc,
			size_t unc_size)
{
	const u8 *cmpr_chunk = cmpr;
	const u8 *cmpr_end = cmpr_chunk + cmpr_size;
	u8 *unc_chunk = unc;
	u8 *unc_end = unc_chunk + unc_size;
	u16 chunk_hdr;

	if (cmpr_size < sizeof(short))
		return -EINVAL;

<<<<<<< HEAD
	/* read chunk header */
=======
	/* Read chunk header. */
>>>>>>> wip
	chunk_hdr = cmpr_chunk[1];
	chunk_hdr <<= 8;
	chunk_hdr |= cmpr_chunk[0];

<<<<<<< HEAD
	/* loop through decompressing chunks */
=======
	/* Loop through decompressing chunks. */
>>>>>>> wip
	for (;;) {
		size_t chunk_size_saved;
		size_t unc_use;
		size_t cmpr_use = 3 + (chunk_hdr & (LZNT_CHUNK_SIZE - 1));

<<<<<<< HEAD
		/* Check that the chunk actually fits the supplied buffer */
		if (cmpr_chunk + cmpr_use > cmpr_end)
			return -EINVAL;

		/* First make sure the chunk contains compressed data */
		if (chunk_hdr & 0x8000) {
			/* Decompress a chunk and return if we get an error */
=======
		/* Check that the chunk actually fits the supplied buffer. */
		if (cmpr_chunk + cmpr_use > cmpr_end)
			return -EINVAL;

		/* First make sure the chunk contains compressed data. */
		if (chunk_hdr & 0x8000) {
			/* Decompress a chunk and return if we get an error. */
>>>>>>> wip
			ssize_t err =
				decompress_chunk(unc_chunk, unc_end,
						 cmpr_chunk + sizeof(chunk_hdr),
						 cmpr_chunk + cmpr_use);
			if (err < 0)
				return err;
			unc_use = err;
		} else {
<<<<<<< HEAD
			/* This chunk does not contain compressed data */
			unc_use = unc_chunk + LZNT_CHUNK_SIZE > unc_end ?
					  unc_end - unc_chunk :
					  LZNT_CHUNK_SIZE;
=======
			/* This chunk does not contain compressed data. */
			unc_use = unc_chunk + LZNT_CHUNK_SIZE > unc_end
					  ? unc_end - unc_chunk
					  : LZNT_CHUNK_SIZE;
>>>>>>> wip

			if (cmpr_chunk + sizeof(chunk_hdr) + unc_use >
			    cmpr_end) {
				return -EINVAL;
			}

			memcpy(unc_chunk, cmpr_chunk + sizeof(chunk_hdr),
			       unc_use);
		}

<<<<<<< HEAD
		/* Advance pointers */
		cmpr_chunk += cmpr_use;
		unc_chunk += unc_use;

		/* Check for the end of unc buffer */
		if (unc_chunk >= unc_end)
			break;

		/* Proceed the next chunk */
=======
		/* Advance pointers. */
		cmpr_chunk += cmpr_use;
		unc_chunk += unc_use;

		/* Check for the end of unc buffer. */
		if (unc_chunk >= unc_end)
			break;

		/* Proceed the next chunk. */
>>>>>>> wip
		if (cmpr_chunk > cmpr_end - 2)
			break;

		chunk_size_saved = LZNT_CHUNK_SIZE;

<<<<<<< HEAD
		/* read chunk header */
=======
		/* Read chunk header. */
>>>>>>> wip
		chunk_hdr = cmpr_chunk[1];
		chunk_hdr <<= 8;
		chunk_hdr |= cmpr_chunk[0];

		if (!chunk_hdr)
			break;

<<<<<<< HEAD
		/* Check the size of unc buffer */
=======
		/* Check the size of unc buffer. */
>>>>>>> wip
		if (unc_use < chunk_size_saved) {
			size_t t1 = chunk_size_saved - unc_use;
			u8 *t2 = unc_chunk + t1;

<<<<<<< HEAD
			/* 'Zero' memory */
=======
			/* 'Zero' memory. */
>>>>>>> wip
			if (t2 >= unc_end)
				break;

			memset(unc_chunk, 0, t1);
			unc_chunk = t2;
		}
	}

<<<<<<< HEAD
	/* Check compression boundary */
=======
	/* Check compression boundary. */
>>>>>>> wip
	if (cmpr_chunk > cmpr_end)
		return -EINVAL;

	/*
	 * The unc size is just a difference between current
<<<<<<< HEAD
	 * pointer and original one
=======
	 * pointer and original one.
>>>>>>> wip
	 */
	return PtrOffset(unc, unc_chunk);
}
