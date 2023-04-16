// SPDX-License-Identifier: GPL-2.0
/*
<<<<<<< HEAD
 *  linux/fs/ntfs3/bitfunc.c
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

#define BITS_IN_SIZE_T (sizeof(size_t) * 8)

/*
 * fill_mask[i] - first i bits are '1' , i = 0,1,2,3,4,5,6,7,8
 * fill_mask[i] = 0xFF >> (8-i)
 */
static const u8 fill_mask[] = { 0x00, 0x01, 0x03, 0x07, 0x0F,
				0x1F, 0x3F, 0x7F, 0xFF };

/*
 * zero_mask[i] - first i bits are '0' , i = 0,1,2,3,4,5,6,7,8
 * zero_mask[i] = 0xFF << i
 */
static const u8 zero_mask[] = { 0xFF, 0xFE, 0xFC, 0xF8, 0xF0,
				0xE0, 0xC0, 0x80, 0x00 };

/*
 * are_bits_clear
 *
<<<<<<< HEAD
 * Returns true if all bits [bit, bit+nbits) are zeros "0"
=======
 * Return: True if all bits [bit, bit+nbits) are zeros "0".
>>>>>>> wip
 */
bool are_bits_clear(const ulong *lmap, size_t bit, size_t nbits)
{
	size_t pos = bit & 7;
	const u8 *map = (u8 *)lmap + (bit >> 3);

<<<<<<< HEAD
	if (!pos)
		goto check_size_t;
	if (8 - pos >= nbits)
		return !nbits ||
		       !(*map & fill_mask[pos + nbits] & zero_mask[pos]);

	if (*map++ & zero_mask[pos])
		return false;
	nbits -= 8 - pos;

check_size_t:
	pos = ((size_t)map) & (sizeof(size_t) - 1);
	if (!pos)
		goto step_size_t;

	pos = sizeof(size_t) - pos;
	if (nbits < pos * 8)
		goto step_size_t;
	for (nbits -= pos * 8; pos; pos--, map++) {
		if (*map)
			return false;
	}

step_size_t:
=======
	if (pos) {
		if (8 - pos >= nbits)
			return !nbits || !(*map & fill_mask[pos + nbits] &
					   zero_mask[pos]);

		if (*map++ & zero_mask[pos])
			return false;
		nbits -= 8 - pos;
	}

	pos = ((size_t)map) & (sizeof(size_t) - 1);
	if (pos) {
		pos = sizeof(size_t) - pos;
		if (nbits >= pos * 8) {
			for (nbits -= pos * 8; pos; pos--, map++) {
				if (*map)
					return false;
			}
		}
	}

>>>>>>> wip
	for (pos = nbits / BITS_IN_SIZE_T; pos; pos--, map += sizeof(size_t)) {
		if (*((size_t *)map))
			return false;
	}

	for (pos = (nbits % BITS_IN_SIZE_T) >> 3; pos; pos--, map++) {
		if (*map)
			return false;
	}

	pos = nbits & 7;
	if (pos && (*map & fill_mask[pos]))
		return false;

<<<<<<< HEAD
	// All bits are zero
=======
>>>>>>> wip
	return true;
}

/*
 * are_bits_set
 *
<<<<<<< HEAD
 * Returns true if all bits [bit, bit+nbits) are ones "1"
=======
 * Return: True if all bits [bit, bit+nbits) are ones "1".
>>>>>>> wip
 */
bool are_bits_set(const ulong *lmap, size_t bit, size_t nbits)
{
	u8 mask;
	size_t pos = bit & 7;
	const u8 *map = (u8 *)lmap + (bit >> 3);

<<<<<<< HEAD
	if (!pos)
		goto check_size_t;

	if (8 - pos >= nbits) {
		mask = fill_mask[pos + nbits] & zero_mask[pos];
		return !nbits || (*map & mask) == mask;
	}

	mask = zero_mask[pos];
	if ((*map++ & mask) != mask)
		return false;
	nbits -= 8 - pos;

check_size_t:
	pos = ((size_t)map) & (sizeof(size_t) - 1); // 0,1,2,3
	if (!pos)
		goto step_size_t;
	pos = sizeof(size_t) - pos;
	if (nbits < pos * 8)
		goto step_size_t;

	for (nbits -= pos * 8; pos; pos--, map++) {
		if (*map != 0xFF)
			return false;
	}

step_size_t:
=======
	if (pos) {
		if (8 - pos >= nbits) {
			mask = fill_mask[pos + nbits] & zero_mask[pos];
			return !nbits || (*map & mask) == mask;
		}

		mask = zero_mask[pos];
		if ((*map++ & mask) != mask)
			return false;
		nbits -= 8 - pos;
	}

	pos = ((size_t)map) & (sizeof(size_t) - 1);
	if (pos) {
		pos = sizeof(size_t) - pos;
		if (nbits >= pos * 8) {
			for (nbits -= pos * 8; pos; pos--, map++) {
				if (*map != 0xFF)
					return false;
			}
		}
	}

>>>>>>> wip
	for (pos = nbits / BITS_IN_SIZE_T; pos; pos--, map += sizeof(size_t)) {
		if (*((size_t *)map) != MINUS_ONE_T)
			return false;
	}

	for (pos = (nbits % BITS_IN_SIZE_T) >> 3; pos; pos--, map++) {
		if (*map != 0xFF)
			return false;
	}

	pos = nbits & 7;
	if (pos) {
		u8 mask = fill_mask[pos];

		if ((*map & mask) != mask)
			return false;
	}

<<<<<<< HEAD
	// All bits are ones
=======
>>>>>>> wip
	return true;
}
