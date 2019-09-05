// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include <linux/types.h>
#include <linux/device-mapper.h>
#include <linux/binfmts.h>
#include <linux/mount.h>
#include "ipe.h"
#include "ipe-hooks.h"
#include "ipe-pin.h"

/*
 * Function to get whether a file exists in a dmverity mounted
 * and verified volume.
 */
void ipe_get_dm_verity(struct ipe_operation_ctx *ctx, struct file *file)
{
	ctx->dm_verity_verified = false;

	/*
	 * If we hit a null pointer until we get to the block device,
	 * this path is considered unverified
	 */
	if (!file || !file->f_path.mnt->mnt_sb ||
	    !file->f_path.mnt->mnt_sb->s_bdev) {
		ctx->dm_verity_verified = false;
		return;
	}

	ctx->dm_verity_verified =
		dm_is_bd_verity_verified(file->f_path.mnt->mnt_sb->s_bdev);
}

bool ipe_evaluate_dm_verity(struct ipe_operation_ctx *ctx)
{
	return ctx->dm_verity_verified == true;
}
