// SPDX-License-Identifier: GPL-2.0

#include <linux/types.h>
#include <linux/mount.h>
#include "ipe.h"
#include "ipe-pin.h"
#include "ipe-property.h"

void ipe_get_boot_verified(struct ipe_operation_ctx *ctx, struct file *file)
{
	ctx->boot_verified = false;
	/*
	 * If we hit a null pointer until we get to the superblock,
	 * this path is considered unverified
	 */
	if (!file || !file->f_path.mnt->mnt_sb)
		return;

	ipe_pin_superblock(file);

	ctx->boot_verified = ipe_is_from_pinned_sb(file);
}

bool ipe_evaluate_boot_verified(struct ipe_operation_ctx *ctx)
{
	return ctx->boot_verified == true;
}
