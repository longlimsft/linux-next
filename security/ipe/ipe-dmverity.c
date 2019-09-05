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
#include "ipe-policy.h"
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

bool ipe_evaluate_dm_verity(struct ipe_operation_ctx *ctx,
			    struct ipe_sub_rule *sub_rule)
{
	return ctx->dm_verity_verified == sub_rule->bool_val;
}

bool ipe_init_dm_verity(void)
{
	IPE_REGISTER_PROPERTY(dm_verity, "dmverity_verified=%s");

	return true;
}

int ipe_parse_dm_verity(const char *token_value, struct ipe_sub_rule *rule)
{
	rule->property_id = ipe_property_dm_verity;
	rule->property_type = ipe_property_bool;

	if (strcmp(token_value, IPE_PROPERTY_VALUE_FALSE) == 0)
		rule->bool_val = false;
	else if (strcmp(token_value, IPE_PROPERTY_VALUE_TRUE) == 0)
		rule->bool_val = true;
	else
		return -EINVAL;

	return 0;
}

void ipe_audit_dm_verity(struct audit_buffer *ab, struct ipe_sub_rule *property)
{
	audit_log_format(ab, "[ dmverity_verified = %s ]",
			 property->bool_val ? "true" : "false");
}
