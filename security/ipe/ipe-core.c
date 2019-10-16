// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#include <linux/device-mapper.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>
#include <linux/mount.h>
#include <linux/binfmts.h>
#include <linux/magic.h>
#include "ipe.h"
#include "ipe-hooks.h"
#include "ipe-property.h"
#include "ipe-audit.h"
#include "ipe-pin.h"

static void ipe_free_ctx(struct ipe_operation_ctx *ctx)
{
	if (ctx->audit_pathname)
		__putname(ctx->audit_pathname);
	ctx->audit_pathname = NULL;
}

/*
 * Function to get the absolute pathname of a file, and populate that in ctx
 */
static void ipe_get_audit_pathname(struct ipe_operation_ctx *ctx,
				   struct file *file)
{
	char *pathbuf = NULL;
	char *temp_path = NULL;
	char *pos = NULL;
	struct super_block *sb;

	/* No File to get Path From */
	if (file == NULL)
		return;

	sb = file->f_path.dentry->d_sb;

	pathbuf = __getname();
	if (!pathbuf)
		goto err;

	pos = d_absolute_path(&file->f_path, pathbuf, PATH_MAX);
	if (IS_ERR(pos))
		goto err;

	temp_path = __getname();
	if (!temp_path)
		goto err;

	if (strlcpy(temp_path, pos, PATH_MAX) > PATH_MAX)
		goto err;

	/* Transfer Buffer */
	ctx->audit_pathname = temp_path;
	temp_path = NULL;
err:
	if (pathbuf)
		__putname(pathbuf);
	if (temp_path)
		__putname(temp_path);
}

/*
 *	Based on the rules, and a populated ctx structure,
 *	determine whether the call should be blocked, or
 *	allowed to pass.
 *	Returns -EACCES when the call should be blocked.
 */
static int ipe_apply_rules(struct ipe_operation_ctx *ctx, struct file *file)
{
	bool is_boot_verified = false;
	bool is_dmverity_verified = false;

	ipe_get_audit_pathname(ctx, file);

	properties[ipe_property_dm_verity].populator(ctx, file);
	properties[ipe_property_boot_verified].populator(ctx, file);

	is_boot_verified =
		properties[ipe_property_boot_verified].evaluator(ctx);
	is_dmverity_verified =
		properties[ipe_property_dm_verity].evaluator(ctx);

	ipe_audit_message(ctx, is_boot_verified, is_dmverity_verified);

	if (!enforce || (is_boot_verified || is_dmverity_verified))
		return 0;

	return -EACCES;
}

/*
 * This function will check the current context against the policy and
 * return success if the policy allows it and returns a -EACCES if the policy
 * blocks it.
 */
int ipe_process_event(struct ipe_operation_ctx *ctx, struct file *file)
{
	int rc = 0;

	rc = ipe_apply_rules(ctx, file);

	ipe_free_ctx(ctx);

	return rc;
}
