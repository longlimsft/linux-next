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

static struct ipe_operation_ctx *ipe_alloc_ctx(enum ipe_operation op,
					       enum ipe_hook hook)
{
	struct ipe_operation_ctx *ctx = NULL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->op = op;
	ctx->hook = hook;

	ctx->audit_data = kzalloc(sizeof(*ctx->audit_data), GFP_KERNEL);
	if (!ctx->audit_data) {
		kfree(ctx);
		return ERR_PTR(-ENOMEM);
	}

	return ctx;
}

static void ipe_free_ctx(struct ipe_operation_ctx *ctx)
{
	/* __putname does not NULL check the free */
	if (ctx->audit_data->audit_pathname &&
	    !IS_ERR(ctx->audit_data->audit_pathname))
		__putname(ctx->audit_data->audit_pathname);

	kfree(ctx->audit_data);
	kfree(ctx);
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

	ipe_build_audit_data(ctx->audit_data, file);

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
int ipe_process_event(enum ipe_operation op, enum ipe_hook hook,
		      struct file *file)
{
	int rc = 0;
	struct ipe_operation_ctx *ctx;

	ctx = ipe_alloc_ctx(op, hook);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	rc = ipe_apply_rules(ctx, file);

	ipe_free_ctx(ctx);

	return rc;
}
