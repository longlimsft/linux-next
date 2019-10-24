// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#include <linux/types.h>
#include <linux/audit.h>
#include <linux/lsm_audit.h>
#include <linux/sched.h>
#include "ipe.h"
#include "ipe-audit.h"

#define BOOLTOSTR(b) (b) ? "true" : "false"

const char *const operation_names[] = { "execute", "kernel_read" };

const char *const hook_names[] = {
	"exec",
	"mmap",
	"kernel_read",
	"kernel_load_data",
	"mprotect"
};

static void ipe_audit_ctx(struct audit_buffer *ab,
			  struct ipe_operation_ctx *ctx)
{
	char comm[sizeof(current->comm)];
	int err;

	audit_log_format(ab, "ctx ( ");

	/*
	 * The following two audit values are copied from
	 * dump_common_audit_data
	 */
	audit_log_format(ab, "pid: [%d] comm: [", task_tgid_nr(current));

	/* This is indicated as comm, but it appears to be the proc name */
	audit_log_untrustedstring(ab,
		memcpy(comm, current->comm, sizeof(comm)));

	audit_log_format(ab, "] ");

	audit_log_format(ab, "op: [%s] ", operation_names[ctx->op]);

	audit_log_format(ab, "hook: [%s] ", hook_names[ctx->hook]);

	audit_log_format(ab, "dmverity_verified: [%s] ",
			 BOOLTOSTR(ctx->dm_verity_verified));

	audit_log_format(ab, "boot_verified: [%s] ",
			 BOOLTOSTR(ctx->boot_verified));

	/* On failure to acquire audit_pathname, log the error code */


	if (IS_ERR(ctx->audit_data->audit_pathname)) {
		err = PTR_ERR(ctx->audit_data->audit_pathname);
		switch (err) {
		case -ENOENT:
			break;
		default:
			audit_log_format(ab, "audit_pathname: ");
			audit_log_format(ab, "[ERR(%ld)] ",
				PTR_ERR(ctx->audit_data->audit_pathname));
		}
	} else
		audit_log_format(ab, "audit_pathname: [%s] ",
			ctx->audit_data->audit_pathname);

	audit_log_format(ab, "ino: [%ld] ", ctx->audit_data->inode_num);

	audit_log_format(ab, "dev: [%s] ", ctx->audit_data->superblock_id);

	audit_log_format(ab, ") ");
}

void ipe_audit_message(struct ipe_operation_ctx *ctx, bool is_boot_verified,
		       bool is_dmverity_verified)
{
	struct audit_buffer *ab;

	/* if verified and no success auditing, return */
	if ((is_boot_verified || is_dmverity_verified) && !success_audit)
		return;

	ab = audit_log_start(audit_context(), GFP_ATOMIC | __GFP_NOWARN,
			     AUDIT_INTEGRITY_POLICY_RULE);
	if (!ab)
		return;

	audit_log_format(ab, "IPE=");

	ipe_audit_ctx(ab, ctx);

	if (is_boot_verified && success_audit)
		audit_log_format(ab,
				 " [ action = %s ] [ boot_verified = %s ]",
				 "allow",
				 "true");
	else if (is_dmverity_verified && success_audit)
		audit_log_format(ab,
				 " [ action = %s ] [ dmverity_verified = %s ]",
				 "allow",
				 "true");
	else if (!is_boot_verified && !is_dmverity_verified)
		audit_log_format(ab, " [ action = deny ]");

	audit_log_end(ab);
}

/*
 * Function to get the absolute pathname of a file, and populate that in ctx
 */
static void ipe_get_audit_pathname(struct ipe_audit_data *audit_data,
				   struct file *file)
{
	char *pathbuf = NULL;
	char *temp_path = NULL;
	char *pos = NULL;
	struct super_block *sb;

	/* No File to get Path From */
	if (file == NULL) {
		audit_data->audit_pathname = ERR_PTR(-ENOENT);
		goto err;
	}

	sb = file->f_path.dentry->d_sb;

	pathbuf = __getname();
	if (!pathbuf) {
		audit_data->audit_pathname = ERR_PTR(-ENOMEM);
		goto err;
	}

	pos = d_absolute_path(&file->f_path, pathbuf, PATH_MAX);
	if (IS_ERR(pos)) {
		/* Use the pointer field to store the error. */
		audit_data->audit_pathname = pos;
		goto err;
	}

	temp_path = __getname();
	if (!temp_path) {
		audit_data->audit_pathname = ERR_PTR(-ENOMEM);
		goto err;
	}

	if (strlcpy(temp_path, pos, PATH_MAX) > PATH_MAX) {
		audit_data->audit_pathname = ERR_PTR(-ENAMETOOLONG);
		goto err;
	}

	/* Transfer Buffer */
	audit_data->audit_pathname = temp_path;
	temp_path = NULL;
err:
	if (pathbuf)
		__putname(pathbuf);
	if (temp_path)
		__putname(temp_path);
}


void ipe_build_audit_data(struct ipe_audit_data *audit_data, struct file *file)
{
	ipe_get_audit_pathname(audit_data, file);

	if (file == NULL)
		return;

	audit_data->inode_num = file->f_inode->i_ino;
	audit_data->superblock_id = file->f_inode->i_sb->s_id;
}


void ipe_audit_mode_change(void)
{
	struct audit_buffer *ab;

	ab = audit_log_start(audit_context(), GFP_ATOMIC | __GFP_NOWARN,
			     AUDIT_INTEGRITY_STATUS);
	if (!ab)
		return;

	audit_log_format(ab, "IPE switched to %s mode",
			 (enforce) ? "enforce" : "audit");

	audit_log_end(ab);
}
