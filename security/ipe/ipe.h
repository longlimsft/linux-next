/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef IPE_H
#define IPE_H

#include <linux/types.h>
#include <linux/fs.h>
#include "ipe-hooks.h"

extern int enforce;
extern int success_audit;

struct ipe_audit_data {
	char *audit_pathname;
	unsigned long inode_num;
	const char *superblock_id;
};

struct ipe_operation_ctx {
	enum ipe_operation op;
	enum ipe_hook hook;
	bool dm_verity_verified;
	bool boot_verified;
	struct ipe_audit_data *audit_data;
};

#endif /* IPE_H */
