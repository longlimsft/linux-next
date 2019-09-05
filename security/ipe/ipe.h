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

struct ipe_operation_ctx {
	enum ipe_hook op;
	bool dm_verity_verified;
	bool boot_verified;
	char *audit_pathname;
};

#endif /* IPE_H */
