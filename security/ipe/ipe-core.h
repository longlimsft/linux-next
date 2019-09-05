/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef IPE_CORE_H
#define IPE_CORE_H

#include <linux/types.h>
#include <linux/fs.h>

int ipe_process_event(struct ipe_operation_ctx *ctx, struct file *file);

#endif /* IPE_CORE_H */
