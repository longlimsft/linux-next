/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef IPE_PIN_H
#define IPE_PIN_H

#include <linux/types.h>
#include "ipe-parse.h"

bool ipe_is_from_pinned_sb(struct file *file);
void ipe_pin_superblock(struct file *file);
void ipe_invalidate_pinned_sb(struct super_block *mnt_sb);

#endif /* IPE_PIN_H */
