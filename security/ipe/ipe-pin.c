// SPDX-License-Identifier: GPL-2.0
/*
 * This file has been heavily adapted from the source code of the
 * loadpin LSM. The source code for loadpin is co-located in the linux
 * tree under security/loadpin/loadpin.c.
 *
 * Loadpin is authored by Kees Cook <keescook@chromium.org>
 * Copyright 2011-2016 Google Inc.
 *
 * Please see loadpin.c for up-to-date information about
 * loadpin.
 */
#include <linux/types.h>
#include <linux/spinlock_types.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/mman.h>

static DEFINE_SPINLOCK(pinned_sb_spinlock);

#ifdef CONFIG_SECURITY_IPE_TRUST_BOOT

static struct super_block *pinned_sb;

bool ipe_is_from_pinned_sb(struct file *file)
{
	bool rv = false;

	spin_lock(&pinned_sb_spinlock);

	/*
	 * Check if pinned_sb is set:
	 *  NULL == not set -> exit
	 *  ERR == was once set (and has been unmounted) -> exit
	 * AND check that the pinned sb is the same as the file's.
	 */
	if (!IS_ERR_OR_NULL(pinned_sb) &&
	    file->f_path.mnt->mnt_sb == pinned_sb) {
		rv = true;
		goto cleanup;
	}

cleanup:
	spin_unlock(&pinned_sb_spinlock);
	return rv;
}

void ipe_pin_superblock(struct file *file)
{
	spin_lock(&pinned_sb_spinlock);

	/* if set, return */
	if (pinned_sb || !file)
		goto cleanup;

	pinned_sb = file->f_path.mnt->mnt_sb;
cleanup:
	spin_unlock(&pinned_sb_spinlock);
}

void ipe_invalidate_pinned_sb(struct super_block *mnt_sb)
{
	spin_lock(&pinned_sb_spinlock);

	/*
	 * On pinned sb unload - invalidate the pinned address
	 * by setting the pinned_sb to ERR_PTR(-EIO)
	 */
	if (!IS_ERR_OR_NULL(pinned_sb) && mnt_sb == pinned_sb)
		pinned_sb = ERR_PTR(-EIO);

	spin_unlock(&pinned_sb_spinlock);
}

#else /* !CONFIG_SECURITY_IPE_TRUST_BOOT */

bool ipe_is_from_pinned_sb(struct file *file)
{
	return false;
}
void ipe_pin_superblock(struct file *file)
{
}
void ipe_invalidate_pinned_sb(struct super_block *mnt_sb)
{
}

#endif /* !CONFIG_SECURITY_IPE_TRUST_BOOT */
