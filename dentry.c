#include "u2fs.h"

/*
 * returns: -ERRNO if error (returned to user)
 *          0: tell VFS to invalidate dentry
 *          1: dentry is valid
 */
static int u2fs_d_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	struct path lower_path, saved_path;
	struct dentry *lower_dentry;
	int err = 1;
	
	if (nd && nd->flags & LOOKUP_RCU)
		return -ECHILD;

	if((U2FS_D(dentry)->lower_path[LEFT].dentry) != NULL && 
		(U2FS_D(dentry)->lower_path[LEFT].mnt) != NULL){

		u2fs_get_lower_path(dentry, &lower_path, LEFT);

	}
	else	
		u2fs_get_lower_path(dentry, &lower_path, RIGHT);

	
	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_op || !lower_dentry->d_op->d_revalidate)
		goto out;
	pathcpy(&saved_path, &nd->path);
	pathcpy(&nd->path, &lower_path);
	err = lower_dentry->d_op->d_revalidate(lower_dentry, nd);
	pathcpy(&nd->path, &saved_path);
out:
	u2fs_put_lower_path(dentry, &lower_path);
	return err;
}

static void u2fs_d_release(struct dentry *dentry)
{
	/* release and reset the lower paths */

	if((U2FS_D(dentry)->lower_path[LEFT].dentry) != NULL && 
		(U2FS_D(dentry)->lower_path[LEFT].mnt) != NULL){

		u2fs_put_reset_lower_path(dentry, LEFT);
	}
	else
		u2fs_put_reset_lower_path(dentry, RIGHT);

	free_dentry_private_data(dentry);
	return;
}

const struct dentry_operations u2fs_dops = {
	.d_revalidate	= u2fs_d_revalidate,
	.d_release	= u2fs_d_release,
};
