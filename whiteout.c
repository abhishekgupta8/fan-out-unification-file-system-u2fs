#include "u2fs.h"

/*
 * whiteout and opaque directory helpers
 */

/* What do we use for whiteouts. */
#define U2FS_WHPFX ".wh."
#define U2FS_WHLEN 4
/*
 * If a directory contains this file, then it is opaque.  We start with the
 * .wh. flag so that it is blocked by lookup.
 */
#define U2FS_DIR_OPAQUE_NAME "__dir_opaque"
#define U2FS_DIR_OPAQUE U2FS_WHPFX U2FS_DIR_OPAQUE_NAME

/* construct whiteout filename */
char *alloc_whname(const char *name, int len)
{
	char *buf;
	
	buf = kmalloc(len + U2FS_WHLEN + 1, GFP_KERNEL);
	if (unlikely(!buf))
		return ERR_PTR(-ENOMEM);

	strcpy(buf, U2FS_WHPFX);
	strlcat(buf, name, len + U2FS_WHLEN + 1);

	return buf;
}

/*
 * XXX: this can be inline or CPP macro, but is here to keep all whiteout
 * code in one place.
 */
void u2fs_set_max_namelen(long *namelen)
{
	*namelen -= U2FS_WHLEN;
}

/* check if @namep is a whiteout, update @namep and @namelenp accordingly */
bool is_whiteout_name(char **namep, int *namelenp)
{		
	
	if (*namelenp > U2FS_WHLEN &&
	    !strncmp(*namep, U2FS_WHPFX, U2FS_WHLEN)) {
		*namep += U2FS_WHLEN;
		*namelenp -= U2FS_WHLEN;
		return true;
	}
	return false;
}

/* is the filename valid == !(whiteout for a file or opaque dir marker) */
bool is_validname(const char *name)
{
	
	if (!strncmp(name, U2FS_WHPFX, U2FS_WHLEN))
		return false;
	if (!strncmp(name, U2FS_DIR_OPAQUE_NAME,
		     sizeof(U2FS_DIR_OPAQUE_NAME) - 1))
		return false;
	return true;
}

/*
 * Look for a whiteout @name in @lower_parent directory.  If error, return
 * ERR_PTR.  Caller must dput() the returned dentry if not an error.
 *
 * XXX: some callers can reuse the whname allocated buffer to avoid repeated
 * free then re-malloc calls.  Need to provide a different API for those
 * callers.
 */
struct dentry *lookup_whiteout(const char *name, struct dentry *lower_parent)
{
	char *whname = NULL;
	int err = 0, namelen;
	struct dentry *wh_dentry = NULL;
	
	namelen = strlen(name);
	whname = alloc_whname(name, namelen);
	if (unlikely(IS_ERR(whname))) {
		err = PTR_ERR(whname);
		goto out;
	}

	/* check if whiteout exists in this branch: lookup .wh.foo */
	wh_dentry = lookup_one_len(whname, lower_parent, strlen(whname));
	if (IS_ERR(wh_dentry)) {
		err = PTR_ERR(wh_dentry);
		goto out;
	}

	/* check if negative dentry (ENOENT) */
	if (!wh_dentry->d_inode)
		goto out;

	/* whiteout found: check if valid type */
	if (!S_ISREG(wh_dentry->d_inode->i_mode)) {
		printk(KERN_ERR "u2fs: invalid whiteout %s entry type %d\n",
		       whname, wh_dentry->d_inode->i_mode);
		dput(wh_dentry);
		err = -EIO;
		goto out;
	}

out:
	kfree(whname);
	if (err)
		wh_dentry = ERR_PTR(err);
	return wh_dentry;
}

/*
 * Unlink a whiteout dentry.  Returns 0 or -errno.  Caller must hold and
 * release dentry reference.
 */
int unlink_whiteout(struct dentry *wh_dentry)
{
	int err;
	struct dentry *lower_dir_dentry;
	
	/* dget and lock parent dentry */
	lower_dir_dentry = lock_parent_wh(wh_dentry);

	/* see Documentation/filesystems/u2fs/issues.txt */
	lockdep_off();
	err = vfs_unlink(lower_dir_dentry->d_inode, wh_dentry);
	lockdep_on();
	unlock_dir(lower_dir_dentry);

	/*
	 * Whiteouts are special files and should be deleted no matter what
	 * (as if they never existed), in order to allow this create
	 * operation to succeed.  This is especially important in sticky
	 * directories: a whiteout may have been created by one user, but
	 * the newly created file may be created by another user.
	 * Therefore, in order to maintain Unix semantics, if the vfs_unlink
	 * above failed, then we have to try to directly unlink the
	 * whiteout.  Note: in the ODF version of u2fs, whiteout are
	 * handled much more cleanly.
	 */
	if (err == -EPERM) {
		struct inode *inode = lower_dir_dentry->d_inode;
		err = inode->i_op->unlink(inode, wh_dentry);
	}
	if (err)
		printk(KERN_ERR "u2fs: could not unlink whiteout %s, "
		       "err = %d\n", wh_dentry->d_name.name, err);

	return err;

}

int create_whiteout(struct dentry *dentry)
{
	struct dentry *lower_dir_dentry;
	struct dentry *lower_dentry;
	struct dentry *lower_wh_dentry;
	struct nameidata nd;
	char *name = NULL;
	int err = -EINVAL;
	
	/* create dentry's whiteout equivalent */
	name = alloc_whname(dentry->d_name.name, dentry->d_name.len);
	if (unlikely(IS_ERR(name))) {
		err = PTR_ERR(name);
		goto out;
	}

	lower_dentry = U2FS_D(dentry)->lower_path[LEFT].dentry;

	if (!lower_dentry) {
		/*
		 * if lower dentry is not present, create the
		 * entire lower dentry directory structure and go
		 * ahead.  Since we want to just create whiteout, we
		 * only want the parent dentry, and hence get rid of
		 * this dentry.
		 */
		lower_dentry = create_parents(dentry->d_inode,
					      dentry,
					      dentry->d_name.name);
		if (!lower_dentry || IS_ERR(lower_dentry)) {
				int ret = PTR_ERR(lower_dentry);
				if (!IS_COPYUP_ERR(ret))
					printk(KERN_ERR
				      	 "u2fs: create_parents for "
				     	  "whiteout failed"
				      	 "err=%d\n", ret);
				goto out;
			}
		u2fs_postcopyup_setmnt(dentry);
	}

	lower_wh_dentry =
		lookup_one_len(name, lower_dentry->d_parent,
			       dentry->d_name.len + U2FS_WHLEN);
	if (IS_ERR(lower_wh_dentry))
		goto out;

	/*
	 * The whiteout already exists. This used to be impossible,
	 * but now is possible because of opaqueness.
	 */
	if (lower_wh_dentry->d_inode) {
		dput(lower_wh_dentry);
		err = 0;
		goto out;
	}

	err = init_lower_nd(&nd, LOOKUP_CREATE);

	if (unlikely(err < 0))
		goto out;
	lower_dir_dentry = lock_parent_wh(lower_wh_dentry);
	err = vfs_create(lower_dir_dentry->d_inode,
			 lower_wh_dentry,
			 current_umask() & S_IRUGO,					 		 &nd);
	unlock_dir(lower_dir_dentry);
	dput(lower_wh_dentry);
	release_lower_nd(&nd, err);
out:
	kfree(name);
	return err;
}
