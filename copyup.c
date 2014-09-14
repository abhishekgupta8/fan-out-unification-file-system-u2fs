#include "u2fs.h"

void __cleanup_dentry(struct dentry *dentry){

	u2fs_put_reset_lower_path(dentry, RIGHT);
}

static inline void path_put_lowers(struct dentry *dentry, bool free_lower)
{
	u2fs_put_reset_lower_path(dentry, RIGHT);

}

void u2fs_postcopyup_release(struct dentry *dentry)
{
	
	BUG_ON(S_ISDIR(dentry->d_inode->i_mode));

	path_put_lowers(dentry, false);
	u2fs_set_lower_inode(dentry->d_inode, NULL, RIGHT);
}

void u2fs_postcopyup_setmnt(struct dentry *dentry)
{
	struct dentry *parent, *hasone;
	
	if (U2FS_D(dentry)->lower_path[LEFT].mnt)
		return;
	hasone = dentry->d_parent;
	/* this loop should stop at root dentry */
	while (!U2FS_D(hasone)->lower_path[LEFT].mnt)
		hasone = hasone->d_parent;
	parent = dentry;
	while (!(U2FS_D(parent)->lower_path[LEFT].mnt)) {
		U2FS_D(parent)->lower_path[LEFT].mnt =
			U2FS_D(hasone)->lower_path[LEFT].mnt;
		parent = parent->d_parent;
	}
}

static void __clear(struct dentry *dentry, struct dentry *old_lower_dentry,
		    struct dentry *new_lower_dentry)
{
	
	/* get rid of the lower dentry and all its traces */
	U2FS_D(dentry)->lower_path[LEFT].dentry = NULL;

	dput(new_lower_dentry);
	dput(old_lower_dentry);
}

static int __copyup_reg_data(struct dentry *dentry,
			     struct dentry *new_lower_dentry,
			     struct dentry *old_lower_dentry,
			     struct file **copyup_file, loff_t len)
{
	struct super_block *sb = dentry->d_sb;
	struct file *input_file;
	struct file *output_file;
	struct vfsmount *output_mnt;
	mm_segment_t old_fs;
	char *buf = NULL;
	ssize_t read_bytes, write_bytes;
	loff_t size;
	int err = 0;
	
	input_file = dentry_open(old_lower_dentry,
				 U2FS_D(dentry)->lower_path[RIGHT].mnt,
				 O_RDONLY | O_LARGEFILE, current_cred());
	if (IS_ERR(input_file)) {
		dput(old_lower_dentry);
		err = PTR_ERR(input_file);
		goto out;
	}
	if (unlikely(!input_file->f_op || !input_file->f_op->read)) {
		err = -EINVAL;
		goto out_close_in;
	}

	/* open new file */
	dget(new_lower_dentry);
	output_mnt = U2FS_D(sb->s_root)->lower_path[LEFT].mnt;

	output_file = dentry_open(new_lower_dentry, output_mnt,
				  O_RDWR | O_LARGEFILE, current_cred());
	if (IS_ERR(output_file)) {
		err = PTR_ERR(output_file);
		goto out_close_in;
	}
	if (unlikely(!output_file->f_op || !output_file->f_op->write)) {
		err = -EINVAL;
		goto out_close_out;
	}

	/* allocating a buffer */
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (unlikely(!buf)) {
		err = -ENOMEM;
		goto out_close_out;
	}

	input_file->f_pos = 0;
	output_file->f_pos = 0;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	size = len;
	err = 0;
	do {
		if (len >= PAGE_SIZE)
			size = PAGE_SIZE;
		else if ((len < PAGE_SIZE) && (len > 0))
			size = len;

		len -= PAGE_SIZE;

		read_bytes =
			input_file->f_op->read(input_file,
					       (char __user *)buf, size,
					       &input_file->f_pos);
		if (read_bytes <= 0) {
			err = read_bytes;
			break;
		}

		/* see Documentation/filesystems/u2fs/issues.txt */
		lockdep_off();
		write_bytes =
			output_file->f_op->write(output_file,
						 (char __user *)buf,
						 read_bytes,
						 &output_file->f_pos);
		lockdep_on();
		if ((write_bytes < 0) || (write_bytes < read_bytes)) {
			err = write_bytes;
			break;
		}
	} while ((read_bytes > 0) && (len > 0));

	set_fs(old_fs);

	kfree(buf);

	if (err)
		goto out_close_out;

	if (copyup_file) {
		*copyup_file = output_file;
		goto out_close_in;
	}

out_close_out:
	fput(output_file);

out_close_in:
	fput(input_file);

out:
	return err;
}


int init_lower_nd(struct nameidata *nd, unsigned int flags)
{
	int err = 0;
	
	memset(nd, 0, sizeof(struct nameidata));
	if (!flags)
		return err;

	switch (flags) {
	case LOOKUP_CREATE:
		nd->intent.open.flags |= O_CREAT;
		/* fall through: shared code for create/open cases */
	case LOOKUP_OPEN:
		nd->flags = flags;
		nd->intent.open.flags |= (FMODE_READ | FMODE_WRITE);
		break;
	default:
		/*
		 * We should never get here, for now.
		 * We can add new cases here later on.
		 */
		pr_debug("u2fs: unknown nameidata flag 0x%x\n", flags);
		BUG();
		break;
	}

	return err;
}

void release_lower_nd(struct nameidata *nd, int err)
{
	if (!nd->intent.open.file)
		return;
}

/*
 * Determine the mode based on the copyup flags, and the existing dentry.
 *
 * Handle file systems which may not support certain options.  For example
 * jffs2 doesn't allow one to chmod a symlink.  So we ignore such harmless
 * errors, rather than propagating them up, which results in copyup errors
 * and errors returned back to users.
 */

static int __copyup_ndentry(struct dentry *old_lower_dentry,
			    struct dentry *new_lower_dentry,
			    struct dentry *new_lower_parent_dentry,
			    char *symbuf)
{
	int err = 0;
	umode_t old_mode = old_lower_dentry->d_inode->i_mode;
	struct sioq_args args;
	
	if (S_ISDIR(old_mode)) {
		args.mkdir.parent = new_lower_parent_dentry->d_inode;
		args.mkdir.dentry = new_lower_dentry;
		args.mkdir.mode = old_mode;

		run_sioq(__u2fs_mkdir, &args);
		err = args.err;
	} else if (S_ISLNK(old_mode)) {
		args.symlink.parent = new_lower_parent_dentry->d_inode;
		args.symlink.dentry = new_lower_dentry;
		args.symlink.symbuf = symbuf;

		run_sioq(__u2fs_symlink, &args);
		err = args.err;
	} else if (S_ISBLK(old_mode) || S_ISCHR(old_mode) ||
		   S_ISFIFO(old_mode) || S_ISSOCK(old_mode)) {
		args.mknod.parent = new_lower_parent_dentry->d_inode;
		args.mknod.dentry = new_lower_dentry;
		args.mknod.mode = old_mode;
		args.mknod.dev = old_lower_dentry->d_inode->i_rdev;

		run_sioq(__u2fs_mknod, &args);
		err = args.err;
	} else if (S_ISREG(old_mode)) {
		struct nameidata nd;
		err = init_lower_nd(&nd, LOOKUP_CREATE);
		if (unlikely(err < 0))
			goto out;
		args.create.nd = &nd;
		args.create.parent = new_lower_parent_dentry->d_inode;
		args.create.dentry = new_lower_dentry;
		args.create.mode = old_mode;
		run_sioq(__u2fs_create, &args);
		err = args.err;
		release_lower_nd(&nd, err);
	} else {
		printk(KERN_CRIT "u2fs: unknown inode type %d\n",
		       old_mode);
		BUG();
	}

out:
	return err;
}

static int copyup_permissions(struct super_block *sb,
			      struct dentry *old_lower_dentry,
			      struct dentry *new_lower_dentry)
{
	struct inode *i = old_lower_dentry->d_inode;
	struct iattr newattrs;
	int err;
	
	newattrs.ia_atime = i->i_atime;
	newattrs.ia_mtime = i->i_mtime;
	newattrs.ia_ctime = i->i_ctime;
	newattrs.ia_gid = i->i_gid;
	newattrs.ia_uid = i->i_uid;
	newattrs.ia_valid = ATTR_CTIME | ATTR_ATIME | ATTR_MTIME |
		ATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_FORCE |
		ATTR_GID | ATTR_UID;
	mutex_lock(&new_lower_dentry->d_inode->i_mutex);
	err = notify_change(new_lower_dentry, &newattrs);
	if (err)
		goto out;

	/* now try to change the mode and ignore EOPNOTSUPP on symlinks */
	newattrs.ia_mode = i->i_mode;
	newattrs.ia_valid = ATTR_MODE | ATTR_FORCE;
	err = notify_change(new_lower_dentry, &newattrs);
	if (err == -EOPNOTSUPP &&
	    S_ISLNK(new_lower_dentry->d_inode->i_mode)) {
		printk(KERN_WARNING
		       "u2fs: changing \"%s\" symlink mode unsupported\n",
		       new_lower_dentry->d_name.name);
		err = 0;
	}

out:
	mutex_unlock(&new_lower_dentry->d_inode->i_mutex);
	return err;
}

/* copy a/m/ctime from the lower branch with the newest times */
void u2fs_copy_attr_times(struct inode *upper)
{
	struct inode *lower;
	
	lower = u2fs_lower_inode(upper, RIGHT);
	
	if (!lower)
		return;
	
	if (unlikely(timespec_compare(&upper->i_mtime,
				      &lower->i_mtime) < 0)){
		upper->i_mtime = lower->i_mtime;
	}
	if (unlikely(timespec_compare(&upper->i_ctime,
				      &lower->i_ctime) < 0)){
		upper->i_ctime = lower->i_ctime;
	}
	if (unlikely(timespec_compare(&upper->i_atime,
				      &lower->i_atime) < 0)){
		upper->i_atime = lower->i_atime;
	}
}

struct dentry *create_parents(struct inode *dir, struct dentry *dentry,
			      const char *name)
{
	int err;
	struct dentry *child_dentry;
	struct dentry *parent_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct dentry *lower_dentry = NULL;
	const char *childname;
	unsigned int childnamelen;
	int nr_dentry;
	int count = 0;
	struct dentry **path = NULL;
	struct super_block *sb;
	
	lower_dentry = ERR_PTR(-ENOMEM);

	/* There is no sense allocating any less than the minimum. */
	nr_dentry = 1;
	path = kmalloc(nr_dentry * sizeof(struct dentry *), GFP_KERNEL);
	if (unlikely(!path))
		goto out;

	/* assume the negative dentry of u2fs as the parent dentry */
	parent_dentry = dentry;

	/*
	 * This loop finds the first parent that exists in the given branch.
	 * We start building the directory structure from there.  At the end
	 * of the loop, the following should hold:
	 *  - child_dentry is the first nonexistent child
	 *  - parent_dentry is the first existent parent
	 *  - path[0] is the = deepest child
	 *  - path[count] is the first child to create
	 */
	do {
		child_dentry = parent_dentry;

		/* find the parent directory dentry in u2fs */
		parent_dentry = dget_parent(child_dentry);

		/* find out the lower_parent_dentry in the given branch */
		if(U2FS_D(parent_dentry)->lower_path[LEFT].dentry != NULL)
			lower_parent_dentry = 
				U2FS_D(parent_dentry)->lower_path[LEFT].dentry;

		/* grow path table */
		if (count == nr_dentry) {
			void *p;

			nr_dentry *= 2;
			p = krealloc(path, nr_dentry * sizeof(struct dentry *),
				     GFP_KERNEL);
			if (unlikely(!p)) {
				lower_dentry = ERR_PTR(-ENOMEM);
				goto out;
			}
			path = p;
		}

		/* store the child dentry */
		path[count++] = child_dentry;
	} while (!lower_parent_dentry);
	
	count--;

	sb = dentry->d_sb;

	/*
	 * This code goes between the begin/end labels and basically
	 * emulates a while(child_dentry != dentry), only cleaner and
	 * shorter than what would be a much longer while loop.
	 */
begin:
	/* get lower parent dir in the current branch */
	lower_parent_dentry = U2FS_D(parent_dentry)->lower_path[LEFT].dentry;
	dput(parent_dentry);
	/* init the values to lookup */
	childname = child_dentry->d_name.name;
	childnamelen = child_dentry->d_name.len;

	if (child_dentry != dentry) {
		/* lookup child in the underlying file system */
		lower_dentry = lookup_one_len(childname, lower_parent_dentry,
					      childnamelen);
		if (IS_ERR(lower_dentry))
			goto out;
	}
	else {	
		 /* Is the name a whiteout of the child name ?  lookup the
		  * whiteout child in the underlying file system */
		 
		lower_dentry = lookup_one_len(name, lower_parent_dentry,
					      strlen(name));
		if (IS_ERR(lower_dentry))
			goto out;

		U2FS_D(dentry)->lower_path[LEFT].dentry = lower_dentry;
		goto out;
	}
	if (lower_dentry->d_inode) {
		/*
		 * since this already exists we dput to avoid
		 * multiple references on the same dentry
		 */
		dput(lower_dentry);
	} 
	else {
	struct sioq_args args;
		/* it's a negative dentry, create a new dir */
		lower_parent_dentry = lock_parent(lower_dentry);
		args.mkdir.parent = lower_parent_dentry->d_inode;
		args.mkdir.dentry = lower_dentry;
		args.mkdir.mode = child_dentry->d_inode->i_mode;
		run_sioq(__u2fs_mkdir, &args);
		err = args.err;
		if (!err)
			err = copyup_permissions(dir->i_sb, child_dentry,
						 lower_dentry);
		unlock_dir(lower_parent_dentry);
		if (err) {
			dput(lower_dentry);
			lower_dentry = ERR_PTR(err);
			goto out;
		}
	}
	u2fs_set_lower_inode(child_dentry->d_inode, lower_dentry->d_inode, 
				LEFT);
	U2FS_D(child_dentry)->lower_path[LEFT].dentry = lower_dentry;
	/*
	 * update times of this dentry, but also the parent, because if
	 * we changed, the parent may have changed too.
	 */
	fsstack_copy_attr_times(parent_dentry->d_inode,
				lower_parent_dentry->d_inode);
	u2fs_copy_attr_times(child_dentry->d_inode);
	parent_dentry = child_dentry;
	child_dentry = path[--count];
	goto begin;
out:
	/* cleanup any leftover locks from the do/while loop above */
	if (IS_ERR(lower_dentry))
		while (count)
			dput(path[count--]);
	kfree(path);
	return lower_dentry;
}

int copyup_dentry(struct inode *dir, struct dentry *dentry,
		  const char *name, int namelen,
		  struct file **copyup_file, loff_t len)
{
	struct dentry *new_lower_dentry;
	struct dentry *old_lower_dentry = NULL;
	struct super_block *sb;
	int err = 0;
	struct dentry *new_lower_parent_dentry = NULL;
	mm_segment_t oldfs;
	char *symbuf = NULL;
	
	sb = dir->i_sb;
	
	/* Create the directory structure above this dentry. */
	new_lower_dentry = create_parents(dir, dentry, name);
	if (IS_ERR(new_lower_dentry)) {
		err = PTR_ERR(new_lower_dentry);
		goto out;
	}

	old_lower_dentry = U2FS_D(dentry)->lower_path[RIGHT].dentry;
	
	/* we conditionally dput this old_lower_dentry at end of function */
	dget(old_lower_dentry);

	/* For symlinks, we must read the link before we lock the directory. */
	if (S_ISLNK(old_lower_dentry->d_inode->i_mode)) {

		symbuf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (unlikely(!symbuf)) {
			__clear(dentry, old_lower_dentry,
				new_lower_dentry);
			err = -ENOMEM;
			goto out_free;
		}

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		err = old_lower_dentry->d_inode->i_op->readlink(
			old_lower_dentry,
			(char __user *)symbuf,
			PATH_MAX);
		set_fs(oldfs);
		if (err < 0) {
			__clear(dentry, old_lower_dentry,
				new_lower_dentry);
			goto out_free;
		}
		symbuf[err] = '\0';
	}

	/* Now we lock the parent, and create the object in the new branch. */
	new_lower_parent_dentry = lock_parent(new_lower_dentry);

	/* create the new inode */
	err = __copyup_ndentry(old_lower_dentry, new_lower_dentry,
			       new_lower_parent_dentry, symbuf);

	if (err) {
		__clear(dentry, old_lower_dentry,
			new_lower_dentry);
		goto out_unlock;
	}

	/* We actually copyup the file here. */
	if (S_ISREG(old_lower_dentry->d_inode->i_mode))

		err= __copyup_reg_data(dentry,
				  new_lower_dentry,
				  old_lower_dentry,
				  copyup_file, 
				  len);

	if (err)
		goto out_unlink;

	/* Set permissions. */
	err = copyup_permissions(sb, old_lower_dentry, new_lower_dentry);
	if (err)
		goto out_unlink;

	goto out_unlock;

out_unlink:
	/*
	 * copyup failed, because we possibly ran out of space or
	 * quota, or something else happened so let's unlink; we don't
	 * really care about the return value of vfs_unlink
	 */
	vfs_unlink(new_lower_parent_dentry->d_inode, new_lower_dentry);

	if (copyup_file) {
		/* need to close the file */

		fput(*copyup_file);
	}

	/*
	 * TODO: should we reset the error to something like -EIO?
	 *
	 * If we don't reset, the user may get some nonsensical errors, but
	 * on the other hand, if we reset to EIO, we guarantee that the user
	 * will get a "confusing" error message.
	 */

out_unlock:
	unlock_dir(new_lower_parent_dentry);

out_free:
	/*
	 * If old_lower_dentry was not a file, then we need to dput it.  If
	 * it was a file, then it was already dput indirectly by other
	 * functions we call above which operate on regular files.
	 */
	if (old_lower_dentry && old_lower_dentry->d_inode &&
	    !S_ISREG(old_lower_dentry->d_inode->i_mode))
		dput(old_lower_dentry);
	kfree(symbuf);

	if (err) {
		/*
		 * if directory creation succeeded, but inode copyup failed,
		 * then purge new dentries.
		 */
		__clear(dentry, NULL,
				U2FS_D(dentry)->lower_path[LEFT].dentry);
		goto out;
	}
	if (!S_ISDIR(dentry->d_inode->i_mode)) {
		u2fs_postcopyup_release(dentry);
	}
	
	if (!u2fs_lower_inode(dentry->d_inode, LEFT)) {

		/* If we got here, then we copied up to an
		 * unlinked-open file, whose name is .u2fsXXXXX.*/
			 
		struct inode *inode = new_lower_dentry->d_inode;
		atomic_inc(&inode->i_count);
		u2fs_set_lower_inode(dentry->d_inode, inode, LEFT);
	}

	u2fs_postcopyup_setmnt(dentry);
	/* sync inode times from copied-up inode to our inode */
	u2fs_copy_attr_times(dentry->d_inode);

out:
	return err;
}

int copyup_file(struct inode *dir, struct file *file, loff_t len)
{
	int err = 0;
	struct file *output_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	
	err = copyup_dentry(dir, dentry,
			    dentry->d_name.name, 
			    dentry->d_name.len,
			    &output_file, len);
	
	if (!err) {
		u2fs_set_lower_file(file, output_file, LEFT);
	}

	return err;
}
