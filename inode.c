#include "u2fs.h"

static int u2fs_create(struct inode *dir, struct dentry *dentry,
			 int mode, struct nameidata *nd)
{
	int err = 0;
	struct dentry *lower_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
	struct dentry *parent= NULL;
	struct dentry *ret=NULL;
	struct path lower_path, saved_path;
	const char *name;
	unsigned int namelen;
	struct dentry *right_parent_dentry = NULL;	
	struct dentry *right_lower_dentry = NULL;
	
	/* creating parent directories if destination is read-only */
	if((U2FS_D(dentry)->lower_path[LEFT].dentry) == NULL && 
		(U2FS_D(dentry)->lower_path[LEFT].mnt) == NULL){

		parent = dget_parent(dentry);
		
		right_parent_dentry = U2FS_D(parent)->lower_path[RIGHT].dentry;

		ret = create_parents(parent->d_inode, dentry,
					      dentry->d_name.name);
		if (!ret || IS_ERR(ret)) {
				err = PTR_ERR(ret);
				if (!IS_COPYUP_ERR(err))
					printk(KERN_ERR
				      	 "u2fs: create_parents for "
			     		  "u2fs_create failed"
				      	 "err=%d\n", err);
				goto out_copyup;
		}
		u2fs_postcopyup_setmnt(dentry);
		u2fs_put_reset_lower_path(dentry, RIGHT);
	}

	u2fs_get_lower_path(dentry, &lower_path, LEFT);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;

	pathcpy(&saved_path, &nd->path);
	pathcpy(&nd->path, &lower_path);

	err = vfs_create(lower_parent_dentry->d_inode, lower_dentry, mode, nd);
	pathcpy(&nd->path, &saved_path);
	if (err)
		goto out;

	/* looking if the file already exists in right_dir to link inode */
	if((U2FS_D(dentry)->lower_path[RIGHT].dentry) != NULL && 
		(U2FS_D(dentry)->lower_path[RIGHT].mnt) != NULL){
		
		name = dentry->d_name.name;
		namelen = dentry->d_name.len;

		right_lower_dentry = lookup_one_len(name, lower_parent_dentry,
					      namelen);

		dentry->d_inode = right_lower_dentry->d_inode;

		u2fs_set_lower_inode(dentry->d_inode, lower_dentry->d_inode, 
					LEFT);
	}
	else
		err = u2fs_interpose(dentry, dir->i_sb, &lower_path, LEFT);

	if (err)
		goto out;

	fsstack_copy_attr_times(dir, u2fs_lower_inode(dir, LEFT));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	u2fs_put_lower_path(dentry, &lower_path);
out_copyup:
	if(parent != NULL)
		dput(parent);
	return err;
}

static int u2fs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err=0;
	int idx;
	struct dentry *ret = NULL;
	struct path lower_old_path, lower_new_path;
	

	file_size_save = i_size_read(old_dentry->d_inode);

	if((U2FS_D(old_dentry)->lower_path[LEFT].dentry != NULL) &&
	(U2FS_D(old_dentry)->lower_path[LEFT].mnt != NULL)){
		u2fs_get_lower_path(old_dentry, &lower_old_path, LEFT);
		idx = LEFT;
	}
	else{
		u2fs_get_lower_path(old_dentry, &lower_old_path, RIGHT);
		idx = RIGHT;
	}

	/* creating parent directories if destination is read-only */
	if((U2FS_D(new_dentry)->lower_path[LEFT].dentry) == NULL && 
		(U2FS_D(new_dentry)->lower_path[LEFT].mnt) == NULL){

		ret = create_parents(dir, new_dentry, 
					new_dentry->d_name.name);

		if (!ret || IS_ERR(ret)) {
					err = PTR_ERR(ret);
					if (!IS_COPYUP_ERR(err))
						printk(KERN_ERR
					      	 "u2fs: create_parents for "
				     		  "u2fs_link failed"
					      	 "err=%d\n", err);
					goto out_copyup;
		}
		u2fs_postcopyup_setmnt(new_dentry);
		u2fs_put_reset_lower_path(new_dentry, RIGHT);
		
		if(err)
			goto out_copyup;	
	}

	u2fs_get_lower_path(new_dentry, &lower_new_path, LEFT);

	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = mnt_want_write(lower_new_path.mnt);
	if (err)
		goto out_unlock;

	err = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
		       lower_new_dentry);
	if (err || !lower_new_dentry->d_inode)
		goto out;

	err = u2fs_interpose(new_dentry, dir->i_sb, &lower_new_path, LEFT);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_new_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_new_dentry->d_inode);
	set_nlink(old_dentry->d_inode,
		  u2fs_lower_inode(old_dentry->d_inode, idx)->i_nlink);
	i_size_write(new_dentry->d_inode, file_size_save);
out:
	mnt_drop_write(lower_new_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	u2fs_put_lower_path(new_dentry, &lower_new_path);
out_copyup:
	u2fs_put_lower_path(old_dentry, &lower_old_path);
	return err;
}

static int u2fs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err=0;
	struct dentry *lower_dentry = NULL;
	struct inode *lower_dir_inode;
	struct inode *lower_inode;
	struct dentry *lower_dir_dentry = NULL;
	struct path lower_path;
	
	/* creating whiteout if file unlinked from read-only branch */
	if((U2FS_D(dentry)->lower_path[LEFT].dentry) == NULL && 
		(U2FS_D(dentry)->lower_path[LEFT].mnt) == NULL){

		err = create_whiteout(dentry);	
		if(err)
			err = -EIO;
		goto out_whiteout;
	}
	else{
		u2fs_get_lower_path(dentry, &lower_path, LEFT);
		lower_dir_inode = u2fs_lower_inode(dir, LEFT);
		lower_inode = u2fs_lower_inode(dentry->d_inode, LEFT);
	}

	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_unlink(lower_dir_inode, lower_dentry);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(dentry->d_inode, lower_inode->i_nlink);
	dentry->d_inode->i_ctime = dir->i_ctime;
	
out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	u2fs_put_lower_path(dentry, &lower_path);

	/* checking for same file in right branch */
	if((U2FS_D(dentry)->lower_path[RIGHT].dentry) != NULL && 
		(U2FS_D(dentry)->lower_path[RIGHT].mnt) != NULL){

		err = create_whiteout(dentry);
		if(err)
			err = -EIO;
	}
	d_drop(dentry);
out_whiteout:
	return err;
}

static int u2fs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;
	struct dentry *ret = NULL;
	
	/* creating parent directories if destination is read-only */
	if((U2FS_D(dentry)->lower_path[LEFT].dentry == NULL) &&
	(U2FS_D(dentry)->lower_path[LEFT].mnt == NULL)){

		ret = create_parents(dir, dentry, 
					dentry->d_name.name);

		if (!ret || IS_ERR(ret)) {
					err = PTR_ERR(ret);
					if (!IS_COPYUP_ERR(err))
						printk(KERN_ERR
					      	 "u2fs: create_parents for "
				     		  "u2fs_symlink failed"
					      	 "err=%d\n", err);
					goto out_copyup;
		}
		u2fs_postcopyup_setmnt(dentry);
		u2fs_put_reset_lower_path(dentry, RIGHT);
		
		if(err)
			goto out_copyup;	

	}

	u2fs_get_lower_path(dentry, &lower_path, LEFT);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_symlink(lower_parent_dentry->d_inode, lower_dentry, symname);
	if (err)
		goto out;

	err = u2fs_interpose(dentry, dir->i_sb, &lower_path, LEFT);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, u2fs_lower_inode(dir, LEFT));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	u2fs_put_lower_path(dentry, &lower_path);
out_copyup:
	return err;
}

static int u2fs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;
	struct dentry *ret = NULL;
	
	/* creating parent directories if destination is read-only */
	if((U2FS_D(dentry)->lower_path[LEFT].dentry) == NULL && 
		(U2FS_D(dentry)->lower_path[LEFT].mnt) == NULL){

		ret = create_parents(dir, dentry, dentry->d_name.name);

		if (!ret || IS_ERR(ret)) {
				err = PTR_ERR(ret);
				if (!IS_COPYUP_ERR(err))
					printk(KERN_ERR
				      	 "u2fs: create_parents for "
			     		  "u2fs_mkdir failed"
				      	 "err=%d\n", err);
				goto out_copyup;
		}
		u2fs_postcopyup_setmnt(dentry);
		u2fs_put_reset_lower_path(dentry, RIGHT);
	}

	u2fs_get_lower_path(dentry, &lower_path, LEFT);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_mkdir(lower_parent_dentry->d_inode, lower_dentry, mode);
	if (err)
		goto out;

	err = u2fs_interpose(dentry, dir->i_sb, &lower_path, LEFT);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, u2fs_lower_inode(dir, LEFT));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
	/* update number of links on parent directory */
	set_nlink(dir, u2fs_lower_inode(dir, LEFT)->i_nlink);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	u2fs_put_lower_path(dentry, &lower_path);
out_copyup:
	return err;
}

static int u2fs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;
	
	/* creating whiteout if directory was in read-only */
	if((U2FS_D(dentry)->lower_path[LEFT].dentry) == NULL && 
		(U2FS_D(dentry)->lower_path[LEFT].mnt) == NULL){

		err = create_whiteout(dentry);	
		if(err)
			err = -EIO;
		goto out_whiteout;
	}
	
	u2fs_get_lower_path(dentry, &lower_path, LEFT);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	
	err = vfs_rmdir(lower_dir_dentry->d_inode, lower_dentry);
	
	if (err)
		goto out;
	if (dentry->d_inode)
		clear_nlink(dentry->d_inode);
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	set_nlink(dir, lower_dir_dentry->d_inode->i_nlink);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	u2fs_put_lower_path(dentry, &lower_path);

	/* creating whiteout if file as existing in both branches */
	if((U2FS_D(dentry)->lower_path[RIGHT].dentry) != NULL && 
		(U2FS_D(dentry)->lower_path[RIGHT].mnt) != NULL){
		err = create_whiteout(dentry);	
		if(err)
			err = -EIO;
	}
	d_drop(dentry);
out_whiteout:
	return err;
}

static int u2fs_mknod(struct inode *dir, struct dentry *dentry, int mode,
			dev_t dev)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;
	struct dentry *ret = NULL;

	/* creating parent directories if destination is read-only */
	if((U2FS_D(dentry)->lower_path[LEFT].dentry) == NULL && 
		(U2FS_D(dentry)->lower_path[LEFT].mnt) == NULL){

		ret = create_parents(dir, dentry, dentry->d_name.name);

		if (!ret || IS_ERR(ret)) {
				err = PTR_ERR(ret);
				if (!IS_COPYUP_ERR(err))
					printk(KERN_ERR
				      	 "u2fs: create_parents for "
			     		  "u2fs_mknod failed"
				      	 "err=%d\n", err);
				goto out_copyup;
		}
		u2fs_postcopyup_setmnt(dentry);
		u2fs_put_reset_lower_path(dentry, RIGHT);
	}

	u2fs_get_lower_path(dentry, &lower_path, LEFT);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_mknod(lower_parent_dentry->d_inode, lower_dentry, mode, dev);
	if (err)
		goto out;

	err = u2fs_interpose(dentry, dir->i_sb, &lower_path, LEFT);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, u2fs_lower_inode(dir, LEFT));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	u2fs_put_lower_path(dentry, &lower_path);
out_copyup:
	return err;
}

/*
 * The locking rules in u2fs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int u2fs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct dentry *ret = NULL;
	struct path lower_old_path, lower_new_path;
	
	/* creating parent directories if destination is read-only */
	if((U2FS_D(old_dentry)->lower_path[LEFT].dentry) == NULL && 
		(U2FS_D(old_dentry)->lower_path[LEFT].mnt) == NULL){

		err = create_whiteout(old_dentry);	
		if(err){
			err = -EIO;
			goto out_copyup;
		}

		err = copyup_dentry(old_dir, old_dentry,
			  old_dentry->d_name.name, old_dentry->d_name.len,
			  NULL, i_size_read(old_dentry->d_inode));
		if(err)
			goto out_copyup;
	}
	
	if((U2FS_D(new_dentry)->lower_path[LEFT].dentry) == NULL && 
		(U2FS_D(new_dentry)->lower_path[LEFT].mnt) == NULL){

		ret = create_parents(new_dir, new_dentry, 
					new_dentry->d_name.name);

		if (!ret || IS_ERR(ret)) {
					err = PTR_ERR(ret);
					if (!IS_COPYUP_ERR(err))
						printk(KERN_ERR
					      	 "u2fs: create_parents for "
				     		  "u2fs_rename failed"
					      	 "err=%d\n", err);
					goto out_copyup;
		}
		u2fs_postcopyup_setmnt(new_dentry);
		u2fs_put_reset_lower_path(new_dentry, RIGHT);
		
		if(err)
			goto out_copyup;
	}
	
	u2fs_get_lower_path(old_dentry, &lower_old_path, LEFT);
	u2fs_get_lower_path(new_dentry, &lower_new_path, LEFT);

	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = mnt_want_write(lower_old_path.mnt);
	if (err)
		goto out;
	err = mnt_want_write(lower_new_path.mnt);
	if (err)
		goto out_drop_old_write;

	err = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			 lower_new_dir_dentry->d_inode, lower_new_dentry);
	if (err)
		goto out_err;

	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode);
	fsstack_copy_inode_size(new_dir, lower_new_dir_dentry->d_inode);
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      lower_old_dir_dentry->d_inode);
		fsstack_copy_inode_size(old_dir,
					lower_old_dir_dentry->d_inode);
	}

out_err:
	mnt_drop_write(lower_new_path.mnt);
out_drop_old_write:
	mnt_drop_write(lower_old_path.mnt);
out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	u2fs_put_lower_path(old_dentry, &lower_old_path);
	u2fs_put_lower_path(new_dentry, &lower_new_path);
out_copyup:
	return err;
}

static int u2fs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;
	

	if((U2FS_D(dentry)->lower_path[LEFT].dentry) != NULL && 
		(U2FS_D(dentry)->lower_path[LEFT].mnt) != NULL)

		u2fs_get_lower_path(dentry, &lower_path, LEFT);
	else
		u2fs_get_lower_path(dentry, &lower_path, RIGHT);

	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_inode->i_op ||
	    !lower_dentry->d_inode->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(dentry->d_inode, lower_dentry->d_inode);

out:
	u2fs_put_lower_path(dentry, &lower_path);
	return err;
}

static void *u2fs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;
	
	
	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		goto out;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = u2fs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
out:
	nd_set_link(nd, buf);
	return NULL;
}

/* this @nd *IS* still used */
static void u2fs_put_link(struct dentry *dentry, struct nameidata *nd,
			    void *cookie)
{
	char *buf = nd_get_link(nd);
	
	if (!IS_ERR(buf))	/* free the char* */
		kfree(buf);
}

static int u2fs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err=0;
	
	
	if(U2FS_I(inode)->lower_inode[LEFT] != NULL)
		lower_inode = u2fs_lower_inode(inode, LEFT);
	else
		lower_inode = u2fs_lower_inode(inode, RIGHT);

	err = inode_permission(lower_inode, mask);
	return err;
}

static int u2fs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err = 0;
	struct dentry *lower_dentry=NULL;
	struct inode *inode;
	struct inode *lower_inode=NULL;
	struct dentry *parent = NULL;
	struct path lower_path;
	struct iattr lower_ia;
	
	inode = dentry->d_inode;

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;

	/* creating parent directories if destination is read-only */
	if((U2FS_D(dentry)->lower_path[LEFT].dentry) == NULL && 
		(U2FS_D(dentry)->lower_path[LEFT].mnt) == NULL){

		parent = dget_parent(dentry);

		err = copyup_dentry(parent->d_inode, dentry,
			  dentry->d_name.name, dentry->d_name.len,
			  NULL, i_size_read(dentry->d_inode));
		if(err)
			goto out;
	}

	u2fs_get_lower_path(dentry, &lower_path, LEFT);
	lower_dentry = lower_path.dentry;
	lower_inode = u2fs_lower_inode(inode, LEFT);	

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = u2fs_lower_file(ia->ia_file, LEFT);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use lower_dentry->d_inode, because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	err = notify_change(lower_dentry, &lower_ia); /* note: lower_ia */
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:	
	if(parent != NULL)
		dput(parent);
	u2fs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

const struct inode_operations u2fs_symlink_iops = {
	.readlink	= u2fs_readlink,
	.permission	= u2fs_permission,
	.follow_link	= u2fs_follow_link,
	.setattr	= u2fs_setattr,
	.put_link	= u2fs_put_link,
};

const struct inode_operations u2fs_dir_iops = {
	.create		= u2fs_create,
	.lookup		= u2fs_lookup,
	.link		= u2fs_link,
	.unlink		= u2fs_unlink,
	.symlink	= u2fs_symlink,
	.mkdir		= u2fs_mkdir,
	.rmdir		= u2fs_rmdir,
	.mknod		= u2fs_mknod,
	.rename		= u2fs_rename,
	.permission	= u2fs_permission,
	.setattr	= u2fs_setattr,
};

const struct inode_operations u2fs_main_iops = {
	.permission	= u2fs_permission,
	.setattr	= u2fs_setattr,
};
