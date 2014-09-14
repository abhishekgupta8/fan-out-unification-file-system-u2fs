#include "u2fs.h"

/* The dentry cache is just so we have properly sized dentries */
static struct kmem_cache *u2fs_dentry_cachep;

int u2fs_init_dentry_cache(void)
{
	
	u2fs_dentry_cachep =
		kmem_cache_create("u2fs_dentry",
				  sizeof(struct u2fs_dentry_info),
				  0, SLAB_RECLAIM_ACCOUNT, NULL);

	return u2fs_dentry_cachep ? 0 : -ENOMEM;
}

void u2fs_destroy_dentry_cache(void)
{
	
	if (u2fs_dentry_cachep)
		kmem_cache_destroy(u2fs_dentry_cachep);
}

void free_dentry_private_data(struct dentry *dentry)
{
	
	if (!dentry || !dentry->d_fsdata)
		return;
	kmem_cache_free(u2fs_dentry_cachep, dentry->d_fsdata);
	dentry->d_fsdata = NULL;
}

/* allocate new dentry private data */
int new_dentry_private_data(struct dentry *dentry)
{
	struct u2fs_dentry_info *info = U2FS_D(dentry);
	
	/* use zalloc to init dentry_info.lower_path */
	info = kmem_cache_zalloc(u2fs_dentry_cachep, GFP_ATOMIC);
	if (!info)
		return -ENOMEM;
	memset((info)->lower_path, 0, (sizeof(struct path)*2));

	spin_lock_init(&info->lock);
	dentry->d_fsdata = info;

	return 0;
}

static int u2fs_inode_test(struct inode *inode, void *candidate_lower_inode)
{
	struct inode *current_lower_inode = u2fs_lower_inode(inode, LEFT);
	
	if (current_lower_inode == (struct inode *)candidate_lower_inode)
		return 1; /* found a match */
	else
		return 0; /* no match */
}

static int u2fs_inode_set(struct inode *inode, void *lower_inode)
{
	/* we do actual inode initialization in u2fs_iget */
	return 0;
}

struct inode *u2fs_iget(struct super_block *sb, struct inode *lower_inode, 
			struct inode *lower_inode1, int idx)
{
	struct u2fs_inode_info *info;
	struct inode *inode; /* the new inode to return */
	int err;
	unsigned long i_ino = iunique(sb, U2FS_ROOT_INO);
	
	inode = iget5_locked(sb, /* our superblock */
			     /*
			      * hashval: we use inode number, but we can
			      * also use "(unsigned long)lower_inode"
			      * instead.
			      */
			     i_ino, /* hashval */
			     u2fs_inode_test,	/* inode comparison function */
			     u2fs_inode_set, /* inode init function */
			     lower_inode); /* data passed to test+set fxns */
	if (!inode) {
		err = -EACCES;
		iput(lower_inode);
		return ERR_PTR(err);
	}
	/* if found a cached inode, then just return it */
	if (!(inode->i_state & I_NEW))
		return inode;

	/* initialize new inode */
	info = U2FS_I(inode);

	inode->i_ino = i_ino;
	if (!igrab(lower_inode)) {
		err = -ESTALE;
		return ERR_PTR(err);
	}
	if(idx != 2)
		u2fs_set_lower_inode(inode, lower_inode, idx);
	else{
		u2fs_set_lower_inode(inode, lower_inode, LEFT);
		u2fs_set_lower_inode(inode, lower_inode1, RIGHT);
	}

	inode->i_version++;

	/* use different set of inode ops for symlinks & directories */
	if (S_ISDIR(lower_inode->i_mode))
		inode->i_op = &u2fs_dir_iops;
	else if (S_ISLNK(lower_inode->i_mode))
		inode->i_op = &u2fs_symlink_iops;
	else
		inode->i_op = &u2fs_main_iops;

	/* use different set of file ops for directories */
	if (S_ISDIR(lower_inode->i_mode))
		inode->i_fop = &u2fs_dir_fops;
	else
		inode->i_fop = &u2fs_main_fops;

	inode->i_mapping->a_ops = &u2fs_aops;

	inode->i_atime.tv_sec = 0;
	inode->i_atime.tv_nsec = 0;
	inode->i_mtime.tv_sec = 0;
	inode->i_mtime.tv_nsec = 0;
	inode->i_ctime.tv_sec = 0;
	inode->i_ctime.tv_nsec = 0;

	/* properly initialize special inodes */
	if (S_ISBLK(lower_inode->i_mode) || S_ISCHR(lower_inode->i_mode) ||
	    S_ISFIFO(lower_inode->i_mode) || S_ISSOCK(lower_inode->i_mode))
		init_special_inode(inode, lower_inode->i_mode,
				   lower_inode->i_rdev);

	/* all well, copy inode attributes */
	fsstack_copy_attr_all(inode, lower_inode);
	fsstack_copy_inode_size(inode, lower_inode);

	unlock_new_inode(inode);
	return inode;
}

/*
 * Connect a u2fs inode dentry/inode with several lower ones.  This is
 * the classic stackable file system "vnode interposition" action.
 *
 * @dentry: u2fs's dentry which interposes on lower one
 * @sb: u2fs's super_block
 * @lower_path: the lower path (caller does path_get/put)
 */
int u2fs_interpose(struct dentry *dentry, struct super_block *sb,
		     struct path *lower_path, int idx)
{
	int err = 0;
	struct inode *inode;
	struct inode *lower_inode;
	struct super_block *lower_sb;
	
	lower_inode = lower_path->dentry->d_inode;
	lower_sb = u2fs_lower_super(sb, idx);

	/* check that the lower file system didn't cross a mount point */
	if (lower_inode->i_sb != lower_sb) {
		err = -EXDEV;
		goto out;
	}

	/*
	 * We allocate our new inode below by calling u2fs_iget,
	 * which will initialize some of the new inode's fields
	 */

	/* inherit lower inode number for u2fs's inode */
	inode = u2fs_iget(sb, lower_inode, NULL, idx);

	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	d_add(dentry, inode);

out:
	return err;
}

/*
 * Main driver function for u2fs's lookup.
 *
 * Returns: NULL (ok), ERR_PTR if an error occurred.
 * Fills in lower_parent_path with <dentry,mnt> on success.
 */
static struct dentry *__u2fs_lookup(struct dentry *dentry, int flags,
				      struct dentry *parent, int idx)
{
	int err = 0;
	struct vfsmount *lower_dir_mnt;
	struct dentry *lower_dir_dentry = NULL;
	struct dentry *lower_dentry;
	struct path lower_parent_path;
	const char *name;
	struct path lower_path;
	struct qstr this;
	int neg_check=0;
	

	/* getting lower parent path */
	if(idx != 2){
		u2fs_get_lower_path(parent, &lower_parent_path, idx);
	}
	else{
		if((U2FS_D(parent)->lower_path[LEFT].dentry) != NULL && 
			(U2FS_D(parent)->lower_path[LEFT].mnt) != NULL){
			u2fs_get_lower_path(parent, &lower_parent_path, LEFT);
			neg_check = LEFT;
		}
		else{
			u2fs_get_lower_path(parent, &lower_parent_path, RIGHT);
			neg_check = RIGHT;
		}
	}

	/* must initialize dentry operations */
	d_set_d_op(dentry, &u2fs_dops);

	if (IS_ROOT(dentry))
		goto out;
	
	name = dentry->d_name.name;

	/* now start the actual lookup procedure */
	lower_dir_dentry = lower_parent_path.dentry;
	lower_dir_mnt = lower_parent_path.mnt;

	/* Use vfs_path_lookup to check if the dentry exists or not */
	err = vfs_path_lookup(lower_dir_dentry, lower_dir_mnt, name, 0,
			      &lower_path);
	
	/* no error: handle positive dentries */
	if (!err) {
		u2fs_set_lower_path(dentry, &lower_path, idx);
		
		if(dentry->d_inode){
			u2fs_set_lower_inode(dentry->d_inode, 
				lower_path.dentry->d_inode, idx);
		}
		else{
		err = u2fs_interpose(dentry, dentry->d_sb, &lower_path, idx);
		if (err) /* path_put underlying path on error */
			u2fs_put_reset_lower_path(dentry, idx);
		goto out;
		}
	}

	/*
	 * We don't consider ENOENT an error, and we want to return a
	 * negative dentry.
	 */
	if (err && err != -ENOENT)
		goto out;

	if(idx == 2){

		/* now start the actual lookup procedure */
		lower_dir_dentry = lower_parent_path.dentry;
		lower_dir_mnt = lower_parent_path.mnt;

		/* instatiate a new negative dentry */
		this.name = name;
		this.len = strlen(name);
		this.hash = full_name_hash(this.name, this.len);
		lower_dentry = d_lookup(lower_dir_dentry, &this);
		if (lower_dentry)
			goto setup_lower;

		lower_dentry = d_alloc(lower_dir_dentry, &this);
		if (!lower_dentry) {
			err = -ENOMEM;
			goto out;
		}
		d_add(lower_dentry, NULL); /* instantiate and hash */

	setup_lower:
		lower_path.dentry = lower_dentry;
		lower_path.mnt = mntget(lower_dir_mnt);
		u2fs_set_lower_path(dentry, &lower_path, neg_check);
	
	/*
	 * If the intent is to create a file, then don't return an error, so
	 * the VFS will continue the process of making this negative dentry
	 * into a positive one.
	 */
	if (flags & (LOOKUP_CREATE|LOOKUP_RENAME_TARGET))
		err = 0;
	}
out:
	u2fs_put_lower_path(parent, &lower_parent_path);
	return ERR_PTR(err);
}

struct dentry *u2fs_lookup(struct inode *dir, struct dentry *dentry,
			     struct nameidata *nd)
{
	struct dentry *ret_left= ERR_PTR(-ENOENT), 
		*ret_right= ERR_PTR(-ENOENT);
	struct dentry *parent;
	struct dentry *wh_dentry = NULL;
	int err = 0;
	bool is_whiteout;
	int len;
	char *name = (char *)dentry->d_name.name;
	

	BUG_ON(!nd);

	parent = dget_parent(dentry);

	/* checking if whiteout name */
	len = dentry->d_name.len;
	is_whiteout = is_whiteout_name(&name, &len);

	if(is_whiteout){
		err = -ENOENT;
		goto out;
	}

	/* allocate dentry private data.  We free it in ->d_release */
	err = new_dentry_private_data(dentry);
	if (err) {
		ret_left = ERR_PTR(err);
		goto out;
	}
	
	/* checking in left branch */
	if((U2FS_D(parent)->lower_path[LEFT].dentry) != NULL && 
		(U2FS_D(parent)->lower_path[LEFT].mnt) != NULL){

		/* checking for whiteouts */
		wh_dentry = lookup_whiteout(dentry->d_name.name, 
				U2FS_D(parent)->lower_path[LEFT].dentry);
		
		if(IS_ERR(wh_dentry)){
			err = PTR_ERR(wh_dentry);
			goto out;
		}
		
		ret_left = __u2fs_lookup(dentry, nd->flags, parent, LEFT);
		if (IS_ERR(ret_left))
			goto check_right;	
		if (ret_left)
			dentry = ret_left;
		if (dentry->d_inode)
			fsstack_copy_attr_times(dentry->d_inode,
				u2fs_lower_inode(dentry->d_inode, LEFT));
		/* update parent directory's atime */
		fsstack_copy_attr_atime(parent->d_inode,
				u2fs_lower_inode(parent->d_inode, LEFT));
	}

check_right:
		if(wh_dentry){	

			if(!IS_WRITE_FLAG(nd->flags)){
	
				if(wh_dentry->d_inode){
					if(IS_ERR(ret_left))
						err = -ENOENT;
					goto out;
				}
			}

			if(IS_WRITE_FLAG(nd->flags) && wh_dentry->d_inode)
				goto check_neg_dentry;
		}

	/* checking in right branch */
	if((U2FS_D(parent)->lower_path[RIGHT].dentry) != NULL && 
		(U2FS_D(parent)->lower_path[RIGHT].mnt) != NULL){
		
		ret_right = __u2fs_lookup(dentry, nd->flags, parent, RIGHT);
		if (IS_ERR(ret_right))
			goto check_neg_dentry;
		if (ret_right)
			dentry = ret_right;
		if (dentry->d_inode && IS_ERR(ret_left))
			fsstack_copy_attr_times(dentry->d_inode,
				u2fs_lower_inode(dentry->d_inode, RIGHT));

		/* update parent directory's atime */
			fsstack_copy_attr_atime(parent->d_inode,
					u2fs_lower_inode(parent->d_inode, 
					RIGHT));
	}

check_neg_dentry:
	if((!(IS_ERR(ret_left))) || (!(IS_ERR(ret_right))))
		goto out;

	ret_right = __u2fs_lookup(dentry, nd->flags, parent, 2);
out:
	
	dput(parent);

	if(IS_ERR(ret_right))
		return ret_left;
	else
		return ret_right;
}
