#include "u2fs.h"

/*
 * The inode cache is used with alloc_inode for both our inode info and the
 * vfs inode.
 */
static struct kmem_cache *u2fs_inode_cachep;

/* final actions when unmounting a file system */
static void u2fs_put_super(struct super_block *sb)
{
	struct u2fs_sb_info *spd;
	struct super_block *s;
	
	spd = U2FS_SB(sb);
	if (!spd)
		return;

	/* decrement lower super references */
	s = u2fs_lower_super(sb, LEFT);
	u2fs_set_lower_super(sb, NULL, LEFT);
	atomic_dec(&s->s_active);

	s = u2fs_lower_super(sb, RIGHT);
	u2fs_set_lower_super(sb, NULL, RIGHT);
	atomic_dec(&s->s_active);

	kfree(spd);
	sb->s_fs_info = NULL;
}

static int u2fs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int err;
	struct path lower_path, lower_path1;
	

	u2fs_get_lower_path(dentry, &lower_path, LEFT);
	err = vfs_statfs(&lower_path, buf);
	u2fs_put_lower_path(dentry, &lower_path);
	u2fs_get_lower_path(dentry, &lower_path1, RIGHT);
	err = vfs_statfs(&lower_path1, buf);
	u2fs_put_lower_path(dentry, &lower_path1);

	/* set return buf to our f/s to avoid confusing user-level utils */
	buf->f_type = WRAPFS_SUPER_MAGIC;

	return err;
}

/*
 * @flags: numeric mount options
 * @options: mount options string
 */
static int u2fs_remount_fs(struct super_block *sb, int *flags, char *options)
{
	int err = 0;
	
	/*
	 * The VFS will take care of "ro" and "rw" flags among others.  We
	 * can safely accept a few flags (RDONLY, MANDLOCK), and honor
	 * SILENT, but anything else left over is an error.
	 */
	if ((*flags & ~(MS_RDONLY | MS_MANDLOCK | MS_SILENT)) != 0) {
		printk(KERN_ERR
		       "u2fs: remount flags 0x%x unsupported\n", *flags);
		err = -EINVAL;
	}

	return err;
}

/*
 * Called by iput() when the inode reference count reached zero
 * and the inode is not hashed anywhere.  Used to clear anything
 * that needs to be, before the inode is completely destroyed and put
 * on the inode free list.
 */
static void u2fs_evict_inode(struct inode *inode)
{
	struct inode *lower_inode;
	
	truncate_inode_pages(&inode->i_data, 0);
	end_writeback(inode);
	/*
	 * Decrement a reference to a lower_inode, which was incremented
	 * by our read_inode when it was created initially.
	 */
	if(U2FS_I(inode)->lower_inode[LEFT] != NULL){
		lower_inode = u2fs_lower_inode(inode, LEFT);
		u2fs_set_lower_inode(inode, NULL, LEFT);
		iput(lower_inode);
	}

	if(U2FS_I(inode)->lower_inode[RIGHT] != NULL){
		lower_inode = u2fs_lower_inode(inode, RIGHT);
		u2fs_set_lower_inode(inode, NULL, RIGHT);
		iput(lower_inode);
	}
}

static struct inode *u2fs_alloc_inode(struct super_block *sb)
{
	struct u2fs_inode_info *i;
	
	i = kmem_cache_alloc(u2fs_inode_cachep, GFP_KERNEL);
	if (!i)
		return NULL;

	/* memset everything up to the inode to 0 */
	memset(i, 0, offsetof(struct u2fs_inode_info, vfs_inode));

	i->vfs_inode.i_version = 1;
	return &i->vfs_inode;
}

static void u2fs_destroy_inode(struct inode *inode)
{
	
	kmem_cache_free(u2fs_inode_cachep, U2FS_I(inode));
}

/* u2fs inode cache constructor */
static void init_once(void *obj)
{
	struct u2fs_inode_info *i = obj;
	
	inode_init_once(&i->vfs_inode);
}

int u2fs_init_inode_cache(void)
{
	int err = 0;
	
	u2fs_inode_cachep =
		kmem_cache_create("u2fs_inode_cache",
				  sizeof(struct u2fs_inode_info), 0,
				  SLAB_RECLAIM_ACCOUNT, init_once);
	if (!u2fs_inode_cachep)
		err = -ENOMEM;
	return err;
}

/* u2fs inode cache destructor */
void u2fs_destroy_inode_cache(void)
{
	
	if (u2fs_inode_cachep)
		kmem_cache_destroy(u2fs_inode_cachep);

}

/*
 * Used only in nfs, to kill any pending RPC tasks, so that subsequent
 * code can actually succeed and won't leave tasks that need handling.
 */
static void u2fs_umount_begin(struct super_block *sb)
{
	struct super_block *lower_sb, *lower_sb1;
	
	lower_sb = u2fs_lower_super(sb, LEFT);
	if (lower_sb && lower_sb->s_op && lower_sb->s_op->umount_begin)
		lower_sb->s_op->umount_begin(lower_sb);

	lower_sb1 = u2fs_lower_super(sb, RIGHT);
	if (lower_sb1 && lower_sb1->s_op && lower_sb1->s_op->umount_begin)
		lower_sb1->s_op->umount_begin(lower_sb1);
}

const struct super_operations u2fs_sops = {
	.put_super	= u2fs_put_super,
	.statfs		= u2fs_statfs,
	.remount_fs	= u2fs_remount_fs,
	.evict_inode	= u2fs_evict_inode,
	.umount_begin	= u2fs_umount_begin,
	.show_options	= generic_show_options,
	.alloc_inode	= u2fs_alloc_inode,
	.destroy_inode	= u2fs_destroy_inode,
	.drop_inode	= generic_delete_inode,
};
