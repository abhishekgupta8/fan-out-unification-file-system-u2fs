#include "u2fs.h"
#include <linux/module.h>

/*
 * There is no need to lock the u2fs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int u2fs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb, *lower_sb1;
	struct path lower_path, lower_path1;
	char *path = ((char *)raw_data);
	char *dev_name;
	char *dev_name1;
	struct inode *inode;
	char *i= NULL, *j= NULL, *end, *first_path, *second_path;
	

	if (!path) {
		printk(KERN_ERR
		       "u2fs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	i = strstr(path, "ldir=");
	if(i == NULL){
		err = -EINVAL;
		goto out;
	}

	j = strstr(path, ",rdir=");
	if(j == NULL){
		err=-EINVAL;
		goto out;
	}

	end = strchr(path, '\0');

	first_path = kmalloc(sizeof(char)*(j-i-5), GFP_KERNEL);
	second_path = kmalloc(sizeof(char)*(end-j-6), GFP_KERNEL);
	strncpy(first_path, i+5 , j-i-6);
	first_path[j-i-6]='\0';
	strcpy(second_path, j+6);
	dev_name = first_path;
	dev_name1 = second_path;

	/* parse lower paths */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"u2fs: error accessing "
		       "lower left directory '%s'\n", dev_name);
		goto out;
	}
	
	err = kern_path(dev_name1, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path1);
	if (err) {
		printk(KERN_ERR	"u2fs: error accessing "
		       "lower right directory '%s'\n", dev_name1);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct u2fs_sb_info), GFP_KERNEL);
	if (!U2FS_SB(sb)) {
		printk(KERN_CRIT "u2fs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	/* set the lower superblock fields of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	u2fs_set_lower_super(sb, lower_sb, LEFT);
	lower_sb1 = lower_path1.dentry->d_sb;
	atomic_inc(&lower_sb1->s_active);
	u2fs_set_lower_super(sb, lower_sb1, RIGHT);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &u2fs_sops;

	/* get a new inode and allocate our root dentry */
	inode = u2fs_iget(sb, lower_path.dentry->d_inode, 
			lower_path1.dentry->d_inode, 2);

	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_alloc_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	
	sb-> s_root->d_op = NULL;
	sb->s_root->d_flags =(!(DCACHE_OP_HASH	|
				DCACHE_OP_COMPARE	|
				DCACHE_OP_REVALIDATE	|
				DCACHE_OP_DELETE));

	d_set_d_op(sb->s_root, &u2fs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	u2fs_set_lower_path(sb->s_root, &lower_path, LEFT);
	u2fs_set_lower_path(sb->s_root, &lower_path1, RIGHT);
	
	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_alloc_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "u2fs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	atomic_dec(&lower_sb1->s_active);
	kfree(U2FS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);
	path_put(&lower_path1);
out:
	return err;
}

struct dentry *u2fs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	void *lower_path_name = (void *) raw_data;
	
	return mount_nodev(fs_type, flags, lower_path_name,
			   u2fs_read_super);
}

static struct file_system_type u2fs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= U2FS_NAME,
	.mount		= u2fs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= FS_REVAL_DOT,
};

static int __init init_u2fs_fs(void)
{
	int err;
	pr_info("Registering u2fs student exp version" U2FS_VERSION "\n");
	
	err = u2fs_init_inode_cache();
	if (err)
		goto out;
	err = u2fs_init_dentry_cache();
	if (err)
		goto out;
	err = init_sioq();
	if (err)
		goto out;
	
	err = register_filesystem(&u2fs_fs_type);
out:
	if (err) {	
		stop_sioq();
		u2fs_destroy_inode_cache();
		u2fs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_u2fs_fs(void)
{	
	stop_sioq();
	u2fs_destroy_inode_cache();
	u2fs_destroy_dentry_cache();
	unregister_filesystem(&u2fs_fs_type);
	pr_info("Completed u2fs module unload\n");
}

MODULE_AUTHOR("Abhishek Gupta, abhishek.gupta@stonybrook.edu");
MODULE_DESCRIPTION("U2FS Student Exp Version" U2FS_VERSION);
MODULE_LICENSE("GPL");

module_init(init_u2fs_fs);
module_exit(exit_u2fs_fs);
