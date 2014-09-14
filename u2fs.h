#ifndef _U2FS_H_
#define _U2FS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include "sioq.h"

/* the file system name */
#define U2FS_NAME "u2fs"

/* u2fs root inode number */
#define U2FS_ROOT_INO     1

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

/* useful to set index */
#define LEFT 0
#define RIGHT 1

/* root inode number */
#define U2FS_ROOT_INO 1

/* u2fs_permission, check if we should bypass error to facilitate copyup */
#define IS_COPYUP_ERR(err) ((err) == -EROFS)

/* for locking whiteouts */
#define U2FS_DMUTEX_WHITEOUT 4

/* unionfs_open, check if we need to copyup the file */
#define OPEN_WRITE_FLAGS (O_WRONLY | O_RDWR | O_APPEND)
#define IS_WRITE_FLAG(flag) ((flag) & OPEN_WRITE_FLAGS)

/* operations vectors defined in specific files */
extern const struct file_operations u2fs_main_fops;
extern const struct file_operations u2fs_dir_fops;
extern const struct inode_operations u2fs_main_iops;
extern const struct inode_operations u2fs_dir_iops;
extern const struct inode_operations u2fs_symlink_iops;
extern const struct super_operations u2fs_sops;
extern const struct dentry_operations u2fs_dops;
extern const struct address_space_operations u2fs_aops, u2fs_dummy_aops;
extern const struct vm_operations_struct u2fs_vm_ops;

extern int u2fs_init_inode_cache(void);
extern void u2fs_destroy_inode_cache(void);
extern int u2fs_init_dentry_cache(void);
extern void u2fs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *u2fs_lookup(struct inode *dir, struct dentry *dentry,
				    struct nameidata *nd);
extern struct inode *u2fs_iget(struct super_block *sb,
				 struct inode *lower_inode,
				 struct inode *lower_inode1, int idx);
extern int u2fs_interpose(struct dentry *dentry, struct super_block *sb,
			    struct path *lower_path, int idx);
extern int copyup_file(struct inode *dir, struct file *file, loff_t len);
extern int copyup_dentry(struct inode *dir, struct dentry *dentry,
		  const char *name, int namelen,
		  struct file **copyup_file, loff_t len);
extern void release_lower_nd(struct nameidata *nd, int err);
extern int init_lower_nd(struct nameidata *nd, unsigned int flags);
extern struct dentry *create_parents(struct inode *dir, struct dentry *dentry,
					const char *name);
extern int create_whiteout(struct dentry *dentry);
extern struct dentry *lookup_whiteout(const char *name, 
					struct dentry *lower_parent);
extern void u2fs_postcopyup_setmnt(struct dentry *dentry);
extern bool is_whiteout_name(char **namep, int *namelenp);

struct u2fs_getdents_callback {
	void *dirent;
	filldir_t filldir;
	struct dentry *lower_parent_dentry;
	off_t offset;
	int idx;
	char **dup_name;
	int dup_count;
};

/* file private data */
struct u2fs_file_info {
	struct file *lower_file[2];
	const struct vm_operations_struct *lower_vm_ops;
};

/* u2fs inode data in memory */
struct u2fs_inode_info {
	struct inode *lower_inode[2];
	struct inode vfs_inode;
};

/* u2fs dentry data in memory */
struct u2fs_dentry_info {
	spinlock_t lock;	/* protects lower_path */
	struct path lower_path[2];
};

/* u2fs super-block data in memory */
struct u2fs_sb_info {
	struct super_block *lower_sb[2];
};

/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * u2fs_inode_info structure, U2FS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct u2fs_inode_info *U2FS_I(const struct inode *inode)
{
	return container_of(inode, struct u2fs_inode_info, vfs_inode);
}

/* dentry to private data */
#define U2FS_D(dent) ((struct u2fs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define U2FS_SB(super) ((struct u2fs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define U2FS_F(file) ((struct u2fs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *u2fs_lower_file(const struct file *f, int idx)
{
	return U2FS_F(f)->lower_file[idx];
}

static inline void u2fs_set_lower_file(struct file *f, struct file *val, 
					int idx)
{
	U2FS_F(f)->lower_file[idx] = val;
}

/* inode to lower inode. */
static inline struct inode *u2fs_lower_inode(const struct inode *i, int idx)
{
	return U2FS_I(i)->lower_inode[idx];
}

static inline void u2fs_set_lower_inode(struct inode *i, struct inode *val, 
					int idx)
{
	U2FS_I(i)->lower_inode[idx] = val;
}

/* superblock to lower superblock */
static inline struct super_block *u2fs_lower_super(
	const struct super_block *sb, int idx)
{
	return U2FS_SB(sb)->lower_sb[idx];
}

static inline void u2fs_set_lower_super(struct super_block *sb,
					struct super_block *val, int idx)
{
	U2FS_SB(sb)->lower_sb[idx] = val;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void u2fs_get_lower_path(const struct dentry *dent,
					struct path *lower_path, int idx)
{
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(lower_path, &U2FS_D(dent)->lower_path[idx]);
	path_get(lower_path);
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}
static inline void u2fs_put_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	path_put(lower_path);
	return;
}
static inline void u2fs_set_lower_path(const struct dentry *dent,
					 struct path *lower_path, int idx)
{
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(&U2FS_D(dent)->lower_path[idx], lower_path);
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}
static inline void u2fs_reset_lower_path(const struct dentry *dent, int idx)
{
	spin_lock(&U2FS_D(dent)->lock);
	U2FS_D(dent)->lower_path[idx].dentry = NULL;
	U2FS_D(dent)->lower_path[idx].mnt = NULL;
	spin_unlock(&U2FS_D(dent)->lock);
	return;
}
static inline void u2fs_put_reset_lower_path(const struct dentry *dent, int idx)
{
	struct path lower_path;
	spin_lock(&U2FS_D(dent)->lock);
	pathcpy(&lower_path, &U2FS_D(dent)->lower_path[idx]);
	U2FS_D(dent)->lower_path[idx].dentry = NULL;
	U2FS_D(dent)->lower_path[idx].mnt = NULL;
	spin_unlock(&U2FS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}

static inline struct dentry *lock_parent_wh(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);

	mutex_lock_nested(&dir->d_inode->i_mutex, U2FS_DMUTEX_WHITEOUT);
	return dir;
}

#endif	/* not _U2FS_H_ */
