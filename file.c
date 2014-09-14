#include "u2fs.h"

static ssize_t u2fs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err=0;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	
	/* reading from left branch */
	if(U2FS_F(file)->lower_file[LEFT] != NULL){	
		lower_file = u2fs_lower_file(file, LEFT);
		err = vfs_read(lower_file, buf, count, ppos);
		/* update our inode atime upon a successful lower read */
		if (err >= 0)
			fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
	}

	/* reading from right branch */
	else if(U2FS_F(file)->lower_file[RIGHT] != NULL){
		lower_file = u2fs_lower_file(file, RIGHT);
		err = vfs_read(lower_file, buf, count, ppos);
		/* update our inode atime upon a successful lower read */
		if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
	}

	return err;
}

static ssize_t u2fs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err = 0;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	

	lower_file = u2fs_lower_file(file, LEFT);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
		fsstack_copy_attr_times(dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
	}

	return err;
}

static int u2fs_filldir(void *dirent, const char *oname, int namelen,
			   loff_t offset, u64 ino, unsigned int d_type)
{
	struct u2fs_getdents_callback *buf = dirent;
	int err = 0, i;
	char *name = (char *) oname;
	struct dentry *wh_dentry;
	bool is_whiteout;
	u64 u2fs_ino = ino;
	void *p;
	

	is_whiteout = is_whiteout_name(&name, &namelen);

	if(is_whiteout)
		goto out;

	/* storing name for duplicate elimination */
	if(buf->idx == LEFT){
		if(buf->dup_count != 0){

			p = krealloc(buf->dup_name, 
			(sizeof(char *)*(buf->dup_count+1)), GFP_KERNEL);

			if(unlikely(!p)){
				err = -ENOMEM;
				goto out;
			}
			buf->dup_name = p;
		}
		buf->dup_name[buf->dup_count] = name;
		buf->dup_count++;
	}
	
	/* removing duplicate */
	if(buf->idx == RIGHT){
		for(i=0;i<buf->dup_count;i++){
			if(strcmp(buf->dup_name[i], name) == 0)
				goto out;
		}

	}

	/* if 'name' isn't a whiteout, filldir it. */
	if (buf->lower_parent_dentry != NULL && buf->idx == RIGHT) {
		wh_dentry = lookup_whiteout(name, buf->lower_parent_dentry);
		
		if(IS_ERR(wh_dentry)){
			err = PTR_ERR(wh_dentry);
			goto out;
		}
	
		if(wh_dentry->d_inode)
			goto out;
	}

	err = buf->filldir(buf->dirent, name, namelen, buf->offset,
				u2fs_ino, d_type);
	buf->offset++;
out:
	return err;
}

static int u2fs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct u2fs_getdents_callback buf;
	struct inode *inode;
	
	inode = dentry->d_inode;

	/* prepare callback buffer */
	buf.dirent = dirent;
	buf.filldir = filldir;
	buf.lower_parent_dentry = NULL;
	buf.offset = 1;
	buf.idx = LEFT;
	buf.dup_count = 0;

	buf.dup_name = kmalloc(sizeof(char*), GFP_KERNEL);
	if(unlikely(!buf.dup_name)){
		err = -ENOMEM;
		goto out;
	}

	if(U2FS_D(dentry)->lower_path[LEFT].dentry !=NULL){
		buf.lower_parent_dentry = 
			U2FS_D(dentry)->lower_path[LEFT].dentry;
	}
	if(U2FS_F(file)->lower_file[LEFT] != NULL){
		lower_file = u2fs_lower_file(file, LEFT);
		err = vfs_readdir(lower_file, u2fs_filldir, &buf);
		file->f_pos = lower_file->f_pos;
		if (err >= 0)		/* copy the atime */
			fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
	}		
	
	buf.idx = RIGHT;

	if(U2FS_F(file)->lower_file[RIGHT] != NULL){
		lower_file = u2fs_lower_file(file, RIGHT);
		err = vfs_readdir(lower_file, u2fs_filldir, &buf);
		file->f_pos = lower_file->f_pos;
		if (err >= 0)		/* copy the atime */
			fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
	}
out:
	kfree(buf.dup_name);
	return err;
}

static long u2fs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;
	
	lower_file = u2fs_lower_file(file, LEFT);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

out:
	return err;
}

#ifdef CONFIG_COMPAT
static long u2fs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;
	
	lower_file = u2fs_lower_file(file, LEFT);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int u2fs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;
	
	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	lower_file = u2fs_lower_file(file, LEFT);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "u2fs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	if (!U2FS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "u2fs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
		err = do_munmap(current->mm, vma->vm_start,
				vma->vm_end - vma->vm_start);
		if (err) {
			printk(KERN_ERR "u2fs: do_munmap failed %d\n", err);
			goto out;
		}
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &u2fs_vm_ops;
	vma->vm_flags |= VM_CAN_NONLINEAR;

	file->f_mapping->a_ops = &u2fs_aops; /* set our aops */
	if (!U2FS_F(file)->lower_vm_ops) /* save for our ->fault */
		U2FS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int u2fs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;
	
	
	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct u2fs_file_info), GFP_KERNEL);
	if (!U2FS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	if ((U2FS_D(file->f_path.dentry)->lower_path[RIGHT].dentry) != NULL &&
		(U2FS_D(file->f_path.dentry)->lower_path[RIGHT].mnt) != NULL){
	
		if(IS_WRITE_FLAG(file->f_flags) &&
		(U2FS_D(file->f_path.dentry)->lower_path[LEFT].dentry) == NULL
		&& (U2FS_D(file->f_path.dentry)->lower_path[LEFT].mnt) == NULL){
			
			err = copyup_file(inode, file, 
				i_size_read(file->f_path.dentry->d_inode));
			if(err)
				goto out_err;

			goto left;
		}

		u2fs_get_lower_path(file->f_path.dentry, &lower_path, RIGHT);
		lower_file = dentry_open(lower_path.dentry, lower_path.mnt,
				 file->f_flags, current_cred());
		if (IS_ERR(lower_file)) {
			err = PTR_ERR(lower_file);
			lower_file = u2fs_lower_file(file, RIGHT);
			if (lower_file) {
				u2fs_set_lower_file(file, NULL, RIGHT);
				fput(lower_file); 
				/* fput calls dput for lower_dentry */
			}
		} else {
			u2fs_set_lower_file(file, lower_file, RIGHT);
		}
		if (err)
			kfree(U2FS_F(file));
		else
			fsstack_copy_attr_all(inode, 
				u2fs_lower_inode(inode, RIGHT));
	}
	else{
		u2fs_set_lower_file(file, NULL, RIGHT);
	}

left:
	// open lower object and link u2fs's file struct to lower's 
	if((U2FS_D(file->f_path.dentry)->lower_path[LEFT].dentry) != NULL &&
		(U2FS_D(file->f_path.dentry)->lower_path[LEFT].mnt) != NULL){
	
		u2fs_get_lower_path(file->f_path.dentry, &lower_path, LEFT);
		lower_file = dentry_open(lower_path.dentry, lower_path.mnt,
				 file->f_flags, current_cred());
	
		if (IS_ERR(lower_file)) {
			err = PTR_ERR(lower_file);
			lower_file = u2fs_lower_file(file, LEFT);
			if (lower_file) {
				u2fs_set_lower_file(file, NULL, LEFT);
				fput(lower_file); 
				/* fput calls dput for lower_dentry */
		}
		} else {
			u2fs_set_lower_file(file, lower_file, LEFT);
		}
		if (err)
			kfree(U2FS_F(file));
		else
			fsstack_copy_attr_all(inode, 
				u2fs_lower_inode(inode, LEFT));
	}
	else{
		u2fs_set_lower_file(file, NULL, LEFT);
	}

out_err:
	return err;
}

static int u2fs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;
	
	if(U2FS_F(file)->lower_file[LEFT] != NULL){
		lower_file = u2fs_lower_file(file, LEFT);
		if (lower_file && lower_file->f_op && lower_file->f_op->flush)
			err = lower_file->f_op->flush(lower_file, id);
	}
	if(U2FS_F(file)->lower_file[RIGHT] != NULL){
		lower_file = u2fs_lower_file(file, RIGHT);
		if (lower_file && lower_file->f_op && lower_file->f_op->flush)
			err = lower_file->f_op->flush(lower_file, id);
	}
	return err;
}

/* release all lower object references & free the file info structure */
static int u2fs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;
	

	if(U2FS_F(file)->lower_file[LEFT] != NULL){
		lower_file = u2fs_lower_file(file, LEFT);
		if (lower_file) {
			u2fs_set_lower_file(file, NULL, LEFT);
			fput(lower_file);
		}
	}

	if(U2FS_F(file)->lower_file[RIGHT] != NULL){
		lower_file = u2fs_lower_file(file, RIGHT);
		if (lower_file) {
			u2fs_set_lower_file(file, NULL, RIGHT);
			fput(lower_file);
		}
	}

	kfree(U2FS_F(file));
	return 0;
}

static int u2fs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err=0;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;
	
	if(file != NULL){
		err = generic_file_fsync(file, start, end, datasync);
	}
	if (err)
		goto out;

	if((U2FS_D(file->f_path.dentry)->lower_path[LEFT].dentry) != NULL && 
		(U2FS_D(file->f_path.dentry)->lower_path[LEFT].mnt) != NULL){	
	
		lower_file = u2fs_lower_file(file, LEFT);
		u2fs_get_lower_path(dentry, &lower_path, LEFT);
		err = vfs_fsync_range(lower_file, start, end, datasync);
		u2fs_put_lower_path(dentry, &lower_path);
	}
	else if
	((U2FS_D(file->f_path.dentry)->lower_path[RIGHT].dentry) != NULL && 
		(U2FS_D(file->f_path.dentry)->lower_path[RIGHT].mnt) != NULL){	
		lower_file = u2fs_lower_file(file, RIGHT);
		u2fs_get_lower_path(dentry, &lower_path, RIGHT);
		err = vfs_fsync_range(lower_file, start, end, datasync);
		u2fs_put_lower_path(dentry, &lower_path);
	}

out:
	return err;
}

static int u2fs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;
	
	lower_file = u2fs_lower_file(file, LEFT);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

const struct file_operations u2fs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= u2fs_read,
	.write		= u2fs_write,
	.unlocked_ioctl	= u2fs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= u2fs_compat_ioctl,
#endif
	.mmap		= u2fs_mmap,
	.open		= u2fs_open,
	.flush		= u2fs_flush,
	.release	= u2fs_file_release,
	.fsync		= u2fs_fsync,
	.fasync		= u2fs_fasync,
};

/* trimmed directory options */
const struct file_operations u2fs_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= u2fs_readdir,
	.unlocked_ioctl	= u2fs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= u2fs_compat_ioctl,
#endif
	.open		= u2fs_open,
	.release	= u2fs_file_release,
	.flush		= u2fs_flush,
	.fsync		= u2fs_fsync,
	.fasync		= u2fs_fasync,
};
