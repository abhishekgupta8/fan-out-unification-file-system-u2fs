#include "u2fs.h"

/*
 * Super-user IO work Queue - sometimes we need to perform actions which
 * would fail due to the unix permissions on the parent directory (e.g.,
 * rmdir a directory which appears empty, but in reality contains
 * whiteouts).
 */

static struct workqueue_struct *superio_workqueue;

int __init init_sioq(void)
{
	int err;

	superio_workqueue = create_workqueue("u2fs_siod");
	if (!IS_ERR(superio_workqueue))
		return 0;

	err = PTR_ERR(superio_workqueue);
	printk(KERN_ERR "u2fs: create_workqueue failed %d\n", err);
	superio_workqueue = NULL;
	return err;
}

void stop_sioq(void)
{
	if (superio_workqueue)
		destroy_workqueue(superio_workqueue);
}

void run_sioq(work_func_t func, struct sioq_args *args)
{
	INIT_WORK(&args->work, func);

	init_completion(&args->comp);
	while (!queue_work(superio_workqueue, &args->work)) {
		/* TODO: do accounting if needed */
		schedule();
	}
	wait_for_completion(&args->comp);
}

void __u2fs_create(struct work_struct *work)
{
	struct sioq_args *args = container_of(work, struct sioq_args, work);
	struct create_args *c = &args->create;

	args->err = vfs_create(c->parent, c->dentry, c->mode, c->nd);
	complete(&args->comp);
}

void __u2fs_mkdir(struct work_struct *work)
{
	struct sioq_args *args = container_of(work, struct sioq_args, work);
	struct mkdir_args *m = &args->mkdir;

	args->err = vfs_mkdir(m->parent, m->dentry, m->mode);
	complete(&args->comp);
}

void __u2fs_mknod(struct work_struct *work)
{
	struct sioq_args *args = container_of(work, struct sioq_args, work);
	struct mknod_args *m = &args->mknod;

	args->err = vfs_mknod(m->parent, m->dentry, m->mode, m->dev);
	complete(&args->comp);
}

void __u2fs_symlink(struct work_struct *work)
{
	struct sioq_args *args = container_of(work, struct sioq_args, work);
	struct symlink_args *s = &args->symlink;

	args->err = vfs_symlink(s->parent, s->dentry, s->symbuf);
	complete(&args->comp);
}

void __u2fs_unlink(struct work_struct *work)
{
	struct sioq_args *args = container_of(work, struct sioq_args, work);
	struct unlink_args *u = &args->unlink;

	args->err = vfs_unlink(u->parent, u->dentry);
	complete(&args->comp);
}
