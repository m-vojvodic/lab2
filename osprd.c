#include <linux/version.h>
#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/sched.h>
#include <linux/kernel.h>  /* printk() */
#include <linux/errno.h>   /* error codes */
#include <linux/types.h>   /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/wait.h>
#include <linux/file.h>

#include "spinlock.h"
#include "osprd.h"

/* The size of an OSPRD sector. */
#define SECTOR_SIZE	512

/* This flag is added to an OSPRD file's f_flags to indicate that the file
 * is locked. */
#define F_OSPRD_LOCKED	0x80000

/* eprintk() prints messages to the console.
 * (If working on a real Linux machine, change KERN_NOTICE to KERN_ALERT or
 * KERN_EMERG so that you are sure to see the messages.  By default, the
 * kernel does not print all messages to the console.  Levels like KERN_ALERT
 * and KERN_EMERG will make sure that you will see messages.) */
#define eprintk(format, ...) printk(KERN_NOTICE format, ## __VA_ARGS__)

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("CS 111 RAM Disk");
// EXERCISE: Pass your names into the kernel as the module's authors.
MODULE_AUTHOR("Karan Kajla & Marko Vojvodic");

#define OSPRD_MAJOR	222

/* This module parameter controls how big the disk will be.
 * You can specify module parameters when you load the module,
 * as an argument to insmod: "insmod osprd.ko nsectors=4096" */
static int nsectors = 32;
module_param(nsectors, int, 0);

/* Structures to hold the pids of processes holding locks. */
struct pid_node 
{
	pid_t pid;
	struct pid_node* next;
};

struct pid_list 
{
	struct pid_node* head;
	int size;
};

/* Structures used to serve processes in order of request. */
struct ticket_node 
{
	unsigned ticket;
	struct ticket_node* next;
};

struct ticket_list 
{
	struct ticket_node* head;
	int size;
};

/* The internal representation of our device. */
typedef struct osprd_info {
	uint8_t *data;                  // The data array. Its size is
	                                // (nsectors * SECTOR_SIZE) bytes.

	osp_spinlock_t mutex;           // Mutex for synchronizing access to
					// this block device

	unsigned ticket_head;		// Currently running ticket for
					// the device lock

	unsigned ticket_tail;		// Next available ticket for
					// the device lock

	wait_queue_head_t blockq;       // Wait queue for tasks blocked on
					// the device lock

	struct pid_list* read_lock_pids;	// List of pids holding read locks.

	struct pid_list* write_lock_pids;	// List of pids holding write locks.

	struct ticket_list* exited_tickets;	// List of processes that have ended.

	// The following elements are used internally; you don't need
	// to understand them.
	struct request_queue *queue;    // The device request queue.
	spinlock_t qlock;		// Used internally for mutual
	                                //   exclusion in the 'queue'.
	struct gendisk *gd;             // The generic disk.
} osprd_info_t;


#define NOSPRD 4
static osprd_info_t osprds[NOSPRD];

/* Helper function to add a pid holding a lock to specified list. */
void add_to_pid_list(struct pid_list** list, pid_t pid);
/* Helper function to remove a pid holding a lock from the specified list. */
void remove_from_pid_list(struct pid_list** list, pid_t pid);
/* Helper function to check if pid holds a lock in specified list. */
int pid_in_list(struct pid_list* list, pid_t pid);
/* Helper function to add a process' ticket in the serving queue. */
void add_to_ticket_list(struct ticket_list** list, unsigned ticket);
/* Helper function to remove a process' ticket from the serving queue. */
void remove_from_ticket_list(struct ticket_list** list, unsigned ticket);
/* Helper function to check if a process' ticket exists in the queue. */
int ticket_in_list(struct ticket_list* list, unsigned ticket);
/* Helper function to serve the next alive process waiting for a lock. */
void grant_next_alive_ticket(osprd_info_t *d);

// Declare useful helper functions

/*
 * file2osprd(filp)
 *   Given an open file, check whether that file corresponds to an OSP ramdisk.
 *   If so, return a pointer to the ramdisk's osprd_info_t.
 *   If not, return NULL.
 */
static osprd_info_t *file2osprd(struct file *filp);

/*
 * for_each_open_file(task, callback, user_data)
 *   Given a task, call the function 'callback' once for each of 'task's open
 *   files.  'callback' is called as 'callback(filp, user_data)'; 'filp' is
 *   the open file, and 'user_data' is copied from for_each_open_file's third
 *   argument.
 */
static void for_each_open_file(struct task_struct *task,
			       void (*callback)(struct file *filp,
						osprd_info_t *user_data),
			       osprd_info_t *user_data);

/*
 * osprd_process_request(d, req)
 *   Called when the user reads or writes a sector.
 *   Should perform the read or write, as appropriate.
 */
static void osprd_process_request(osprd_info_t *d, struct request *req)
{
	if (!blk_fs_request(req)) {
		end_request(req, 0);
		return;
	}

	unsigned int request_type = rq_data_dir(req);
	uint8_t* data_ptr = d->data + req->sector * SECTOR_SIZE;

	if (request_type == READ) 
	{
		//copy contents from ramdisk buffer into request buffer
		memcpy ((void*)req->buffer, (void*) data_ptr, req->current_nr_sectors * SECTOR_SIZE);
	}
	else if (request_type == WRITE) 
	{
		//copy contents of request buffer into ramdisk buffer
		memcpy((void*) data_ptr, (void*)req->buffer, req->current_nr_sectors * SECTOR_SIZE);
	}

	end_request(req, 1);
}


// This function is called when a /dev/osprdX file is opened.
// You aren't likely to need to change this.
static int osprd_open(struct inode *inode, struct file *filp)
{
	// Always set the O_SYNC flag. That way, we will get writes immediately
	// instead of waiting for them to get through write-back caches.
	filp->f_flags |= O_SYNC;
	return 0;
}


// This function is called when a /dev/osprdX file is finally closed.
// (If the file descriptor was dup2ed, this function is called only when the
// last copy is closed.)
static int osprd_close_last(struct inode *inode, struct file *filp)
{
	if (filp) {
		osprd_info_t *d = file2osprd(filp);
		int filp_writable = filp->f_mode & FMODE_WRITE;

		// if the file hasn't locked the ramdisk, invalid
		osp_spin_lock(&(d->mutex));
		if (!pid_in_list(d->write_lock_pids, current->pid) && 
		    !pid_in_list(d->read_lock_pids, current->pid)) 
		{
			osp_spin_unlock(&(d->mutex));
			return -EINVAL;
		}

		// if process holds a write lock
		if (pid_in_list(d->write_lock_pids, current->pid))
		{
			remove_from_pid_list(&(d->write_lock_pids), current->pid);	
		}

		// if process holds a read lock
		if (pid_in_list(d->read_lock_pids, current->pid))
		{
			remove_from_pid_list(&(d->read_lock_pids), current->pid);
		}

		// if no locks left, ramdisk is unlocked
		if (d->read_lock_pids == NULL && d->write_lock_pids == NULL) 
		{
			filp->f_flags &= ~F_OSPRD_LOCKED;
		}
		osp_spin_unlock(&(d->mutex));

		wake_up_all(&(d->blockq));
	}

	return 0;
}

/*
 * osprd_lock
 */

/*
 * osprd_ioctl(inode, filp, cmd, arg)
 *   Called to perform an ioctl on the named file.
 */
int osprd_ioctl(struct inode *inode, struct file *filp,
		unsigned int cmd, unsigned long arg)
{
	osprd_info_t *d = file2osprd(filp);	// device info
	int r = 0;			// return value: initially 0

	// is file open for writing?
	int filp_writable = (filp->f_mode & FMODE_WRITE) != 0;

	unsigned my_ticket; // used for handling multiple processes

	// Set 'r' to the ioctl's return value: 0 on success, negative on error
	if (cmd == OSPRDIOCACQUIRE) {

		// request a WRITE lock
		if(filp_writable) 
		{
			// get a ticket
			osp_spin_lock(&(d->mutex));
			my_ticket = d->ticket_head;
			d->ticket_head++;
			// check for READ deadlock
			if(pid_in_list(d->read_lock_pids, current->pid)) 
			{
				osp_spin_unlock(&(d->mutex));
				return -EDEADLK;
			}
			// check for WRITE deadlock
			if(pid_in_list(d->write_lock_pids, current->pid)) 
			{
				osp_spin_unlock(&(d->mutex));
				return -EDEADLK;
			}
			osp_spin_unlock(&(d->mutex)); 

			// block until a write lock can be obtained
			if(wait_event_interruptible(d->blockq, d->ticket_tail == my_ticket &&
							       d->write_lock_pids == NULL && 
							       d->read_lock_pids  == NULL)) 
			{ 
				if (d->ticket_tail == my_ticket) 
				{
					grant_next_alive_ticket(d);
				}
				else 
				{ 
					add_to_ticket_list(&(d->exited_tickets), my_ticket);
				}
				return -ERESTARTSYS;
			}

			// grab the write lock
			osp_spin_lock(&(d->mutex));
			filp->f_flags |= F_OSPRD_LOCKED;
			add_to_pid_list(&(d->write_lock_pids), current->pid);
			grant_next_alive_ticket(d);
			osp_spin_unlock(&(d->mutex));

			// wake up waiting processes
			wake_up_all(&(d->blockq)); 
			return 0;
		}
		// request a READ lock
		else 
		{			
			// get a ticket
			osp_spin_lock(&(d->mutex));
			my_ticket = d->ticket_head;
			d->ticket_head++;
			// check WRITE deadlock
			if(pid_in_list(d->write_lock_pids, current->pid)) 
			{
				osp_spin_unlock(&(d->mutex));
				return -EDEADLK;
			}
			// check for READ deadlock
			if(pid_in_list(d->read_lock_pids, current->pid)) 
			{
				osp_spin_unlock(&(d->mutex));
				return -EDEADLK;
			}

			osp_spin_unlock(&(d->mutex)); 

			// block until a read lock can be obtained
			if(wait_event_interruptible(d->blockq, d->ticket_tail == my_ticket &&
							       d->write_lock_pids == NULL)) 
			{
				if (d->ticket_tail == my_ticket) 
				{
					grant_next_alive_ticket(d);
				}
				else 
				{
					add_to_ticket_list(&(d->exited_tickets), my_ticket);
				}
				
				return -ERESTARTSYS;
			}

			// grab the read lock
			osp_spin_lock(&(d->mutex));
			filp->f_flags |= F_OSPRD_LOCKED;
			add_to_pid_list(&(d->read_lock_pids), current->pid);
			grant_next_alive_ticket(d);
			osp_spin_unlock(&(d->mutex));

			// wake up all waiting processes
			wake_up_all(&(d->blockq)); 
			return 0;
		}

	} else if (cmd == OSPRDIOCTRYACQUIRE) {
		// like OSPRDIOACQUIRE, but return -EBUSY where OSPRDIOACQUIRE
		// would return -EDEADLK or block

		// request a WRITE lock
		if(filp_writable)
		{
		   	osp_spin_lock(&(d->mutex));
			// check for READ deadlock
			if (pid_in_list(d->read_lock_pids, current->pid)) 
			{
		       		osp_spin_unlock(&(d->mutex));
		       		return -EBUSY;
			}
			// check for WRITE deadlock
			if (pid_in_list(d->write_lock_pids, current->pid)) 
			{
				osp_spin_unlock(&(d->mutex));
				return -EBUSY;
			}

			//get a ticket
			my_ticket = d->ticket_head;
			d->ticket_head++;

			// check if OSPRDIOACQUIRE would block
			if (d->ticket_tail != my_ticket ||
			    d->write_lock_pids != NULL ||
			    d->read_lock_pids != NULL) 
			{
				osp_spin_unlock(&(d->mutex));
				return -EBUSY;
			}
		   
			// grab the lock
			filp->f_flags |= F_OSPRD_LOCKED;
			add_to_pid_list(&d->write_lock_pids, current->pid);
			grant_next_alive_ticket(d);
			osp_spin_unlock(&(d->mutex));

			// wake up all waiting processes
			wake_up_all(&(d->blockq));
			return 0;
	       	}
	       	//request a READ lock
	       	else 
		{    
			osp_spin_lock(&(d->mutex));
	   
			// check for WRITE deadlock
		   	if (pid_in_list(d->write_lock_pids, current->pid))
			{
				osp_spin_unlock(&(d->mutex));
				return -EBUSY;
			}
			// check for READ deadlock
			if (pid_in_list(d->read_lock_pids, current->pid)) 
			{
		    		osp_spin_unlock(&(d->mutex));
		    		return -EBUSY;
			}
			//get a ticket
			my_ticket = d->ticket_head;
			d->ticket_head++;

			// check if OSPRDIOACQUIRE would block
			if (d->ticket_tail != my_ticket || 
			    d->write_lock_pids != NULL) 
			{
			    osp_spin_unlock(&(d->mutex));
			    return -EBUSY;
			}

			// grab the lock
			filp->f_flags |= F_OSPRD_LOCKED;
			add_to_pid_list(&d->read_lock_pids, current->pid);
			grant_next_alive_ticket(d);
			osp_spin_unlock(&(d->mutex));

			// wake up all waiting processes
			wake_up_all(&(d->blockq));
			return 0;
		}

	} else if (cmd == OSPRDIOCRELEASE) {

		osp_spin_lock(&(d->mutex));

		// if the file hasn't locked the ramdisk, invalid
		if (!pid_in_list(d->write_lock_pids, current->pid) && 
		    !pid_in_list(d->read_lock_pids, current->pid)) 
		{
			osp_spin_unlock(&(d->mutex));
			return -EINVAL;
		}
		// if process holds a write lock, release it
		if (pid_in_list(d->write_lock_pids, current->pid)) 
		{
			remove_from_pid_list(&(d->write_lock_pids), current->pid);	
		}
		// if process holds a read lock, release it
		if (pid_in_list(d->read_lock_pids, current->pid)) 
		{
			remove_from_pid_list(&(d->read_lock_pids), current->pid);
		}

		// if no locks left, ramdisk is unlocked
		if (d->read_lock_pids == NULL && 
		    d->write_lock_pids == NULL) 
		{
			filp->f_flags &= !F_OSPRD_LOCKED;
		}
		osp_spin_unlock(&(d->mutex));

		// wake up all waiting processes
		wake_up_all(&(d->blockq));
		return 0;

	} else
		r = -ENOTTY; /* unknown command */
	return r;
}


// Initialize internal fields for an osprd_info_t.

static void osprd_setup(osprd_info_t *d)
{
	/* Initialize the wait queue. */
	init_waitqueue_head(&d->blockq);
	osp_spin_lock_init(&d->mutex);
	d->ticket_head = d->ticket_tail = 0;

	/* Add code here if you add fields to osprd_info_t. */
	d->read_lock_pids = NULL;
	d->write_lock_pids = NULL;
	d->exited_tickets = NULL;
}

/* Additional functions. */

/* Helper function to add a pid holding a lock to specified list. */
void add_to_pid_list(struct pid_list** list, pid_t pid) 
{

	struct pid_node* new_pid_node;
	//check if need to initialize list
	if (*list == NULL) 
	{
		*list = kzalloc(sizeof(struct pid_list), GFP_ATOMIC);
		(*list)->head = NULL;
		(*list)->size = 0;
	}
	new_pid_node = kzalloc(sizeof(struct pid_node), GFP_ATOMIC);
	new_pid_node->pid = pid;
	if ((*list)->head == NULL) 
	{
		(*list)->head = new_pid_node;
		new_pid_node->next = NULL;
	}
	else 
	{
		new_pid_node->next = (*list)->head;
		(*list)->head = new_pid_node;
	}
	(*list)->size++;
}

/* Helper function to remove a pid holding a lock from the specified list. */
void remove_from_pid_list(struct pid_list** list, pid_t pid) 
{
	struct pid_node* current_pid_node;
	struct pid_node* delete_pid_node;

	if (list == NULL) 
	{
		return;
	}

	current_pid_node = (*list)->head;
	if (current_pid_node == NULL) 
	{
		return;
	}

	// Remove all occurances of pid
	while (current_pid_node != NULL) 
	{ 
		if (current_pid_node->pid == pid) 
		{
			if (current_pid_node == (*list)->head) 
			{
				(*list)->head = current_pid_node->next;
			}
			delete_pid_node = current_pid_node;
			current_pid_node = current_pid_node->next;
			kfree(delete_pid_node);
			(*list)->size--;
		} 
		else 
		{
			current_pid_node = current_pid_node->next;
		}
	}

	if ((*list)->size == 0) {
		//deallocate list so no memory leaks
		kfree(*list);
		*list = NULL;
	}
}

/* Helper function to check if pid holds a lock in specified list. */
int pid_in_list(struct pid_list* list, pid_t pid) 
{
	struct pid_node* current_pid_node;
	if (list == NULL) 
	{
		return 0;
	}
	current_pid_node = list->head;
	while (current_pid_node != NULL) 
	{
		if (current_pid_node->pid == pid) 
		{
			return 1;
		}
		current_pid_node = current_pid_node->next;
	}
	return 0;
}	

/* Helper function to add a process' ticket in the serving queue. */
void add_to_ticket_list(struct ticket_list** list, unsigned ticket) 
{
	struct ticket_node* new_ticket_node;
	//check if need to initialize list
	if (*list == NULL) 
	{
		*list = kzalloc(sizeof(struct ticket_list), GFP_ATOMIC);
		(*list)->head = NULL;
		(*list)->size = 0;
	}
	new_ticket_node = kzalloc(sizeof(struct ticket_node), GFP_ATOMIC);
	new_ticket_node->ticket = ticket;
	if ((*list)->head == NULL) 
	{
		(*list)->head = new_ticket_node;
		new_ticket_node->next = NULL;
	}
	else 
	{
		new_ticket_node->next = (*list)->head;
		(*list)->head = new_ticket_node;
	}
	(*list)->size++;
}

/* Helper function to remove a process' ticket from the serving queue. */
void remove_from_ticket_list(struct ticket_list** list, unsigned ticket) 
{
	struct ticket_node* current_ticket_node;
	struct ticket_node* delete_ticket_node;

	if (list == NULL) 
	{
		return;
	}

	current_ticket_node = (*list)->head;
	if (current_ticket_node== NULL) 
	{
		return;
	}
	
	// Remove all occurances of ticket
	while (current_ticket_node != NULL) 
	{
		if (current_ticket_node->ticket == ticket) 
		{
			if (current_ticket_node == (*list)->head) 
			{
				(*list)->head = current_ticket_node->next;
			}
			delete_ticket_node = current_ticket_node;
			current_ticket_node = current_ticket_node->next;
			kfree(delete_ticket_node);
			(*list)->size--;
		} 
		else 
		{
			current_ticket_node = current_ticket_node->next;
		}
	}

	if ((*list)->size == 0) {
		//deallocate list so no memory leaks
		kfree(*list);
		*list = NULL;
	}	
}

/* Helper function to check if a process' ticket exists in the queue. */
int ticket_in_list(struct ticket_list* list, unsigned ticket) 
{

	struct ticket_node* current_ticket_node;
	if (list == NULL) 
	{
		return 0;
	}
	current_ticket_node = list->head;
	while (current_ticket_node != NULL) 
	{
		if (current_ticket_node->ticket == ticket) 
		{
			return 1;
		}
		current_ticket_node = current_ticket_node->next;
	}
	return 0;
}

/* Helper function to serve the next alive process waiting for a lock. */
void grant_next_alive_ticket(osprd_info_t *d) 
{
	// make sure only pass the alive ticket to alive processes.
	while (++(d->ticket_tail)) 
	{
		if (!ticket_in_list(d->exited_tickets, d->ticket_tail)) 
		{
			// process is alive
			break;
		}
		else 
		{
			// process is dead
			remove_from_ticket_list(&(d->exited_tickets), d->ticket_tail);
		}
	}
}


/*****************************************************************************/
/*         THERE IS NO NEED TO UNDERSTAND ANY CODE BELOW THIS LINE!          */
/*                                                                           */
/*****************************************************************************/

// Process a list of requests for a osprd_info_t.
// Calls osprd_process_request for each element of the queue.

static void osprd_process_request_queue(request_queue_t *q)
{
	osprd_info_t *d = (osprd_info_t *) q->queuedata;
	struct request *req;

	while ((req = elv_next_request(q)) != NULL)
		osprd_process_request(d, req);
}


// Some particularly horrible stuff to get around some Linux issues:
// the Linux block device interface doesn't let a block device find out
// which file has been closed.  We need this information.

static struct file_operations osprd_blk_fops;
static int (*blkdev_release)(struct inode *, struct file *);

static int _osprd_release(struct inode *inode, struct file *filp)
{
	if (file2osprd(filp))
		osprd_close_last(inode, filp);
	return (*blkdev_release)(inode, filp);
}

static int _osprd_open(struct inode *inode, struct file *filp)
{
	if (!osprd_blk_fops.open) {
		memcpy(&osprd_blk_fops, filp->f_op, sizeof(osprd_blk_fops));
		blkdev_release = osprd_blk_fops.release;
		osprd_blk_fops.release = _osprd_release;
	}
	filp->f_op = &osprd_blk_fops;
	return osprd_open(inode, filp);
}


// The device operations structure.

static struct block_device_operations osprd_ops = {
	.owner = THIS_MODULE,
	.open = _osprd_open,
	// .release = osprd_release, // we must call our own release
	.ioctl = osprd_ioctl
};


// Given an open file, check whether that file corresponds to an OSP ramdisk.
// If so, return a pointer to the ramdisk's osprd_info_t.
// If not, return NULL.

static osprd_info_t *file2osprd(struct file *filp)
{
	if (filp) {
		struct inode *ino = filp->f_dentry->d_inode;
		if (ino->i_bdev
		    && ino->i_bdev->bd_disk
		    && ino->i_bdev->bd_disk->major == OSPRD_MAJOR
		    && ino->i_bdev->bd_disk->fops == &osprd_ops)
			return (osprd_info_t *) ino->i_bdev->bd_disk->private_data;
	}
	return NULL;
}


// Call the function 'callback' with data 'user_data' for each of 'task's
// open files.

static void for_each_open_file(struct task_struct *task,
		  void (*callback)(struct file *filp, osprd_info_t *user_data),
		  osprd_info_t *user_data)
{
	int fd;
	task_lock(task);
	spin_lock(&task->files->file_lock);
	{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 13)
		struct files_struct *f = task->files;
#else
		struct fdtable *f = task->files->fdt;
#endif
		for (fd = 0; fd < f->max_fds; fd++)
			if (f->fd[fd])
				(*callback)(f->fd[fd], user_data);
	}
	spin_unlock(&task->files->file_lock);
	task_unlock(task);
}


// Destroy a osprd_info_t.

static void cleanup_device(osprd_info_t *d)
{
	wake_up_all(&d->blockq);
	if (d->gd) {
		del_gendisk(d->gd);
		put_disk(d->gd);
	}
	if (d->queue)
		blk_cleanup_queue(d->queue);
	if (d->data)
		vfree(d->data);
}


// Initialize a osprd_info_t.

static int setup_device(osprd_info_t *d, int which)
{
	memset(d, 0, sizeof(osprd_info_t));

	/* Get memory to store the actual block data. */
	if (!(d->data = vmalloc(nsectors * SECTOR_SIZE)))
		return -1;
	memset(d->data, 0, nsectors * SECTOR_SIZE);

	/* Set up the I/O queue. */
	spin_lock_init(&d->qlock);
	if (!(d->queue = blk_init_queue(osprd_process_request_queue, &d->qlock)))
		return -1;
	blk_queue_hardsect_size(d->queue, SECTOR_SIZE);
	d->queue->queuedata = d;

	/* The gendisk structure. */
	if (!(d->gd = alloc_disk(1)))
		return -1;
	d->gd->major = OSPRD_MAJOR;
	d->gd->first_minor = which;
	d->gd->fops = &osprd_ops;
	d->gd->queue = d->queue;
	d->gd->private_data = d;
	snprintf(d->gd->disk_name, 32, "osprd%c", which + 'a');
	set_capacity(d->gd, nsectors);
	add_disk(d->gd);

	/* Call the setup function. */
	osprd_setup(d);

	return 0;
}

static void osprd_exit(void);


// The kernel calls this function when the module is loaded.
// It initializes the 4 osprd block devices.

static int __init osprd_init(void)
{
	int i, r;

	// shut up the compiler
	(void) for_each_open_file;
#ifndef osp_spin_lock
	(void) osp_spin_lock;
	(void) osp_spin_unlock;
#endif

	/* Register the block device name. */
	if (register_blkdev(OSPRD_MAJOR, "osprd") < 0) {
		printk(KERN_WARNING "osprd: unable to get major number\n");
		return -EBUSY;
	}

	/* Initialize the device structures. */
	for (i = r = 0; i < NOSPRD; i++)
		if (setup_device(&osprds[i], i) < 0)
			r = -EINVAL;

	if (r < 0) {
		printk(KERN_EMERG "osprd: can't set up device structures\n");
		osprd_exit();
		return -EBUSY;
	} else
		return 0;
}


// The kernel calls this function to unload the osprd module.
// It destroys the osprd devices.

static void osprd_exit(void)
{
	int i;
	for (i = 0; i < NOSPRD; i++)
		cleanup_device(&osprds[i]);
	unregister_blkdev(OSPRD_MAJOR, "osprd");
}


// Tell Linux to call those functions at init and exit time.
module_init(osprd_init);
module_exit(osprd_exit);
