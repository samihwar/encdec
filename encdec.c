#include <linux/ctype.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>  	
#include <linux/slab.h>
#include <linux/fs.h>       		
#include <linux/errno.h>  
#include <linux/types.h> 
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/string.h>


#include "encdec.h"

#define MODULE_NAME "encdec"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YOUR NAME");

int 	encdec_open(struct inode* inode, struct file* filp);
int 	encdec_release(struct inode* inode, struct file* filp);
int 	encdec_ioctl(struct inode* inode, struct file* filp, unsigned int cmd, unsigned long arg);

ssize_t encdec_read_caesar(struct file* filp, char* buf, size_t count, loff_t* f_pos);
ssize_t encdec_write_caesar(struct file* filp, const char* buf, size_t count, loff_t* f_pos);

ssize_t encdec_read_xor(struct file* filp, char* buf, size_t count, loff_t* f_pos);
ssize_t encdec_write_xor(struct file* filp, const char* buf, size_t count, loff_t* f_pos);

int major = 0;
int memory_size = 0;
char* Caesar_buffer = NULL;
char* XOR_buffer = NULL;

MODULE_PARM(memory_size, "i");

struct file_operations fops_caesar = {
	.open = encdec_open,
	.release = encdec_release,
	.read = encdec_read_caesar,
	.write = encdec_write_caesar,
	.llseek = NULL,
	.ioctl = encdec_ioctl,
	.owner = THIS_MODULE
};

struct file_operations fops_xor = {
	.open = encdec_open,
	.release = encdec_release,
	.read = encdec_read_xor,
	.write = encdec_write_xor,
	.llseek = NULL,
	.ioctl = encdec_ioctl,
	.owner = THIS_MODULE
};

typedef struct {
	unsigned char key;
	int read_state;

} encdec_private_data;

int init_module(void)
{
	major = register_chrdev(major, MODULE_NAME, &fops_caesar);
	if (major < 0)
	{
		return major;
	}
	XOR_buffer = kmalloc(memory_size, GFP_KERNEL);
	if (!XOR_buffer)	//if kmalloc failed
		return -ENOMEM;
	Caesar_buffer = kmalloc(memory_size, GFP_KERNEL);
	if (!Caesar_buffer)	//if kmalloc failed
		return -ENOMEM;
	memset(XOR_buffer, 0, memory_size); //initilaizing the buffer
	memset(Caesar_buffer, 0, memory_size);	//initilaizing the buffer
	return 0;
}

void cleanup_module(void)
{	//just freeing :)
	unregister_chrdev(major, MODULE_NAME);
	kfree(XOR_buffer);
	kfree(Caesar_buffer);
	return;
}

int encdec_open(struct inode* inode, struct file* filp)
{
	int minor = MINOR(inode->i_rdev);
	if (minor == 1)// if its minor 1 we want to choose the xor file operation else we want to choose th ecaesar fp
		filp->f_op = &fops_xor;
	else
		filp->f_op = &fops_caesar;

	encdec_private_data* fileData = kmalloc(sizeof(encdec_private_data), GFP_KERNEL);
	if (!fileData)
		return -ENOMEM;
	fileData->key = 0;	//init the key
	fileData->read_state = ENCDEC_READ_STATE_DECRYPT;// init the read state
	filp->private_data = fileData;//init the private data
	return 0;
}

int encdec_release(struct inode* inode, struct file* filp)
{//free :)
	if (filp->private_data)
		kfree(filp->private_data);

	return 0;
}

int encdec_ioctl(struct inode* inode, struct file* filp, unsigned int cmd, unsigned long arg)
{
	int minor = 0;
	encdec_private_data* file_data = (encdec_private_data*)filp->private_data;
	switch (cmd)
	{
	case ENCDEC_CMD_CHANGE_KEY://we want to change the key
		if (file_data)
			file_data->key = (char)arg;
		break;

	case ENCDEC_CMD_SET_READ_STATE://we want to change the read state
		if (file_data)
			file_data->read_state = (int)arg;
		break;

	case ENCDEC_CMD_ZERO://empty the buffer and choosing accoring to the minor number
		minor = MINOR(inode->i_rdev);
		if (minor)
			memset(XOR_buffer, 0, memory_size);
		else
			memset(Caesar_buffer, 0, memory_size);
		break;

	default: return -ENOTTY;
	}

	return 0;

}

ssize_t encdec_read_caesar(struct file* filp, char* buf, size_t count, loff_t* f_pos)
{
	int  i;
	unsigned long bytes_read, bytes_to_read, maxbytes, unread;
	if (!filp) return -EBADF;//if its not valid
	maxbytes = memory_size - *f_pos;//calculating the remining space to read
	if (maxbytes <= 0)//if its 0
		return -EINVAL;
	if (maxbytes > count)
		bytes_to_read = count;//if we can read them all
	else
		bytes_to_read = maxbytes;
	unread = copy_to_user(buf, Caesar_buffer + (*f_pos), bytes_to_read);//sending the buffer to the user
	bytes_read = bytes_to_read - unread;								//the pytes we will actually read
	encdec_private_data* my_private = (encdec_private_data*)filp->private_data;
	if (!my_private) return -1;
	if ((my_private->read_state) == ENCDEC_READ_STATE_DECRYPT)//we will check the read state
	{
		for (i = 0; i < bytes_read; i++)
			*(buf + i + *f_pos) = ((*(buf + i + *f_pos) - my_private->key + 128) % 128);
	}

	*f_pos += bytes_read;//updating the offset
	return bytes_read;
}
ssize_t encdec_write_caesar(struct file* filp, const char* buf, size_t count, loff_t* f_pos)
{
	int  i;
	unsigned long bytes_writen, bytes_to_write, maxbytes, unwrite;
	if (!filp) return -EBADF;// if its invalid file
	if (!buf) return -1;// if its NULL
	maxbytes = memory_size - *f_pos;//calculating the empty space
	if (maxbytes <= 0)//its 0
		return -ENOSPC;
	if (maxbytes > count)//if all the text can fit
		bytes_to_write = count;
	else
		bytes_to_write = maxbytes;
	unwrite = copy_from_user(Caesar_buffer + *f_pos, buf , bytes_to_write);//moving the buffer from the user to the kernel
	bytes_writen = bytes_to_write - unwrite;//the byte that we actually gonna write
	encdec_private_data* my_private = (encdec_private_data*)filp->private_data;
	if (!my_private) return -1;// if its NULL
	for (i = 0; i < bytes_writen; i++)
	{
		*(Caesar_buffer + *f_pos + i) = ((*(Caesar_buffer + *f_pos + i) + my_private->key) % 128);	
	}
	*f_pos += bytes_writen;//updating the offset
	return bytes_writen;
}



ssize_t encdec_read_xor(struct file* filp, char* buf, size_t count, loff_t* f_pos)
{
	int  i;
	unsigned long bytes_read, bytes_to_read, maxbytes, unread;
	if (!filp) return -EBADF;//if its not valid
	maxbytes = memory_size - *f_pos;//calculating the remining space to read
	if (maxbytes <= 0)//if its 0
		return -EINVAL;
	if (maxbytes > count)
		bytes_to_read = count;//if we can read them all
	else
		bytes_to_read = maxbytes;
	unread = copy_to_user(buf , XOR_buffer + *f_pos, bytes_to_read);//sending the buffer to the user
	bytes_read = bytes_to_read - unread;								//the pytes we will actually read
	encdec_private_data* my_private = (encdec_private_data*)filp->private_data;
	if (!my_private) return -1;
	if ((my_private->read_state) == ENCDEC_READ_STATE_DECRYPT)//we will check the read state
	{
		for (i = 0; i < bytes_read; i++)
			*(buf + i + *f_pos) = *(buf + i + *f_pos) ^ (int)my_private->key;
	}

	*f_pos += bytes_read;//updating the offset
	return bytes_read;

}


ssize_t encdec_write_xor(struct file* filp, const char* buf, size_t count, loff_t* f_pos)
{
	int  i;
	unsigned long bytes_writen, bytes_to_write, maxbytes, unwrite;
	if (!filp) return -EBADF;// if its invalid file
	if (!buf) return -1;// if its NULL
	maxbytes = memory_size - *f_pos;//calculating the empty space
	if (maxbytes <= 0)//its 0
		return -ENOSPC;
	if (maxbytes > count)//if all the text can fit
		bytes_to_write = count;
	else
		bytes_to_write = maxbytes;
	unwrite = copy_from_user(XOR_buffer + *f_pos, buf, bytes_to_write);//moving the buffer from the user to the kernel
	bytes_writen = bytes_to_write - unwrite;//the byte that we actually gonna write
	encdec_private_data* my_private = (encdec_private_data*)filp->private_data;
	if (!my_private) return -1;// if its NULL
	for (i = 0; i < bytes_writen; i++)
	{
		*(XOR_buffer + *f_pos + i) = *(XOR_buffer + *f_pos + i) ^ (int)my_private->key;
	}
	*f_pos += bytes_writen;//updating the offset
	return bytes_writen;
}
