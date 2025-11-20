#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/tee_drv.h>

#define DEVICE_NAME "my_kmod"
#define CLASS_NAME  "mykmod"

static int my_major;
static struct class *my_class;
static struct device *my_device;

static char kbuf[128] = "hello from kernel";

/* ioctl */
static long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    pr_info("my_kmod: ioctl called (cmd=%u)\n", cmd);
    return 0;
}

/* read */
static ssize_t my_read(struct file *file, char __user *buf,
                       size_t len, loff_t *offset)
{
    return simple_read_from_buffer(buf, len, offset, kbuf, strlen(kbuf));
}

/* write */
static ssize_t my_write(struct file *file, const char __user *buf,
                        size_t len, loff_t *offset)
{
    if (len > sizeof(kbuf) - 1)
        len = sizeof(kbuf) - 1;

    if (copy_from_user(kbuf, buf, len))
        return -EFAULT;

    kbuf[len] = '\0';
    pr_info("my_kmod: write received: %s\n", kbuf);

    return len;
}

/* file operations */
static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = my_ioctl,
    .read  = my_read,
    .write = my_write,
};

/* init */
static int __init my_init(void)
{
    /* 1. allocate major */
    my_major = register_chrdev(0, DEVICE_NAME, &fops);
    if (my_major < 0) {
        pr_err("my_kmod: failed to register chrdev\n");
        return my_major;
    }

    /* 2. create class */
    my_class = class_create(CLASS_NAME);
    if (IS_ERR(my_class)) {
        unregister_chrdev(my_major, DEVICE_NAME);
        return PTR_ERR(my_class);
    }

    /* 3. create device node: /dev/my_kmod */
    my_device = device_create(my_class, NULL,
                              MKDEV(my_major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(my_device)) {
        class_destroy(my_class);
        unregister_chrdev(my_major, DEVICE_NAME);
        return PTR_ERR(my_device);
    }

    pr_info("my_kmod: loaded (major=%d)\n", my_major);
    return 0;
}

/* exit */
static void __exit my_exit(void)
{
    device_destroy(my_class, MKDEV(my_major, 0));
    class_destroy(my_class);
    unregister_chrdev(my_major, DEVICE_NAME);
    pr_info("my_kmod: unloaded\n");
}

module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple kernel module with ioctl/read/write");
MODULE_AUTHOR("you");
