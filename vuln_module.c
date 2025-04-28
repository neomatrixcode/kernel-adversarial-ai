#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "vuln_dev"

static char buffer[64];

static ssize_t vuln_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos) {
    char local_buf[64];
    copy_from_user(local_buf, user_buf, count); // ¡Desbordamiento si count > 64!
    printk(KERN_INFO "Buffer: %s\n", local_buf);
    return count;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .write = vuln_write,
};

static int __init vuln_init(void) {
    register_chrdev(0, DEVICE_NAME, &fops);
    return 0;
}

static void __exit vuln_exit(void) {
    unregister_chrdev(0, DEVICE_NAME);
}

module_init(vuln_init);
module_exit(vuln_exit);
MODULE_LICENSE("GPL");
