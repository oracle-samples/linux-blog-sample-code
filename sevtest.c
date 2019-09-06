/*
* Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*
* This code is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 only, as
* published by the Free Software Foundation.
*
* This code is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
* version 2 for more details (a copy is included in the LICENSE file that
* accompanied this code).
*
* You should have received a copy of the GNU General Public License version
* 2 along with this work; if not, write to the Free Software Foundation,
* Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*
* Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
* or visit www.oracle.com if you need additional information or have any
* questions.
*/
#include <linux module.h="">
#include <linux set_memory.h="">
#include <linux device.h="">
 
#define SECRET_DATA "my secret\n"
 
static int smetest_major;
static struct class *smetest_class;
static char *secret;
 
static long smetest_ioctl(struct file *file, unsigned int cmd,
                         unsigned long arg)
{
    int ret = 0;
    char buf[strlen(SECRET_DATA) + 1];
 
    if (!mem_encrypt_active())
                return -ENXIO;
 
    switch (cmd) {
    case 1:
        ret = set_memory_decrypted((unsigned long)secret, 1);
    case 0:
        break;
    default:
        return -EINVAL;
    }
    if (ret)
        return ret;
 
    memcpy(buf, secret, strlen(SECRET_DATA) + 1);
    if (cmd == 1) {
        /* Re-encrypt memory */
        ret = set_memory_encrypted((unsigned long)secret, 1);
 
        /* Make sure string is terminated */
        buf[strlen(SECRET_DATA)] = 0;
    }
    printk("Secret data is: %s\n", buf);
 
    return ret;
}
 
 
static struct file_operations smetest_ops = {
        .owner   = THIS_MODULE,
    .unlocked_ioctl = smetest_ioctl,
};
 
static void smetest_cleanup(void)
{
    if (smetest_class) {
        device_destroy(smetest_class, MKDEV(smetest_major, 0));
        class_destroy(smetest_class);
    }
    __unregister_chrdev(smetest_major, 0, 1, "smetest");
    free_page((unsigned long)secret);   
}
 
static int smetest_init(void)
{
    int err = 0;
 
    smetest_major = __register_chrdev(smetest_major, 0, 1,
                "smetest", &smetest_ops);
    if (smetest_major < 0) {
                pr_err("unable to get major %d for msr\n", smetest_major);
                err = smetest_major;
        goto errout;
        }
        smetest_class = class_create(THIS_MODULE, "smetest");
        if (IS_ERR(smetest_class)) {
                err = PTR_ERR(smetest_class);
                goto errout;
        }
 
    device_create(smetest_class, NULL, MKDEV(smetest_major, 0), NULL, "smetest");
 
    secret = (char *)__get_free_page(GFP_KERNEL);
    if (!secret) {
        printk("Can't allocate page for smetest\n");
        err = -ENOMEM;
        goto errout;
    }
    strcpy(secret, SECRET_DATA);
    printk("secret is %s\n", secret);
 
    return 0;
 
errout:
    smetest_cleanup();
        return err;
}
    
static void smetest_exit(void)
{
    smetest_cleanup();
}
    
module_init(smetest_init);
module_exit(smetest_exit);
 
MODULE_LICENSE("GPL");
