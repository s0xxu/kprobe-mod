#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/slab.h>
static struct kprobe kp;



static int pre_handler(struct kprobe *kp, struct pt_regs *regs)
{
	const struct pt_regs *sys_regs = (const struct pt_regs *)regs->di; //userspace syscall arguments stored in rdi, current regs is kernel registers from kernel memory
	pr_info("kernel pt_regs %px", regs);
			if (sys_regs->orig_ax != __NR_openat) { //check if the rax argument matches the value of the syscall on our system
				pr_err("ERR ORIG_AX != OPENAT \n");	
				return -1;
			}
	char *buf;
		buf = kmalloc(PATH_MAX, GFP_ATOMIC); //allocate memory for buffer, using PATH_MAX on stack could potentially overflow the kernel stack frame which could crash our kernel or result in undefined behavior
			if (!buf) {
				pr_err("KMALLOC FAIL PATH_MAX");
				return 0;
			}
	long ret = strncpy_from_user(buf, (const char __user *)sys_regs->si, PATH_MAX); //copy from userspace pointer containing filename string to our buffer, returns length of string including 'null-trail'
		if (ret < 0) {
				pr_err("PATHNAME OPENAT RETURN < 0\n");	
		}
	buf[ret] = '\0';
	pr_info("openat: dfd: %d \n path: %s \n flags: %lx \n mode: %lx \n", (int)sys_regs->di, buf, sys_regs->dx, sys_regs->r10); 
	kfree(buf); //free memory from heap
	return 0;
}



static int __init init_mod(void) 
{
	int err; 
	pr_info("KERN HOOK MOD LOAD");
	kp.symbol_name = "__x64_sys_openat"; //register syscall for openat in kprobe structure before we register it, sys_entry will push the userspace values to the kernel stack, and we will now grab them
	kp.pre_handler = pre_handler; //declare our pre_handler function for the kprobe structure
	err = register_kprobe(&kp); //declare our kprobe data structure to the kprobe API
		if (err < 0) {
			pr_err("KPROBE REGISTER FAIL");	
			return -1;
		}
	pr_info("KPROBE REG SUCCEED");
	return 0;
}



static void __exit exit_mod(void) 
{
	unregister_kprobe(&kp);
	pr_info("KERN HOOK MOD UNLOAD");
}

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("s0xxu");
MODULE_DESCRIPTION("read userspace syscall arguments in kernel space via kprobe api");
