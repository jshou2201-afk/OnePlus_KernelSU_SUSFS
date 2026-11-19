/*
 * memhook_dev.c — /dev/memhook_ctl 字符设备：注入引擎 ↔ 内核通信通道
 *
 * 用途：让"内存注入引擎"通过 ioctl 在目标进程内存中分配 RWX 匿名段、
 *       写入 shellcode、安装 inline hook —— 全程不依赖 ptrace，
 *       也不在目标进程落地任何文件（MAP_ANONYMOUS 无文件映射）。
 *
 * ioctl 命令（与 control 端头文件 memhook_ioctl.h 一致）：
 *   MH_IOCTL_MAP      目标进程 mmap RWX 匿名段，返回地址
 *   MH_IOCTL_WRITE    向目标进程地址写数据（access_process_vm）
 *   MH_IOCTL_ARM_HOOK 在目标进程目标地址安装 16 字节绝对跳转（inline hook）
 *   MH_IOCTL_CALL     在目标进程设置 PC 到注入 shellcode（重定向执行）
 *
 * 内核 API 版本：6.1（GKI）。do_mmap 为 7 参数形式（带 populate/uf）。
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <asm/cacheflush.h>

/* 与用户态共享的 ioctl 编号（同 memhook_ioctl.h） */
#define MH_IOCTL_MAP       _IOWR('M', 1, struct mh_map_req)
#define MH_IOCTL_WRITE     _IOWR('M', 2, struct mh_write_req)
#define MH_IOCTL_ARM_HOOK  _IOWR('M', 3, struct mh_hook_req)
#define MH_IOCTL_CALL      _IOWR('M', 4, struct mh_call_req)

struct mh_map_req {
    pid_t pid;             /* 目标进程 */
    unsigned long size;    /* 映射大小(页对齐) */
    unsigned long addr;    /* 出参：映射地址 */
    int result;            /* 出参：0 或 -errno */
};

struct mh_write_req {
    pid_t pid;
    unsigned long addr;    /* 目标地址 */
    unsigned long len;
    unsigned long uptr;    /* 用户态源缓冲 */
    int result;
};

struct mh_hook_req {
    pid_t pid;
    unsigned long target;  /* 被 hook 函数地址(目标进程虚拟地址) */
    unsigned long hook;    /* hook 函数地址(目标进程虚拟地址) */
    int result;
};

struct mh_call_req {
    pid_t pid;
    unsigned long pc;      /* 设置 PC 到该地址 */
    unsigned long x0;      /* 第一个参数(如 context/jobject) */
    unsigned long x1;      /* 第二个参数 */
    int result;
};

static dev_t mh_devno;
static struct cdev mh_cdev;
static struct class *mh_class;

/* ------------------------------------------------------------------ */
/* 辅助                                                                */
/* ------------------------------------------------------------------ */
static struct task_struct *mh_get_task(pid_t pid) {
    struct task_struct *tsk = NULL;
    rcu_read_lock();
    tsk = find_task_by_vpid(pid);
    if (tsk) get_task_struct(tsk);
    rcu_read_unlock();
    return tsk;
}

/* 在目标进程地址空间 mmap RWX 匿名段 */
static int mh_map_rwx(pid_t pid, unsigned long size, unsigned long *out_addr) {
    struct task_struct *tsk = mh_get_task(pid);
    struct mm_struct *mm;
    unsigned long len = PAGE_ALIGN(size);
    unsigned long addr;
    int r = 0;
    if (!tsk) return -ESRCH;
    mm = get_task_mm(tsk);
    if (!mm) { put_task_struct(tsk); return -EINVAL; }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    /* 6.1 形式：7 参数 + populate + uf */
    addr = do_mmap(NULL, 0, len,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS,
                   0, NULL, NULL);
#else
    addr = do_mmap(NULL, 0, len,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, 0);
#endif
    if (IS_ERR((void *)addr)) r = (int)PTR_ERR((void *)addr);
    else *out_addr = addr;

    mmput(mm);
    put_task_struct(tsk);
    return r;
}

/* 向目标进程地址写数据 */
static int mh_write_mem(pid_t pid, unsigned long addr, unsigned long uptr, unsigned long len) {
    struct task_struct *tsk = mh_get_task(pid);
    ssize_t n;
    if (!tsk) return -ESRCH;
    n = access_process_vm(tsk, addr, (void *)uptr, len, FOLL_WRITE);
    put_task_struct(tsk);
    if (n != (ssize_t)len) return -EFAULT;
    return 0;
}

/* 安装 16 字节绝对跳转（inline hook）: LDR X16,#8; BR X16; .quad hook */
static int mh_arm_hook(pid_t pid, unsigned long target, unsigned long hook) {
    struct task_struct *tsk = mh_get_task(pid);
    u32 patch[4];
    ssize_t n;
    if (!tsk) return -ESRCH;
    patch[0] = 0x58000050u;               /* LDR X16, #8   */
    patch[1] = 0xD61F0200u;               /* BR X16        */
    patch[2] = (u32)(hook & 0xffffffffu); /* 低 32 位地址   */
    patch[3] = (u32)(hook >> 32);         /* 高 32 位地址   */
    n = access_process_vm(tsk, target, patch, sizeof(patch), FOLL_WRITE);
    put_task_struct(tsk);
    if (n != (ssize_t)sizeof(patch)) return -EFAULT;
    /* 刷新指令缓存，确保目标进程执行新指令 */
#if defined(CONFIG_ARM64)
    flush_icache_range(target, target + sizeof(patch));
#else
    flush_icache_range((unsigned long)target, (unsigned long)target + sizeof(patch));
#endif
    return 0;
}

/* 设置目标进程 PC（重定向执行到注入 shellcode） */
static int mh_set_pc(pid_t pid, unsigned long pc, unsigned long x0, unsigned long x1) {
    struct task_struct *tsk = mh_get_task(pid);
    struct pt_regs *regs;
    int r = 0;
    if (!tsk) return -ESRCH;
    regs = task_pt_regs(tsk);
    if (!regs) { put_task_struct(tsk); return -EINVAL; }
    /* 直接改 regs 需要在目标线程暂停时进行；骨架用 ptrace 放行方式，此处写 regs */
    regs->pc = pc;
    regs->regs[0] = x0;
    regs->regs[1] = x1;
    /* 触发调度，让目标线程从新 PC 继续 */
    put_task_struct(tsk);
    return r;
}

/* ------------------------------------------------------------------ */
/* ioctl                                                              */
/* ------------------------------------------------------------------ */
static long mh_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    long ret = 0;
    switch (cmd) {
    case MH_IOCTL_MAP: {
        struct mh_map_req req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
        ret = mh_map_rwx(req.pid, req.size, &req.addr);
        req.result = (int)ret;
        if (copy_to_user((void __user *)arg, &req, sizeof(req))) return -EFAULT;
        return ret;
    }
    case MH_IOCTL_WRITE: {
        struct mh_write_req req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
        ret = mh_write_mem(req.pid, req.addr, req.uptr, req.len);
        req.result = (int)ret;
        if (copy_to_user((void __user *)arg, &req, sizeof(req))) return -EFAULT;
        return ret;
    }
    case MH_IOCTL_ARM_HOOK: {
        struct mh_hook_req req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
        ret = mh_arm_hook(req.pid, req.target, req.hook);
        req.result = (int)ret;
        if (copy_to_user((void __user *)arg, &req, sizeof(req))) return -EFAULT;
        return ret;
    }
    case MH_IOCTL_CALL: {
        struct mh_call_req req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
        ret = mh_set_pc(req.pid, req.pc, req.x0, req.x1);
        req.result = (int)ret;
        if (copy_to_user((void __user *)arg, &req, sizeof(req))) return -EFAULT;
        return ret;
    }
    default:
        return -EINVAL;
    }
}

static int mh_open(struct inode *inode, struct file *filp) { return 0; }
static int mh_release(struct inode *inode, struct file *filp) { return 0; }

static const struct file_operations mh_fops = {
    .owner = THIS_MODULE,
    .open = mh_open,
    .release = mh_release,
    .unlocked_ioctl = mh_ioctl,
    .compat_ioctl = mh_ioctl,
};

int mh_dev_init(void) {
    int r;
    r = alloc_chrdev_region(&mh_devno, 0, 1, "memhook_ctl");
    if (r) return r;
    cdev_init(&mh_cdev, &mh_fops);
    mh_cdev.owner = THIS_MODULE;
    r = cdev_add(&mh_cdev, mh_devno, 1);
    if (r) { unregister_chrdev_region(mh_devno, 1); return r; }
    mh_class = class_create(THIS_MODULE, "memhook_ctl");
    if (IS_ERR(mh_class)) {
        cdev_del(&mh_cdev);
        unregister_chrdev_region(mh_devno, 1);
        return PTR_ERR(mh_class);
    }
    device_create(mh_class, NULL, mh_devno, NULL, "memhook_ctl");
    pr_info("memhook: /dev/memhook_ctl ready\n");
    return 0;
}

void mh_dev_exit(void) {
    device_destroy(mh_class, mh_devno);
    class_destroy(mh_class);
    cdev_del(&mh_cdev);
    unregister_chrdev_region(mh_devno, 1);
}
