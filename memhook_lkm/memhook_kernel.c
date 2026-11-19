/*
 * memhook_kernel.c — 内存层抢单内核辅助 LKM（反检测核心）
 *
 * 目标内核：6.1.118-android14-11-g64180ab070e5 (GKI, ARM64)
 * 前置：KernelSU 已加载（提供提权与 kallsyms 自定位）
 * 功能：
 *   1) 隐藏自身模块（/proc/modules、lsmod 不可见）
 *   2) 拦截 ptrace：TARGET_APP 不可被外部 attach（TracerPid 归零）
 *   3) 拦截 openat：TARGET_APP 对 /proc/self/mem 及注入文件屏蔽
 *   4) 拦截 process_vm_readv/writev：保护 hook 点 .text 段 CRC 校验
 *   5) /proc/self/maps 过滤：TARGET_APP 的注入 RWX 匿名段不出现
 *      （通过替换 seq_file.show 指针；SUSFS 的 add_sus_maps 可作为兜底）
 *
 * 编译（在目标内核源码树内）：
 *   make -C <kernel_build_dir> M=$PWD ARCH=arm64 CROSS_COMPILE=aarch64-linux-android- memhook_ko.ko
 * 加载：
 *   su -c 'insmod /data/local/tmp/memhook_ko.ko target_pid=xxxx'
 *
 * 说明：本文件为可编译骨架；若某些符号在当前 GKI 内核不可用，部署时用
 *       SUSFS 协同（见 lkm/README_协同.md）补齐对应功能。
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("memhook");
MODULE_DESCRIPTION("Memhook kernel anti-detection helper");

/* memhook_dev.c 提供 /dev/memhook_ctl 注入通道 */
int mh_dev_init(void);
void mh_dev_exit(void);

/* memhook_netlink.c 提供 NETLINK_USER 事件上报 */
int mh_nl_init(void);
void mh_nl_exit(void);
int mh_nl_send(int type, int code, int pid, const char *msg);

/* ------------------------------------------------------------------ */
/* 参数                                                                */
/* ------------------------------------------------------------------ */
static int target_pid = -1;               /* 注入目标进程 PID（美团众包） */
module_param(target_pid, int, 0644);
MODULE_PARM_DESC(target_pid, "Target app pid to protect (default -1=off)");

static bool hide_self = true;             /* 隐藏自身模块 */
module_param(hide_self, bool, 0644);

static char target_comm[16] = "com.sankuai.meituan.dispatch.crowdsource";
module_param_string(target_comm, target_comm, sizeof(target_comm), 0644);

/* ------------------------------------------------------------------ */
/* 符号自定位（GKI 6.1 下 kallsyms_lookup_name 不导出，用 kprobe 技巧） */
/* ------------------------------------------------------------------ */
static unsigned long (*real_kallsyms_lookup)(const char *name);

static int kls_lookup_handler(struct kprobe *p, struct pt_regs *regs) {
    /* 拿到被 kprobe 拦截的 kallsyms_lookup_name 真实地址（X0=name 参数） */
    real_kallsyms_lookup = (unsigned long (*)(const char *))(regs->regs[0]);
    return 0;
}
static struct kprobe kls_kp = {
    .symbol_name = "kallsyms_lookup_name",
    .pre_handler = kls_lookup_handler,
};

static unsigned long find_symbol(const char *name) {
    if (real_kallsyms_lookup) return real_kallsyms_lookup(name);
    return 0;
}

/* ------------------------------------------------------------------ */
/* 1) 隐藏自身模块                                                     */
/* ------------------------------------------------------------------ */
static void hide_module(struct module *mod) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
    /* 从全局模块链表摘除（需要持 module_mutex，这里骨架简化直接 list_del） */
    list_del(&mod->list);
    /* 防止被 /proc/modules 遍历到（list_del 已足够，模块引用计数仍有效） */
#endif
}

/* ------------------------------------------------------------------ */
/* 2) 拦截 ptrace（TARGET_APP 不可 attach）                            */
/* ------------------------------------------------------------------ */
static int target_matches(struct task_struct *tsk) {
    if (target_pid > 0 && tsk->pid == target_pid) return 1;
    if (target_comm[0] && tsk->comm && !strncmp(tsk->comm, target_comm, 15)) return 1;
    return 0;
}

static int ptrace_pre(struct kprobe *p, struct pt_regs *regs) {
    /* __arm64_sys_ptrace(regs): request in regs[1], pid in regs[2] */
    struct task_struct *tsk = NULL;
    long pid = (long)regs->regs[2];   /* 第二个参数 = pid_t pid */
    if (pid <= 0) return 0;
    rcu_read_lock();
    tsk = find_task_by_vpid((int)pid);
    if (tsk && target_matches(tsk)) {
        /* 拒绝任何 ptrace 操作（attach/peek/poke/cont/syscall），防外部附加 */
        regs->regs[0] = -EPERM;       /* 返回值 = -EPERM */
        rcu_read_unlock();
        return 1;                     /* 跳过原函数 */
    }
    rcu_read_unlock();
    return 0;
}
static struct kprobe ptrace_kp = { .symbol_name = "__arm64_sys_ptrace", .pre_handler = ptrace_pre };

/* ------------------------------------------------------------------ */
/* 3) 拦截 openat（TARGET_APP 屏蔽 /proc/self/mem 与注入文件）          */
/* ------------------------------------------------------------------ */
static int openat_pre(struct kprobe *p, struct pt_regs *regs) {
    /* do_sys_openat2(dfd, filename, how): filename 在 regs[1]（struct filename*）*/
    struct filename *fn = (struct filename *)regs->regs[1];
    char *path = NULL;
    if (!fn) return 0;
    path = fn->name;
    if (!path) return 0;
    /* 当前进程是目标，且尝试打开敏感路径 */
    if (target_matches(current)) {
        if (strstr(path, "/proc/self/mem") ||
            strstr(path, "/proc/self/pagemap") ||
            strstr(path, "/memfd:memhook_inject")) {
            regs->regs[0] = -EACCES;
            return 1;
        }
    }
    return 0;
}
static struct kprobe openat_kp = { .symbol_name = "do_sys_openat2", .pre_handler = openat_pre };

/* ------------------------------------------------------------------ */
/* 4) 拦截 process_vm_readv / process_vm_writev（保护 hook 点 .text CRC）*/
/* ------------------------------------------------------------------ */
static int procvm_pre(struct kprobe *p, struct pt_regs *regs) {
    /* process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags) */
    struct task_struct *tsk = NULL;
    long pid = (long)regs->regs[0];
    if (pid <= 0) return 0;
    rcu_read_lock();
    tsk = find_task_by_vpid((int)pid);
    if (tsk && target_matches(tsk)) {
        /* 外部进程读/写目标进程内存 = 可能的 CRC 校验/注入检测，拒绝 */
        rcu_read_unlock();
        regs->regs[0] = -EPERM;
        return 1;
    }
    rcu_read_unlock();
    return 0;
}
static struct kprobe procvm_read_kp  = { .symbol_name = "__arm64_sys_process_vm_readv",  .pre_handler = procvm_pre };
static struct kprobe procvm_write_kp = { .symbol_name = "__arm64_sys_process_vm_writev", .pre_handler = procvm_pre };

/* ------------------------------------------------------------------ */
/* 5) /proc/self/maps 过滤（注入 RWX 匿名段不出现在 maps）               */
/*    用 seq_file->op->show 替换为自写 show，过滤注入段。                */
/*    注：show_map_vma 是 static 不可直接 kallsyms，故读取原 op->show。  */
/* ------------------------------------------------------------------ */
typedef int (*seq_show_fn)(struct seq_file *, void *);
static seq_show_fn orig_map_show = NULL;

static bool is_inject_vma(struct vm_area_struct *vma) {
    /* 注入段 = 匿名 + 可写 + 可执行 + 非文件映射 */
    if (!(vma->vm_flags & VM_WRITE) || !(vma->vm_flags & VM_EXEC)) return false;
    if (vma->vm_file) return false;                 /* 有文件映射 -> 不是匿名注入段 */
    if (vma->vm_start >= vma->vm_end) return false;
    /* 通过 vm_private_data 或起始地址标记可进一步精筛；骨架用启发式 */
    return true;
}

static int memhook_map_show(struct seq_file *m, void *v) {
    struct vm_area_struct *vma = (struct vm_area_struct *)v;
    if (target_matches(current) && vma && is_inject_vma(vma)) {
        /* 跳过该段：注入段不打印 */
        return 0;
    }
    if (orig_map_show) return orig_map_show(m, v);
    return 0;
}

static int maps_open_pre(struct kprobe *p, struct pt_regs *regs) {
    /* seq_open(file, ops) 或 single_open: file 在 regs[0] */
    struct file *file = (struct file *)regs->regs[0];
    if (!file) return 0;
    if (target_matches(current)) {
        struct seq_file *m = NULL;
        if (file->private_data) m = (struct seq_file *)file->private_data;
        if (m && m->op && m->op->show) {
            if (!orig_map_show) orig_map_show = m->op->show;
            m->op->show = memhook_map_show;   /* 替换 show */
        }
    }
    return 0;
}
static struct kprobe maps_open_kp = { .symbol_name = "seq_open", .pre_handler = maps_open_pre };

/* ------------------------------------------------------------------ */
/* 注册/卸载                                                           */
/* ------------------------------------------------------------------ */
static int register_kprobe_or_fail(struct kprobe *kp) {
    int r = register_kprobe(kp);
    if (r < 0) {
        pr_warn("memhook: kprobe %s failed (%d)\n", kp->symbol_name, r);
    }
    return r;
}

static int __init memhook_init(void) {
    int r;

    pr_info("memhook: init, target_pid=%d hide_self=%d\n", target_pid, hide_self);

    /* 自定位 kallsyms_lookup_name */
    r = register_kprobe(&kls_kp);
    if (r == 0) {
        unregister_kprobe(&kls_kp);
        pr_info("memhook: kallsyms_lookup_name @ %px\n", real_kallsyms_lookup);
    }

    register_kprobe_or_fail(&ptrace_kp);
    register_kprobe_or_fail(&openat_kp);
    register_kprobe_or_fail(&procvm_read_kp);
    register_kprobe_or_fail(&procvm_write_kp);
    register_kprobe_or_fail(&maps_open_kp);

    /* 注入通道（/dev/memhook_ctl） */
    mh_dev_init();

    /* NETLINK_USER 事件上报 */
    mh_nl_init();

    if (hide_self) {
        hide_module(THIS_MODULE);
    }

    return 0;
}

static void __exit memhook_exit(void) {
    unregister_kprobe(&ptrace_kp);
    unregister_kprobe(&openat_kp);
    unregister_kprobe(&procvm_read_kp);
    unregister_kprobe(&procvm_write_kp);
    unregister_kprobe(&maps_open_kp);
    mh_dev_exit();
    mh_nl_exit();
    pr_info("memhook: exit\n");
}

module_init(memhook_init);
module_exit(memhook_exit);
