/*
 * memhook_report.c — 优化上报：LKM workqueue 轮询美团进程内上报槽
 *
 * 背景：美团进程内 hook 若直接开 netlink socket / open 设备，会被 MTGuard
 *       检测到。优化为：美团进程内只写注入段的上报槽（无系统调用），
 *       LKM 本 workqueue 用 access_process_vm 定时读该槽，发现新事件
 *       再经 mh_nl_send 组播到控制端。美团进程零可疑痕迹。
 *
 * 上报槽布局（与 grab_hook.h 的 MH_REPORT_*_OFF 一致）：
 *   int type; int code; int pid; char payload[64];
 *
 * 参数：
 *   report_pid  美团进程 pid（控制端注入时经 ioctl/模块参数设置）
 *   report_addr 上报槽虚拟地址（注入段 + MH_SC_REPORT_OFF）
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/delay.h>

/* 与 grab_hook.h 对齐的 slot 布局 */
struct mh_report_slot {
    int type;            /* 0x0  1=GRAB 2=RISK 3=STATE */
    int code;            /* 0x4  0=ok 1=rejected ... */
    int pid;             /* 0x8 */
    char payload[64];    /* 0xC */
};

/* memhook_netlink.c 提供（EXPORT_SYMBOL） */
int mh_nl_send(int type, int code, int pid, const char *msg);

static int report_pid = -1;
module_param(report_pid, int, 0644);
MODULE_PARM_DESC(report_pid, "Meituan app pid to poll (default -1=off)");

static unsigned long report_addr = 0;
module_param(report_addr, ulong, 0644);
MODULE_PARM_DESC(report_addr, "Report slot virtual address in target process");

static struct workqueue_struct *mh_report_wq = NULL;
static struct delayed_work mh_report_work;

static struct task_struct *mh_get_task(pid_t pid) {
    struct task_struct *tsk = NULL;
    rcu_read_lock();
    tsk = find_task_by_vpid(pid);
    if (tsk) get_task_struct(tsk);
    rcu_read_unlock();
    return tsk;
}

static void mh_report_work_fn(struct work_struct *work) {
    struct mh_report_slot slot;
    struct task_struct *tsk;
    ssize_t n;

    if (report_pid > 0 && report_addr) {
        tsk = mh_get_task(report_pid);
        if (tsk) {
            memset(&slot, 0, sizeof(slot));
            n = access_process_vm(tsk, report_addr, &slot, sizeof(slot), 0);
            if (n == (ssize_t)sizeof(slot) && slot.type > 0) {
                /* 新事件 → 组播到控制端 */
                slot.payload[63] = '\0';
                mh_nl_send(slot.type, slot.code, slot.pid, slot.payload);
                /* 清零槽（美团进程侧写 type=0 表示"已消费"） */
                memset(&slot, 0, sizeof(slot));
                access_process_vm(tsk, report_addr, &slot, sizeof(slot), FOLL_WRITE);
            }
            put_task_struct(tsk);
        }
    }
    /* 100ms 周期轮询 */
    queue_delayed_work(mh_report_wq, &mh_report_work, msecs_to_jiffies(100));
}

int mh_report_init(void) {
    mh_report_wq = create_singlethread_workqueue("memhook_report");
    if (!mh_report_wq) return -ENOMEM;
    INIT_DELAYED_WORK(&mh_report_work, mh_report_work_fn);
    queue_delayed_work(mh_report_wq, &mh_report_work, msecs_to_jiffies(100));
    pr_info("memhook: report poller ready (pid=%d addr=%lx)\n",
            report_pid, report_addr);
    return 0;
}

void mh_report_exit(void) {
    if (mh_report_wq) {
        cancel_delayed_work_sync(&mh_report_work);
        destroy_workqueue(mh_report_wq);
        mh_report_wq = NULL;
    }
}
