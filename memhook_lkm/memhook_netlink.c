/*
 * memhook_netlink.c — NETLINK_USER 事件上报通道（LKM → 控制端 APK）
 *
 * 用途：把抢单结果 / 风控触发事件异步上报到控制端（用户态 netlink socket）。
 * 与 ioctl（下行配置）互补：ioctl 走 /dev/memhook_ctl，netlink 走 NETLINK_USER。
 *
 * 消息格式（struct mh_nl_event）：
 *   type: 1=GRAB_RESULT, 2=RISK_TRIGGER, 3=STATE_CHANGE
 *   code: 0=ok, 1=rejected, 2=sealed, 3=armed, 4=detected
 *   pid: 目标进程 pid；payload[0..N) 附加文本（UTF-8, NUL 结尾）
 *
 * 控制端：socket(AF_NETLINK, SOCK_RAW, NETLINK_USER) → bind → recv。
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>

#define MH_NETLINK_PROTO   (NETLINK_USERSOCK)   /* 或 NETLINK_USER=2 */
#define MH_NL_GRP          1                    /* 组播组 1 */

static struct sock *mh_nl_sk = NULL;

/* 事件消息 */
struct mh_nl_event {
    int type;
    int code;
    int pid;
    char payload[64];
};

int mh_nl_init(void);
void mh_nl_exit(void);

/* 上报事件到用户态 */
int mh_nl_send(int type, int code, int pid, const char *msg) {
    struct mh_nl_event ev;
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    struct nlattr *attr;
    int len;

    if (!mh_nl_sk) return -ENODEV;

    memset(&ev, 0, sizeof(ev));
    ev.type = type;
    ev.code = code;
    ev.pid = pid;
    if (msg) strncpy(ev.payload, msg, sizeof(ev.payload) - 1);

    len = NLMSG_SPACE(sizeof(struct mh_nl_event));
    skb = alloc_skb(len, GFP_KERNEL);
    if (!skb) return -ENOMEM;

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, sizeof(struct mh_nl_event), 0);
    if (!nlh) { kfree_skb(skb); return -EMSGSIZE; }
    memcpy(nlmsg_data(nlh), &ev, sizeof(ev));
    nlmsg_end(skb, nlh);

    /* 组播到 MH_NL_GRP */
    nlmsg_multicast(mh_nl_sk, skb, 0, MH_NL_GRP, GFP_KERNEL);
    return 0;
}
EXPORT_SYMBOL(mh_nl_send);   /* memhook_report.c 轮询线程调用 */

int mh_nl_init(void) {
    struct netlink_kernel_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.groups = 1;                 /* 组播组数量（MH_NL_GRP=1） */
    mh_nl_sk = netlink_kernel_create(&init_net, MH_NETLINK_PROTO, &cfg);
    if (!mh_nl_sk) {
        pr_err("memhook: netlink create failed\n");
        return -ENOMEM;
    }
    pr_info("memhook: netlink ready (proto=%d grp=%d)\n", MH_NETLINK_PROTO, MH_NL_GRP);
    return 0;
}

void mh_nl_exit(void) {
    if (mh_nl_sk) {
        netlink_kernel_release(mh_nl_sk);
        mh_nl_sk = NULL;
    }
}
