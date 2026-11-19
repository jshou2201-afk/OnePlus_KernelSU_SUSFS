# memhook_lkm/Makefile — Kbuild 外部模块格式（供 GitHub Actions 用 make M= 编译）
#
# 在 OnePlus_KernelSU_SUSFS 的 build-kernel action 里：
#   make -C $COMMON_KERNEL_FOLDER O=$OUT ARCH=arm64 LLVM=1 LLVM_IAS=1 \
#        LD=...ld-wrapper HOSTLD=... \
#        M=$GITHUB_WORKSPACE/memhook_lkm memhook_ko.ko
# 输出：$OUT/memhook_lkm/memhook_ko.ko
#
# 也可在内核树内： make -C <kernel> M=$(pwd) memhook_ko.ko

obj-m += memhook_ko.o
memhook_ko-objs := memhook_kernel.o memhook_dev.o memhook_netlink.o memhook_report.o
