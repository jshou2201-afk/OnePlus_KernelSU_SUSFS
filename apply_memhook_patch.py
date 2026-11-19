#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apply_memhook_patch.py — 把 memhook_lkm 编进 OnePlus_KernelSU_SUSFS 的 CI 构建。

用法（在你 fork 的 OnePlus_KernelSU_SUSFS 仓库根目录执行）：
    python3 apply_memhook_patch.py

它做两件事：
  1) 复制 ./memhook_lkm/ 到仓库根（若不存在）
  2) 修改 .github/actions/build-kernel/action.yml：
     a. 在 "Build Kernel" 步骤的 make Image 之后，追加编译 memhook_ko.ko
     b. 在 "Create Kernel ZIP" 步骤的 cp Image 之后，把 memhook_ko.ko 收进刷机包

改完 commit + push 后，到 Actions 页面手动触发 oneplus-custom.yml，
选择 OnePlus-Ace3-Pro-6.1.118 (A16) + FinaSU，构建产物 AnyKernel3.zip 里
将包含 memhook_ko.ko（刷入后 su -c 'insmod /data/.../memhook_ko.ko target_pid=<美团pid>'）。
"""
import os, sys, shutil, filecmp

ROOT = os.getcwd()
ACTION = os.path.join(ROOT, ".github/actions/build-kernel/action.yml")
LKM_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "memhook_lkm")
LKM_DST = os.path.join(ROOT, "memhook_lkm")

def copy_lkm():
    if not os.path.isdir(LKM_SRC):
        print("[!] 未找到 memhook_lkm 源码目录:", LKM_SRC); return
    if os.path.isdir(LKM_DST):
        # 只覆盖缺失/不同文件
        changed = False
        for f in os.listdir(LKM_SRC):
            s, d = os.path.join(LKM_SRC, f), os.path.join(LKM_DST, f)
            if (not os.path.exists(d)) or (not filecmp.cmp(s, d, shallow=False)):
                shutil.copy2(s, d); changed = True
        print("[*] memhook_lkm 已存在，覆盖了缺失/不同文件" if changed else "[*] memhook_lkm 已是最新")
    else:
        shutil.copytree(LKM_SRC, LKM_DST)
        print("[+] 复制 memhook_lkm ->", LKM_DST)

def patch_action():
    if not os.path.isfile(ACTION):
        print("[!] 未找到 action.yml:", ACTION); return False
    with open(ACTION, "r", encoding="utf-8", errors="replace") as f:
        txt = f.read()
    orig = txt

    # a) Build Kernel: 在 IMG 变量定义前插入 LKM 编译
    anchor_build = 'IMG="$OUT/arch/arm64/boot/Image"'
    block_build = '''
        # === memhook_lkm: 编译反检测内核模块 ===
        if [ -d "$GITHUB_WORKSPACE/memhook_lkm" ]; then
          echo "::group::Build memhook_ko.ko (external module)"
          make LD="$COMMON_KERNEL_FOLDER/ld-wrapper" HOSTLD="$COMMON_KERNEL_FOLDER/ld-wrapper" \\
            -C "$COMMON_KERNEL_FOLDER" O="$OUT" ARCH=arm64 LLVM=1 LLVM_IAS=1 \\
            M="$GITHUB_WORKSPACE/memhook_lkm" memhook_ko.ko \\
            || echo "::warning::memhook_ko.ko build failed"
          echo "::endgroup::"
        fi
'''
    if "memhook_lkm" in txt:
        print("[*] Build Kernel 已含 memhook_lkm，跳过 a")
    elif anchor_build in txt:
        txt = txt.replace(anchor_build, block_build + "\n" + anchor_build, 1)
        print("[+] Build Kernel 已插入 memhook_ko.ko 编译")
    else:
        print("[!] 未找到 Build Kernel 锚点:", anchor_build)

    # b) Create Kernel ZIP: cp Image 后收集 ko
    anchor_zip = 'cp "$IMAGE_PATH" "$AK3_FOLDER/Image"'
    block_zip = '''
        # === memhook_lkm: 收集 ko 到刷机包 ===
        if [ -f "$COMMON_KERNEL_FOLDER/out/memhook_lkm/memhook_ko.ko" ]; then
          cp "$COMMON_KERNEL_FOLDER/out/memhook_lkm/memhook_ko.ko" "$AK3_FOLDER/memhook_ko.ko"
          echo "Added memhook_ko.ko to ZIP"
        fi
'''
    if "memhook_lkm" in txt and "collect memhook_ko.ko" in txt:
        print("[*] Create ZIP 已含 memhook ko 收集，跳过 b")
    elif anchor_zip in txt:
        txt = txt.replace(anchor_zip, anchor_zip + block_zip, 1)
        print("[+] Create Kernel ZIP 已插入 memhook_ko.ko 收集")
    else:
        print("[!] 未找到 Create ZIP 锚点:", anchor_zip)

    # c) 独立上传 memhook_ko.ko 为 artifact（供 KoLoader 加载，无需刷内核）
    anchor_up = '    - name: Final Build Summary'
    block_up = '''    - name: Upload memhook_lkm artifact
      if: ${{ env.COMMON_KERNEL_FOLDER != '' }}
      uses: actions/upload-artifact@v4
      with:
        name: memhook_lkm
        path: ${{ env.COMMON_KERNEL_FOLDER }}/out/memhook_lkm/memhook_ko.ko
        if-no-files-found: warn

'''
    if "Upload memhook_lkm artifact" in txt:
        print("[*] 已含独立 memhook_lkm artifact 上传，跳过 c")
    elif anchor_up in txt:
        txt = txt.replace(anchor_up, block_up + anchor_up, 1)
        print("[+] 已插入独立 memhook_lkm artifact 上传")
    else:
        print("[!] 未找到 Final Build Summary 锚点:", anchor_up)

    if txt != orig:
        with open(ACTION, "w", encoding="utf-8") as f:
            f.write(txt)
        print("[+] action.yml 已更新")
    else:
        print("[*] action.yml 无变化")
    return True

if __name__ == "__main__":
    print("== memhook_lkm CI patch ==")
    copy_lkm()
    if patch_action():
        print("== 完成。请 commit + push 后触发 oneplus-custom.yml ==")
