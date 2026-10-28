# -*- coding: utf-8 -*-
"""
sync.py - Script tự động kéo code & đẩy code an toàn cho nhóm PHÚC, KHANG, LÂM
Đã loại bỏ hoàn toàn shell=True và format chuỗi cmd thô nhằm ngăn ngừa Command Injection.
Sử dụng subprocess với đối số danh sách (argv) và xác thực regex nghiêm ngặt cho branch name.
"""
import re
import subprocess
import sys
from typing import List, Tuple

BRANCH_REGEX = re.compile(r"^[A-Za-z0-9._/-]+$")


def run_cmd_args(args: List[str]) -> Tuple[int, str, str]:
    """Chạy lệnh an toàn qua danh sách đối số trực tiếp, không qua shell."""
    try:
        result = subprocess.run(args, shell=False, text=True, capture_output=True)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def main():
    print("=" * 60)
    print("🚀 TOOL TỰ ĐỘNG ĐỒNG BỘ DỰ ÁN: AI DEVSECOPS MULTI-AGENT")
    print("=" * 60)

    # 1. Kéo code mới nhất từ GitHub
    print("\n[1/3] Đang kéo cập nhật mới nhất từ GitHub (git pull origin main --rebase)...")
    code_pull, out_pull, err_pull = run_cmd_args(["git", "pull", "origin", "main", "--rebase"])
    if code_pull != 0:
        print(f"⚠️ Lưu ý từ Git: {err_pull or out_pull}")
    else:
        print("✅ Đã cập nhật xong toàn bộ code mới nhất của các bạn trong nhóm!")

    # 2. Kiểm tra thay đổi của người dùng
    _, status, _ = run_cmd_args(["git", "status", "--porcelain"])
    if not status:
        print("\n🎉 Bạn chưa sửa file nào. Mã nguồn của bạn đang đồng bộ 100% với GitHub!")
        return

    print("\n[2/3] Phát hiện bạn có thay đổi mã nguồn:")
    for line in status.splitlines():
        print(f"   {line}")

    # Lấy nhánh hiện tại
    _, current_branch, _ = run_cmd_args(["git", "branch", "--show-current"])
    if current_branch in ["main", "master", ""]:
        print("\n⚠️ Bạn đang đứng ở nhánh 'main'. Để an toàn, chúng ta cần đẩy lên nhánh riêng của bạn.")
        user = input("👉 Nhập tên bạn (phuc / khang / lam): ").strip().lower()
        while user not in ["phuc", "khang", "lam"]:
            user = input("Vui lòng chỉ nhập đúng 'phuc', 'khang' hoặc 'lam': ").strip().lower()
        target_branch = f"feat/{user}-dev"
        if not BRANCH_REGEX.match(target_branch):
            print("❌ Tên nhánh không hợp lệ.")
            return
        run_cmd_args(["git", "checkout", "-B", target_branch])
    else:
        target_branch = current_branch
        if not BRANCH_REGEX.match(target_branch):
            print("❌ Tên nhánh hiện tại chứa ký tự không an toàn.")
            return

    commit_msg = input("\n💬 Nhập mô tả ngắn gọn việc bạn vừa làm (Enter để lấy mặc định): ").strip()
    if not commit_msg:
        commit_msg = f"feat: cập nhật tiến độ từ nhánh {target_branch}"

    # 3. Đóng gói và đẩy lên
    print(f"\n[3/3] Đang đóng gói và đẩy code lên branch [{target_branch}]...")
    # Thu thập danh sách các file thay đổi thực tế để add an toàn
    run_cmd_args(["git", "add", "-u"])  # Add các file đã tracked được sửa/xóa
    code_commit, out_commit, err_commit = run_cmd_args(["git", "commit", "-m", commit_msg])

    if code_commit != 0 and "nothing to commit" not in (out_commit + err_commit).lower():
        print(f"⚠️ Lưu ý commit: {err_commit or out_commit}")

    code_push, out_push, err_push = run_cmd_args(["git", "push", "origin", target_branch])

    if code_push == 0:
        print("\n" + "=" * 60)
        print("🎉 ĐẨY LÊN GITHUB THÀNH CÔNG RỰC RỠ!")
        print(f"👉 Chi nhánh: {target_branch}")
        print("👉 Bạn chỉ cần vào GitHub bấm 'Create Pull Request' để hợp nhất vào main.")
        print("=" * 60)
    else:
        print(f"\n❌ Lỗi khi push lên GitHub: {err_push or out_push}")


if __name__ == "__main__":
    main()
