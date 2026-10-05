# -*- coding: utf-8 -*-
"""
sync.py - Script tự động kéo code & đẩy code an toàn cho nhóm PHÚC, KHANG, LÂM
"""
import subprocess
import sys

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()

def main():
    print("=" * 60)
    print("🚀 TOOL TỰ ĐỘNG ĐỒNG BỘ DỰ ÁN: AI DEVSECOPS MULTI-AGENT")
    print("=" * 60)

    # 1. Kéo code mới nhất từ GitHub
    print("\n[1/3] Đang kéo cập nhật mới nhất từ GitHub (git pull origin main)...")
    code_pull, out_pull, err_pull = run_cmd("git pull origin main --rebase")
    if code_pull != 0:
        print(f"⚠️ Lưu ý từ Git: {err_pull or out_pull}")
    else:
        print("✅ Đã cập nhật xong toàn bộ code mới nhất của các bạn trong nhóm!")

    # 2. Kiểm tra thay đổi của người dùng
    _, status, _ = run_cmd("git status --porcelain")
    if not status:
        print("\n🎉 Bạn chưa sửa file nào. Mã nguồn của bạn đang đồng bộ 100% với GitHub!")
        return

    print("\n[2/3] Phát hiện bạn có thay đổi mã nguồn:")
    for line in status.splitlines():
        print(f"   {line}")

    # Lấy nhánh hiện tại
    _, current_branch, _ = run_cmd("git branch --show-current")
    if current_branch in ["main", "master", ""]:
        print("\n⚠️ Bạn đang đứng ở nhánh 'main'. Để an toàn, chúng ta cần đẩy lên nhánh riêng của bạn.")
        user = input("👉 Nhập tên bạn (phuc / khang / lam): ").strip().lower()
        while user not in ["phuc", "khang", "lam"]:
            user = input("Vui lòng chỉ nhập đúng 'phuc', 'khang' hoặc 'lam': ").strip().lower()
        target_branch = f"feat/{user}-dev"
        run_cmd(f"git checkout -B {target_branch}")
    else:
        target_branch = current_branch

    commit_msg = input("\n💬 Nhập mô tả ngắn gọn việc bạn vừa làm (Enter để lấy mặc định): ").strip()
    if not commit_msg:
        commit_msg = f"feat: cập nhật tiến độ từ nhánh {target_branch}"

    # 3. Đóng gói và đẩy lên
    print(f"\n[3/3] Đang đóng gói và đẩy code lên branch [{target_branch}]...")
    run_cmd("git add .")
    run_cmd(f'git commit -m "{commit_msg}"')
    code_push, out_push, err_push = run_cmd(f"git push origin {target_branch}")

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
