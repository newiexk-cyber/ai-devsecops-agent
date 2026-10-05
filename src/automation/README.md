# ⚙️ LÃNH THỔ CỦA LÂM (DevOps, CI/CD & Git Bot Lead)

Thư mục này dành riêng cho LÂM phát triển pipeline tự động hóa:
- `webhook_server.py`: FastAPI server lắng nghe `git push` từ GitHub
- `sandbox_manager.py`: Clone repo vào thư mục cách ly để chạy quét
- `test_runner.py`: Tự động chạy Unit Test (pytest/npm/dotnet) kiểm chứng bản vá
- `github_bot.py`: Tự tạo branch mới và mở Pull Request qua PyGithub
- `dashboard/`: Giao diện Web theo dõi lịch sử quét

👉 **Quy ước:** 
- Nhận `AgentRunOutput` từ Phúc để đóng gói vào Pull Request.
- Các thành viên khác chỉ gọi hàm trong thư mục này, không sửa file bên trong.
