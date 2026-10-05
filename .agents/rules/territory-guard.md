# LUẬT BẢO VỆ RANH GIỚI VÀ PHÂN QUYỀN MÃ NGUỒN (TERRITORY GUARD)

## 1. Bản đồ quyền sở hữu:
- PHÚC sở hữu độc quyền: thư mục `src/core/`
- KHANG sở hữu độc quyền: thư mục `src/security/`
- LÂM sở hữu độc quyền: thư mục `src/automation/`

## 2. Luật bảo vệ bất khả xâm phạm:
- Agent trên máy của thành viên nào CHỈ ĐƯỢC PHÉP chỉnh sửa file trong thư mục của thành viên đó.
- NẾU phát hiện yêu cầu sửa code nằm ngoài thư mục của mình:
  -> DỪNG LẠI NGAY LẬP TỨC.
  -> Không được tự ý sửa file.
  -> Đưa ra cảnh báo cho người dùng: 
     "⚠️ CẢNH BÁO: File này thuộc quyền sở hữu của [Tên chủ code]. Bạn không nên chỉnh sửa trực tiếp. Hãy liên hệ với [Tên chủ code] để thống nhất hoặc gọi qua hàm Interface trong shared/schemas.py!"
- Khi cần kết nối với module của người khác: Chỉ được ĐỌC (Read-Only) để hiểu cách gọi hàm, TUYỆT ĐỐI không được sửa mã nguồn bên trong của bạn mình.
