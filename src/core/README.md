# 👑 LÃNH THỔ CỦA PHÚC (Trưởng nhóm - AI Core Lead)

Thư mục này dành riêng cho PHÚC phát triển bộ não Multi-Agent:
- `langgraph_graph.py`: Đồ thị trạng thái StateGraph
- `prompts/`: Chứa các prompt trích xuất context, lọc báo ảo, sinh bản vá
- `llm_client.py`: Module gọi API Qwen 2.5 Coder / DeepSeek V3 / Claude 3.5

👉 **Quy ước:** 
- Nhận input: `ScannerOutput` từ `shared.schemas`
- Trả output: `AgentRunOutput` sang `shared.schemas`
- Các thành viên khác chỉ gọi hàm trong thư mục này, không sửa file bên trong.
