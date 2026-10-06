# 📊 TÀI LIỆU BỘ DỮ LIỆU CHUẨN: DIVERSEVUL (RAID 2023)

> **Mục đích:** Bộ dữ liệu kiểm thử chuẩn (Benchmark Dataset) dùng để đánh giá độ chính xác, tỷ lệ bắt lỗi của Semgrep và khả năng lọc báo ảo / sinh bản vá của AI Agent.

---

## 1. THÔNG TIN BÀI BÁO KHOA HỌC
* **Tên nghiên cứu:** *DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection*
* **Hội nghị công bố:** **RAID 2023** (International Symposium on Research in Attacks, Intrusions and Defenses).
* **Tác giả:** Yizheng Chen, Zhoujie Ding, Lamya Alowain, Xinyun Chen, David Wagner (**Đại học UC Berkeley, Mỹ**).
* **Kho mã nguồn GitHub:** [https://github.com/wagner-group/diversevul](https://github.com/wagner-group/diversevul)
* **Bản PDF bài báo:** [https://surrealyz.github.io/files/pubs/raid23-diversevul.pdf](https://surrealyz.github.io/files/pubs/raid23-diversevul.pdf)

---

## 2. LINK TẢI BỘ DỮ LIỆU GỐC (GOOGLE DRIVE)
* **File Dataset (Chứa code hàm lỗi & code sửa):** [Tải tại đây](https://drive.google.com/file/d/12IWKhmLhq7qn5B_iXgn5YerOQtkH-6RG/view?usp=sharing)
* **File Metadata (Chứa Commit URL & Repository URL của 7.512 commit):** [Tải tại đây](https://drive.google.com/file/d/19cJ7avNtsziaYkrrYuW7FeFdvgrxoNLc/view?usp=sharing)

---

## 3. CẤU TRÚC DỮ LIỆU ĐẶC BIỆT
Mỗi mẫu trong DiverseVul lưu trữ theo cặp đối chiếu:
* `func`: Đoạn mã nguồn hàm thực tế.
* `target`: 
  * `1`: Code có chứa lỗ hổng bảo mật.
  * `0`: Code an toàn (sau khi đã được lập trình viên vá lỗi).
* `cwe`: Danh sách các mã lỗ hổng CWE tương ứng (CWE-89, CWE-79, CWE-119, CWE-476, CWE-22...).
* `project` & `commit_id`: Dự án nguồn mở và commit sửa lỗi tương ứng.

---

## 4. HƯỚNG DẪN DÀNH CHO KHANG (SECURITY LEAD)
Trong **Tuần 9 - 10**, Khang sẽ sử dụng bộ dữ liệu này như sau:
1. Trích xuất **50 - 100 mẫu hàm** thuộc 4 nhóm lỗi mục tiêu của nhóm (SQLi, XSS, Path Traversal, Secrets).
2. Lưu các file code mẫu vào thư mục `src/security/datasets/samples/`.
3. Cho Semgrep quét trước $\rightarrow$ Ghi nhận số lượng cảnh báo.
4. Cho AI Agent của Phúc thẩm định và sinh bản vá $\rightarrow$ So sánh bản vá của AI với bản vá của chuyên gia trong DiverseVul.
5. Tính toán các chỉ số: **Precision, Recall, Tỷ lệ giảm False Positive** để đưa vào báo cáo đồ án nộp trường.
