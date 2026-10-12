# Báo cáo sự cố secret giả trong lịch sử Git

- **Scanner và phiên bản:** Gitleaks 8.30.1, dùng `.gitleaks.toml` của lab.
- **Commit chứa token giả:** `1bdd849922156c868a5ee9293d68f5b72e242d2c` (seed commit).
- **File, rule và kết quả quét lịch sử:** `lab-fake-secret.txt`, rule `lab24-synthetic-token`, dòng 1. Gitleaks quét 4 commit và phát hiện 1 finding; exit code 1 là kết quả kỳ vọng của bài tập. Giá trị token là dữ liệu giả của lab.
- **Kết quả quét file hiện tại:** Quét thư mục làm việc với rule `lab24-synthetic-token` trả exit code 0, không phát hiện finding. Gitleaks bỏ qua `.pytest_cache` và `.pytest_tmp` do Windows báo permission denied; bộ binary Gitleaks tải về chứa ví dụ credential trong README và không phải mã nguồn của lab.
- **Nếu đây là credential thật, cần xử lý thế nào:** Thu hồi/rotate credential ngay tại dịch vụ phát hành; kiểm tra log truy cập và phạm vi ảnh hưởng; lưu bằng chứng; sau đó dọn credential khỏi các nhánh và lịch sử Git theo quy trình của nhóm. Xóa file khỏi HEAD không làm credential đã lộ mất hiệu lực.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:** Git giữ phiên bản cũ trong lịch sử và các clone/fork có thể còn bản lộ. Pin phiên bản cùng hash kiểm soát tính toàn vẹn dependency nhưng không vô hiệu hóa credential bị lộ; cần rotate và tiếp tục quét lịch sử.
