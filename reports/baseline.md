# Baseline — Checkpoint 1

1. **Agent có identity riêng mỗi run chưa?** Chưa. Trong baseline `_naive_loop()` chỉ nhận `message` và `llm`; hàm không tạo hoặc kiểm tra principal, agent ID hay run ID (`agent/loop.py:27-30`). Lưu ý: `run_once()` có tham số `principal_id` ở `agent/loop.py:57-58`, nhưng baseline `_naive_loop()` không nhận hay sử dụng giá trị đó.

2. **Ai cho phép `http_post`?** Không có policy/PEP nào cấp quyền. Luồng `_naive_loop()` gọi `find_injection()`, đọc các customer ID do kết quả injection trả về, rồi gọi `http_post()` nếu có record (`agent/loop.py:34-44`). Vì thế baseline tự đi tới lời gọi tool mà không có quyết định authorization riêng trước đó.

3. **Bằng chứng gửi sai dữ liệu nằm ở đâu?** `tools.http_post()` gửi payload tới sink (`agent/loop.py:42-44`). Sink ghi từng POST vào `reports/sink.log` (`sink/sink.py:37,40-47`). Khi làm CP2, cần sao chép log baseline đã kiểm tra sang `reports/attack-before.log`; file này là evidence trước containment.
