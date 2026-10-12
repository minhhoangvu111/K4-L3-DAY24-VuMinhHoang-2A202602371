# DPIA-lite — đánh giá sơ bộ luồng dữ liệu trong lab

## Phạm vi và dữ liệu

- Lab chạy deterministic với `--mock`; corpus và `data/customers.json` chứa fixture synthetic. Không nhập hồ sơ cá nhân hoặc credential thật.
- Agent xử lý nội dung ticket (internal) và một số trường hồ sơ khách hàng (restricted): tên, CCCD, điện thoại, số tài khoản, email. PII detector/redactor nằm ở `agent/pii.py:54-115`; Run A redacts nội dung tài liệu trước khi đưa cho bước tóm tắt tại `agent/runner.py:123-159`.

## Mục đích và quyền

- Mục đích demo: tổng hợp ticket và chứng minh kiểm soát truy cập/egress trong bài học, không dùng cho quyết định thực tế về khách hàng.
- `support_l1` và `dpo` là principal mô phỏng lấy từ `data/principals.json`; `--as dpo` không chứng minh người dùng đã được xác thực. Quyết định quyền được kiểm tra trước tool tại `agent/policy.py:60-112` và ghi audit tại `agent/runner.py:90-119`.

## Luồng xử lý và nơi dữ liệu đi

1. Run A tìm tài liệu trong `corpus/`, dò dấu hiệu injection, redacts văn bản và chỉ chuyển các ticket ID số lấy từ tên file; xem `agent/runner.py:123-160`.
2. Run B tra quan hệ ticket–khách từ `data/customers.json`, authorize trước `read_customer`; xem `agent/runner.py:162-211`. Hồ sơ được đọc trong bài test/replay nhưng nội dung không đưa vào ledger hay gửi tiếp ở đường egress bị chặn.
3. `http_post` chỉ nhắm `http://127.0.0.1:10024/reconcile` trong harness (`agent/runner.py:78`, `agent/tools.py:26-28,68-86`). Policy deny khi dữ liệu restricted đi qua egress (`agent/policy.py:60-64`). Sink là server local ghi POST vào `reports/sink.log` (`sink/sink.py:40-48,58-62`).
4. Ledger cục bộ `reports/ledger.jsonl` lưu metadata, lý do, identity mô phỏng, TTL và `args_hash`; không lưu PII thô theo thiết kế (`agent/runner.py:90-119`, `agent/ledger.py:54-109`).

## Kết quả, rủi ro còn lại và giới hạn

- Bằng chứng replay sau containment: `reports/attack-after.log` rỗng; dòng ledger 201 ghi `http_post` deny, `on_behalf_of=dpo`, reason `restricted data cannot use egress`. Ledger xác minh hash chain thành công ở lần kiểm CP5.
- Rủi ro còn lại: regex có thể bỏ sót PII hoặc đánh dấu nhầm; fixture principal không thay xác thực thật; file ledger cục bộ có thể bị xóa/ghi lại bởi người có quyền trên máy; mock không kiểm tra network, IAM, retention, encryption, quyền vận hành, hay mọi tình huống injection ngoài bộ test.
- Đây là DPIA-lite học tập, không phải đánh giá tác động chính thức, tư vấn pháp lý, hay kết luận tuân thủ. Trước khi dùng dữ liệu thật cần xác định controller/processor, căn cứ và mục đích xử lý, thông báo/quyền chủ thể, retention, nơi lưu/chia sẻ, kiểm soát truy cập, ứng phó sự cố và các hồ sơ pháp lý phù hợp.
