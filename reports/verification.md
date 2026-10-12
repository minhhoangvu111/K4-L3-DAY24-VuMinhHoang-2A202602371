# Verification — Checkpoint 5

Ngày chạy: 2026-10-12. Workspace: repo Lab Day 24; shell thực thi là Windows PowerShell với Python trong `.venv`.

## Môi trường

- OS: Windows (CP0 đã chuẩn bị WSL Ubuntu, nhưng lệnh CP5 thực thi/được ghi nhận tại Windows workspace).
- Python: 3.12.10; pytest: 9.1.1.
- Gitleaks: 8.30.1 (`gitleaks_8.30.1_windows_x64/gitleaks.exe`).
- Test cần `tmp_path`; chạy toàn bộ test với quyền tạo thư mục temporary do Windows ACL từ chối temp mặc định khi chạy sandbox thường.

## Kết quả xác minh

| Kiểm tra | Kết quả |
|---|---|
| `python -m pytest tests/ -q` | **33 passed in 8.05s** (Python Windows `.venv`; cấp quyền temp để pytest dùng fixture). |
| `gitleaks version` | **8.30.1**. |
| Quét lịch sử `gitleaks git --config .gitleaks.toml --redact --verbose .` | **1 finding synthetic** tại `1bdd849...`, rule `lab24-synthetic-token`; exit 1 là kết quả mong đợi, chi tiết ở `reports/secrets-incident.md`. |
| Quét working tree theo rule lab | `gitleaks dir --config .gitleaks.toml --redact --no-banner --enable-rule lab24-synthetic-token .`: **no leaks found**, exit 0. Gitleaks báo bỏ qua `.pytest_cache` và `.pytest_tmp` do permission denied. Quét mặc định toàn bộ rules từng gặp ví dụ credential trong README của gói binary Gitleaks tải về; đó là tài liệu công cụ bên ngoài, không phải source lab. |
| Replay sau containment | Reset sink, chạy `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"`; copy `reports/sink.log` sang `reports/attack-after.log`. Kết quả CLI thành công với `PYTHONUTF8=1`; `attack-after.log` có **0 byte / 0 dòng**. `reports/attack-before.log` còn **1 dòng** synthetic chứa record `KH-000999`. |
| Egress deny | Ledger run CP5 có 67 dòng; dòng `reports/ledger.jsonl:201` là `http_post`, `decision=deny`, `on_behalf_of=dpo`, reason `restricted data cannot use egress`. Sink không nhận POST. |
| Ledger verify | `python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"` → **True**. File hiện có 201 dòng, mỗi dòng có reason; hash chain hợp lệ. |
| `pre-commit run --all-files` | **Passed** — hook `Detect hardcoded secrets` (Gitleaks) khởi tạo và hoàn tất thành công trong WSL Ubuntu (`.venv-linux`). |
| `git diff --check` | Pass; chỉ có cảnh báo line ending CRLF/LF trên các file Markdown. |

## Giới hạn / việc cần làm trước khi nộp

- Test CP5 pass toàn bộ; pre-commit đã chạy thành công trong WSL Ubuntu theo kết quả người dùng xác nhận.
- `reports/ledger.jsonl` và `reports/attack-*.log` bị `.gitignore` bỏ qua theo cấu hình repo; kiểm tra file đúng nội dung trước khi stage thủ công theo `SUBMISSION.md` nếu cần nộp chúng.
- Chưa tạo commit mới; HEAD tại thời điểm ghi report là `52b33b5bddfcfdb5425010d6996c5c1d8eed13bd`. Hãy ghi SHA commit cuối sau khi tạo commit nộp.
