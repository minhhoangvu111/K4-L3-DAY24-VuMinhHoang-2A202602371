"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu một dòng còn trong file bị sửa mà không tính lại
        hash, nếu xoá/chèn giữa file làm đứt liên kết, hoặc thiếu reason.
        Chỉ kiểm tra file hiện có KHÔNG phát hiện được việc xoá dòng cuối
        hoặc viết lại cả file và tính lại chuỗi. Muốn phát hiện cắt đuôi
        phải lưu hash/số dòng cuối ở một nơi tin cậy bên ngoài file rồi
        đối chiếu. Bài lab không cung cấp mốc đó.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


_GENESIS_HASH = "0" * 64


def _digest(entry: dict) -> str:
    payload = {key: value for key, value in entry.items() if key != "hash"}
    canonical = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    previous_hash = _GENESIS_HASH
    if path.exists() and path.stat().st_size:
        lines = path.read_text(encoding="utf-8").splitlines()
        if lines:
            try:
                previous_hash = json.loads(lines[-1])["hash"]
            except (json.JSONDecodeError, KeyError, TypeError):
                # Preserve a broken chain as broken; verification will reject it.
                previous_hash = "invalid-previous-hash"

    record = dict(entry)
    record.pop("hash", None)
    record["prev_hash"] = previous_hash
    record["hash"] = _digest(record)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
        stream.write("\n")
    return record


def verify(path: Path) -> bool:
    path = Path(path)
    if not path.exists():
        return False

    previous_hash = _GENESIS_HASH
    try:
        with path.open("r", encoding="utf-8") as stream:
            for raw_line in stream:
                if not raw_line.strip():
                    return False
                record = json.loads(raw_line)
                if not isinstance(record, dict):
                    return False
                if not isinstance(record.get("reason"), str) or not record["reason"].strip():
                    return False
                if record.get("prev_hash") != previous_hash:
                    return False
                stored_hash = record.get("hash")
                if not isinstance(stored_hash, str) or stored_hash != _digest(record):
                    return False
                previous_hash = stored_hash
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return False
    return True
