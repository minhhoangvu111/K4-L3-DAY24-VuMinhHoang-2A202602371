"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re
import unicodedata


_EMAIL = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
    r"(?![\w-])"
)
_NUMBER = re.compile(r"(?<!\w)\d(?:[\s.-]?\d){7,15}(?!\w)")
_BANK_LABEL = re.compile(r"\b(?:stk|tai\s*khoan|bank\s+account|account)\b")
_PHONE_LABEL = re.compile(r"\b(?:sdt|so\s*dien\s*thoai|dien\s*thoai|phone)\b")
_CCCD_LABEL = re.compile(r"\b(?:cccd|can\s*cuoc|identity\s*card)\b")


def _fold(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(char for char in normalized if not unicodedata.combining(char)).lower()


def detect(text: str) -> list[dict]:
    """Find synthetic Vietnamese IDs/contact details with character offsets.

    Numeric values are classified using nearby field labels where available:
    STK/account labels take precedence over the generic 12-digit CCCD shape,
    while 10/11 digit values starting with 0 are treated as phone numbers.
    Unlabelled 8-16 digit values are not guessed to be bank accounts, reducing
    false positives on ticket numbers and other ordinary numeric text.
    """
    entities: list[dict] = []
    email_spans: list[tuple[int, int]] = []

    for match in _EMAIL.finditer(text):
        start, end = match.span()
        email_spans.append((start, end))
        entities.append({"type": "EMAIL", "start": start, "end": end})

    for match in _NUMBER.finditer(text):
        start, end = match.span()
        if any(start < email_end and email_start < end for email_start, email_end in email_spans):
            continue

        value = match.group()
        digits = re.sub(r"\D", "", value)
        # Look only within the current clause so a previous field label does not
        # accidentally classify an unrelated number later in the sentence.
        prefix = text[max(0, start - 80):start]
        prefix = re.split(r"[.!?;\n]", prefix)[-1]
        context = _fold(prefix)

        if 8 <= len(digits) <= 16 and _BANK_LABEL.search(context):
            entity_type = "VN_BANK_ACCOUNT"
        elif len(digits) == 12:
            entity_type = "VN_CCCD"
        elif digits.startswith("0") and len(digits) in (10, 11):
            entity_type = "VN_PHONE"
        elif len(digits) in (10, 11) and _PHONE_LABEL.search(context):
            entity_type = "VN_PHONE"
        elif len(digits) == 12 and _CCCD_LABEL.search(context):
            entity_type = "VN_CCCD"
        else:
            continue

        entities.append({"type": entity_type, "start": start, "end": end})

    return sorted(entities, key=lambda item: (item["start"], item["end"], item["type"]))


def redact(text: str) -> str:
    entities = detect(text)
    for entity in sorted(entities, key=lambda item: item["start"], reverse=True):
        start, end = entity["start"], entity["end"]
        text = text[:start] + f"[REDACTED_{entity['type']}]" + text[end:]
    return text
