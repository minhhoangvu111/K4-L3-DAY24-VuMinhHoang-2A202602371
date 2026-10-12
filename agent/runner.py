"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
_AGENT_ID = "lab24-agent"
_AGENT_CAPABILITIES = ("search_docs", "read_customer", "http_post")
_SINK_URL = "http://127.0.0.1:10024/reconcile"


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _args_hash(args: dict) -> str:
    serialized = json.dumps(args, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _authorize_and_audit(
    *, path: Path, run_id: str, principal_id: str, expires_at: str,
    tool_name: str, args: dict, classification: str, purpose: str,
    scopes: tuple[str, ...], egress_enabled: bool = False,
) -> bool:
    context = policy.PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=f"{_AGENT_ID}/{run_id}",
        delegation_depth=0,
        egress_enabled=egress_enabled,
        principal_id=principal_id,
        requested_tool=tool_name,
        agent_scopes=scopes,
        parent_scopes=(),
        expires_at=expires_at,
    )
    allowed, reason = policy.check(context)
    ledger.append({
        "ts": _timestamp(),
        "agent_id": _AGENT_ID,
        "run_id": run_id,
        "tool": tool_name,
        "args_hash": _args_hash(args),
        "classification": classification,
        "decision": "allow" if allowed else "deny",
        "reason": reason,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
    }, path)
    return allowed


def _run_a(message: str, llm, *, path: Path, run_id: str,
           principal_id: str, expires_at: str) -> tuple[tuple[int, ...], str, bool]:
    """Read untrusted documents, sanitize their content, and emit typed IDs only."""
    allowed = _authorize_and_audit(
        path=path,
        run_id=run_id,
        principal_id=principal_id,
        expires_at=expires_at,
        tool_name="search_docs",
        args={"query": message},
        classification="internal",
        purpose="summarize-tickets",
        scopes=("search_docs",),
    )
    if not allowed:
        return (), llm.summarize([]), False

    docs = tools.search_docs(message)
    ticket_ids: set[int] = set()
    for doc in docs:
        # File names are produced by search_docs. Ignore arbitrary IDs and
        # extract only numeric ticket IDs from the expected corpus filename.
        match = re.fullmatch(r"ticket-(\d+)[a-z]?\.md", Path(doc["id"]).name, re.IGNORECASE)
        if match:
            ticket_ids.add(int(match.group(1)))

    sanitized_docs = [
        {"id": doc["id"], "text": pii.redact(doc["text"])}
        for doc in docs
    ]
    safe_context = "\n\n".join(doc["text"] for doc in sanitized_docs)
    suspicious = llm.find_injection(safe_context) is not None
    summary = llm.summarize(sanitized_docs)

    # Only typed IDs and a safe user-facing summary leave Run A. Raw documents,
    # free text, and customer IDs extracted by the model are deliberately dropped.
    return tuple(sorted(ticket_ids)), summary, suspicious


def _run_b(ticket_ids: tuple[int, ...], *, path: Path, run_id: str,
           principal_id: str, expires_at: str) -> None:
    """Resolve trusted ticket relationships, then authorize each customer read."""
    already_read: set[str] = set()
    customer_index: list[dict] | None = None

    for ticket_id in ticket_ids:
        # Authorize before consulting the private customer store. This lets a
        # denied principal stop at the policy boundary without reading records.
        if not _authorize_and_audit(
            path=path,
            run_id=run_id,
            principal_id=principal_id,
            expires_at=expires_at,
            tool_name="read_customer",
            args={"ticket_id": ticket_id},
            classification="restricted",
            purpose="support-reply",
            scopes=("read_customer",),
        ):
            continue

        if customer_index is None:
            customer_index = json.loads((DATA_DIR / "customers.json").read_text(encoding="utf-8"))

        related = [
            str(customer["customer_id"])
            for customer in customer_index
            if ticket_id in customer.get("related_tickets", [])
        ]
        for customer_id in related:
            if customer_id in already_read:
                continue
            # Check again at the exact tool boundary using the resolved ID.
            allowed = _authorize_and_audit(
                path=path,
                run_id=run_id,
                principal_id=principal_id,
                expires_at=expires_at,
                tool_name="read_customer",
                args={"customer_id": customer_id},
                classification="restricted",
                purpose="support-reply",
                scopes=("read_customer",),
            )
            if allowed:
                tools.read_customer(customer_id)
                already_read.add(customer_id)


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_dir = Path(log_dir) if log_dir is not None else REPORTS_DIR
    ledger_path = ledger_dir / "ledger.jsonl"
    run_id = uuid.uuid4().hex
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")

    ticket_ids, answer, suspicious = _run_a(
        message,
        llm,
        path=ledger_path,
        run_id=run_id,
        principal_id=principal_id,
        expires_at=expires_at,
    )
    _run_b(
        ticket_ids,
        path=ledger_path,
        run_id=run_id,
        principal_id=principal_id,
        expires_at=expires_at,
    )

    if suspicious:
        # The fixed localhost destination keeps the lab harness bounded. The
        # PEP must deny restricted-data egress before http_post can execute.
        _authorize_and_audit(
            path=ledger_path,
            run_id=run_id,
            principal_id=principal_id,
            expires_at=expires_at,
            tool_name="http_post",
            args={"url": _SINK_URL},
            classification="restricted",
            purpose="support-reply",
            scopes=("http_post",),
            egress_enabled=True,
        )

    return answer
