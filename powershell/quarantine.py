"""Conservative local file quarantine with identity and postcondition checks."""
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class FileQuarantine:
    """Move one verified regular file into the agent-owned quarantine directory."""

    def __init__(self, root=None):
        base = root or Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ZTA" / "quarantine"
        self.root = Path(base).resolve()

    def validate(self, file_path: str, expected_sha256: str) -> tuple[Path, str]:
        if not isinstance(file_path, str) or not file_path or "\x00" in file_path:
            raise ValueError("Quarantine requires an exact file path")
        if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
            raise ValueError("Quarantine requires an expected SHA-256 identity")
        try:
            int(expected_sha256, 16)
        except ValueError as exc:
            raise ValueError("Expected SHA-256 is invalid") from exc
        source = Path(file_path)
        if source.is_symlink():
            raise ValueError("Symbolic links and reparse targets cannot be quarantined")
        source = source.resolve(strict=True)
        if not source.is_file():
            raise ValueError("Quarantine target must be one regular file")
        protected = [Path(os.environ.get(name, value)).resolve() for name, value in (
            ("SystemRoot", r"C:\Windows"), ("ProgramFiles", r"C:\Program Files"),
            ("ProgramFiles(x86)", r"C:\Program Files (x86)"), ("ProgramData", r"C:\ProgramData"))]
        if any(source == root or root in source.parents for root in protected):
            raise ValueError("Protected system/application path cannot be quarantined")
        actual = _sha256(source)
        if actual.casefold() != expected_sha256.casefold():
            raise ValueError("Quarantine target hash changed")
        return source, actual

    def quarantine(self, file_path: str, expected_sha256: str) -> dict:
        source, digest = self.validate(file_path, expected_sha256)
        self.root.mkdir(parents=True, exist_ok=True)
        item_id = uuid4().hex
        destination = self.root / f"{item_id}.bin"
        metadata = self.root / f"{item_id}.json"
        shutil.move(str(source), str(destination))
        evidence = {"quarantine_id": item_id, "original_path": str(source),
                    "quarantine_path": str(destination), "sha256": digest,
                    "quarantined_at": datetime.now(timezone.utc).isoformat()}
        metadata.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
        if source.exists() or not destination.is_file() or _sha256(destination) != digest or not metadata.is_file():
            raise RuntimeError("File quarantine postcondition was not verified")
        return evidence
