"""Quarantine vault: contains flagged files so they can't run or be opened.

Containment layers:
1. Contents are encrypted (Fernet / AES-128-CBC + HMAC) so the stored bytes are
   not a valid executable, script, or document on any OS.
2. Stored under its SHA-256 with a .qbin extension, so no file-type
   association can open it by double-click. The original name lives only in
   the manifest.
3. File permissions are read-only for the owner (0400) and the vault folder is
   owner-only (0700). On Windows, inheritance is removed with icacls.
4. Restore decrypts, verifies the SHA-256 matches what was quarantined, and
   refuses to overwrite an existing file unless force=True.

Limitation: the key sits in the vault (0600), so anyone with the user's
account can read it. Full isolation would run the vault under a separate
service account, see README.
"""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime

try:
    from cryptography.fernet import Fernet
except ImportError:  # pragma: no cover
    Fernet = None

KEY_FILE = ".vault.key"
MANIFEST_FILE = "manifest.json"


def sha256_file(filepath, chunk_size=65_536):
    digest = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


class QuarantineError(Exception):
    pass


class QuarantineManager:
    def __init__(self, quarantine_dir="quarantine_vault"):
        if Fernet is None:
            raise QuarantineError("Install 'cryptography' to use the quarantine vault")
        self.quarantine_dir = os.path.abspath(quarantine_dir)
        self.manifest_file = os.path.join(self.quarantine_dir, MANIFEST_FILE)
        self.key_file = os.path.join(self.quarantine_dir, KEY_FILE)
        self._setup()
        self._fernet = Fernet(self._load_or_create_key())

    # ---------- setup ----------
    def _setup(self):
        os.makedirs(self.quarantine_dir, exist_ok=True)
        _restrict_dir(self.quarantine_dir)
        if not os.path.exists(self.manifest_file):
            self._write_manifest({})

    def _load_or_create_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                return f.read()
        key = Fernet.generate_key()
        fd = os.open(self.key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        return key

    # ---------- manifest ----------
    def _read_manifest(self):
        with open(self.manifest_file, "r") as f:
            data = json.load(f)
        if isinstance(data, list):  # migrate the old list format
            data = {entry.get("file_hash") or str(i): entry for i, entry in enumerate(data)}
        return data

    def _write_manifest(self, manifest):
        # write to a temp file then rename, so a crash never leaves half a manifest
        fd, tmp = tempfile.mkstemp(dir=self.quarantine_dir, prefix=".manifest-")
        with os.fdopen(fd, "w") as f:
            json.dump(manifest, f, indent=2)
        os.replace(tmp, self.manifest_file)

    # ---------- operations ----------
    def quarantine_file(self, filepath, reason="High risk detected", metadata=None):
        """Encrypt the file into the vault and remove the original.

        Returns the manifest entry, or None on failure.
        """
        if not os.path.isfile(filepath) or os.path.islink(filepath):
            print(f"[ERROR] Not a regular file: {filepath}")
            return None
        original_path = os.path.abspath(filepath)
        if original_path.startswith(self.quarantine_dir + os.sep):
            print(f"[ERROR] File is already inside the vault: {filepath}")
            return None

        try:
            file_hash = sha256_file(original_path)
            original_mode = stat.S_IMODE(os.stat(original_path).st_mode)
            with open(original_path, "rb") as f:
                ciphertext = self._fernet.encrypt(f.read())

            manifest = self._read_manifest()
            qid = file_hash
            n = 1
            while qid in manifest:  # same content quarantined twice from different paths
                qid = f"{file_hash}-{n}"
                n += 1
            vault_path = os.path.join(self.quarantine_dir, f"{qid}.qbin")

            fd = os.open(vault_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(ciphertext)
            _make_inert(vault_path)

            entry = {
                "id": qid,
                "filename": os.path.basename(original_path),
                "original_path": original_path,
                "original_mode": oct(original_mode),
                "vault_path": vault_path,
                "file_hash": file_hash,
                "size_bytes": os.path.getsize(original_path),
                "timestamp": datetime.now().isoformat(),
                "reason": reason,
                "metadata": metadata or {},
            }
            manifest[qid] = entry
            self._write_manifest(manifest)
            os.remove(original_path)  # only after the encrypted copy and manifest are safe
            print(f"[+] Quarantined {entry['filename']} as {qid[:12]}... ({reason})")
            return entry
        except Exception as e:
            print(f"[ERROR] Failed to quarantine {filepath}: {e}")
            return None

    def _find(self, manifest, ident):
        """Look up by id, id prefix, or vault path."""
        if ident in manifest:
            return manifest[ident]
        matches = [e for k, e in manifest.items() if k.startswith(ident) or e.get("vault_path") == ident]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise QuarantineError(f"'{ident}' matches {len(matches)} entries, use a longer id")
        raise QuarantineError(f"No quarantined file matches '{ident}'")

    def restore_file(self, ident, force=False):
        """Decrypt back to the original path after verifying the hash."""
        manifest = self._read_manifest()
        entry = self._find(manifest, ident)
        target = entry["original_path"]

        if os.path.exists(target) and not force:
            raise QuarantineError(f"Refusing to overwrite existing file: {target}")

        with open(entry["vault_path"], "rb") as f:
            plaintext = self._fernet.decrypt(f.read())
        if hashlib.sha256(plaintext).hexdigest() != entry["file_hash"]:
            raise QuarantineError("Hash mismatch, vault copy was altered. Not restoring.")

        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as f:
            f.write(plaintext)
        try:
            os.chmod(target, int(entry.get("original_mode", "0o644"), 8))
        except (OSError, ValueError):
            pass

        _remove_vault_file(entry["vault_path"])
        del manifest[entry["id"]]
        self._write_manifest(manifest)
        print(f"[+] Restored {entry['filename']} to {target} (hash verified)")
        return True

    def delete_quarantined(self, ident):
        manifest = self._read_manifest()
        entry = self._find(manifest, ident)
        _remove_vault_file(entry["vault_path"])
        del manifest[entry["id"]]
        self._write_manifest(manifest)
        print(f"[+] Permanently deleted {entry['filename']}")
        return True

    def list_quarantined(self):
        return sorted(self._read_manifest().values(), key=lambda e: e["timestamp"], reverse=True)

    def get_stats(self):
        entries = self.list_quarantined()
        total = sum(os.path.getsize(e["vault_path"]) for e in entries if os.path.exists(e["vault_path"]))
        return {
            "total_quarantined": len(entries),
            "total_size_bytes": total,
            "total_size_mb": round(total / (1024 * 1024), 2),
            "quarantine_dir": self.quarantine_dir,
        }


# ---------- OS-level controls ----------
def _restrict_dir(path):
    if os.name == "nt":
        _icacls_owner_only(path)
    else:
        os.chmod(path, 0o700)


def _make_inert(path):
    if os.name == "nt":
        _icacls_owner_only(path)
    else:
        os.chmod(path, stat.S_IRUSR)  # 0400: no write, no execute, owner-read only


def _remove_vault_file(path):
    if os.path.exists(path):
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        os.remove(path)


def _icacls_owner_only(path):
    """Windows: drop inherited permissions, grant only the current user + SYSTEM."""
    user = os.environ.get("USERNAME")
    if not user or shutil.which("icacls") is None:
        return
    subprocess.run(["icacls", path, "/inheritance:r",
                    "/grant:r", f"{user}:(R,W,D)", "/grant:r", "SYSTEM:(F)"],
                   capture_output=True, check=False)
