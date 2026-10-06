import argparse
import sys

from RansomwareAudit.config.manager import get_config
from RansomwareAudit.quarantine.manager import QuarantineManager, QuarantineError


def main(argv=None):
    cfg = get_config()
    parser = argparse.ArgumentParser(description="Quarantine vault manager")
    parser.add_argument("action", choices=["add", "list", "restore", "delete", "stats"])
    parser.add_argument("target", nargs="?", help="File path (add) or quarantine id/prefix (restore/delete)")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing file on restore")
    parser.add_argument("--yes", action="store_true", help="Skip delete confirmation")
    parser.add_argument("--quarantine-dir", default=cfg.get("quarantine.quarantine_dir", "quarantine_vault"))
    args = parser.parse_args(argv)

    qm = QuarantineManager(quarantine_dir=args.quarantine_dir)
    try:
        if args.action == "list":
            entries = qm.list_quarantined()
            if not entries:
                print("[*] Vault is empty")
            for e in entries:
                print(f"{e['id'][:12]}  {e['timestamp'][:19]}  {e['original_path']}")
                print(f"              reason: {e['reason']}")
        elif args.action == "stats":
            s = qm.get_stats()
            print(f"{s['total_quarantined']} files, {s['total_size_mb']} MB in {s['quarantine_dir']}")
        elif not args.target:
            parser.error(f"'{args.action}' needs a target")
        elif args.action == "add":
            return 0 if qm.quarantine_file(args.target, reason="Manual quarantine") else 1
        elif args.action == "restore":
            qm.restore_file(args.target, force=args.force)
        elif args.action == "delete":
            if args.yes or input(f"Permanently delete {args.target}? (yes/no): ").lower() == "yes":
                qm.delete_quarantined(args.target)
            else:
                print("[*] Cancelled")
    except QuarantineError as e:
        print(f"[ERROR] {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
