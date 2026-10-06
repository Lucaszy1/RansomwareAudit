import argparse

from RansomwareAudit.config.manager import get_config
from RansomwareAudit.monitor.watcher import EventMonitor, FileSystemMonitor


def main(argv=None):
    cfg = get_config()
    parser = argparse.ArgumentParser(description="Real-time ransomware monitoring")
    parser.add_argument("paths", nargs="+", help="Directories to monitor")
    parser.add_argument("--interval", "-i", type=int,
                        default=cfg.get("monitoring.interval_seconds", 5),
                        help="Polling interval in seconds (polling mode)")
    parser.add_argument("--events", action="store_true",
                        help="Use OS file events (watchdog) instead of polling")
    args = parser.parse_args(argv)

    if args.events:
        EventMonitor(args.paths, cfg=cfg).run_forever()
    else:
        FileSystemMonitor(args.paths, cfg=cfg).start_monitoring(interval=args.interval)


if __name__ == "__main__":
    main()
