import argparse
from RansomwareAudit.backup.manager import BackupManager

def main():
    parser = argparse.ArgumentParser(description="Backup Manager")
    parser.add_argument('action', choices=['create', 'list', 'restore', 'delete'],
                       help='Action to perform')
    parser.add_argument('--source', help='Source directory for backup')
    parser.add_argument('--name', help='Backup name')
    parser.add_argument('--restore-to', help='Restore destination')
    parser.add_argument('--backup-dir', default='ransomware_backups',
                       help='Backup directory (default: ransomware_backups)')
    
    args = parser.parse_args()
    
    bm = BackupManager(backup_dir=args.backup_dir)
    
    print("\n" + "="*70)
    print("BACKUP MANAGER")
    print("="*70 + "\n")
    
    if args.action == 'create':
        if not args.source:
            print("[ERROR] --source required for create action")
        else:
            bm.create_backup(args.source, args.name)
    
    elif args.action == 'list':
        backups = bm.list_backups()
        if not backups:
            print("[*] No backups found")
        else:
            print(f"[*] Found {len(backups)} backup(s):\n")
            for backup in backups:
                print(f"Name: {backup['backup_name']}")
                print(f"  Source: {backup['source_dir']}")
                print(f"  Created: {backup['timestamp']}")
                print(f"  Size: {backup['size_mb']} MB")
                print()
    
    elif args.action == 'restore':
        if not args.name:
            print("[ERROR] --name required for restore action")
        else:
            bm.restore_backup(args.name, args.restore_to)
    
    elif args.action == 'delete':
        if not args.name:
            print("[ERROR] --name required for delete action")
        else:
            confirm = input(f"Delete backup {args.name}? (yes/no): ")
            if confirm.lower() == 'yes':
                bm.delete_backup(args.name)
            else:
                print("[*] Deletion cancelled")

if __name__ == '__main__':
    main()
