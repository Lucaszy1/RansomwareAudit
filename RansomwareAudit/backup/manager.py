import os
import shutil
import tarfile
import json
from datetime import datetime
from pathlib import Path

import re

_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


def _check_name(name):
    """Backup names become file names, so block '../' style traversal."""
    if not _SAFE_NAME.match(name or "") or name.startswith("."):
        raise ValueError(f"Invalid backup name: {name!r} (use letters, numbers, _ . -)")
    return name


def _safe_extract(tar, dest):
    """Extract without letting archive members escape `dest` (path traversal)."""
    if hasattr(tarfile, "data_filter"):  # Python 3.12+ / patched 3.8+
        tar.extractall(path=dest, filter="data")
        return
    dest_real = os.path.realpath(dest)
    for member in tar.getmembers():
        target = os.path.realpath(os.path.join(dest, member.name))
        if not (target == dest_real or target.startswith(dest_real + os.sep)):
            raise ValueError(f"Blocked unsafe path in archive: {member.name}")
        if member.issym() or member.islnk():
            raise ValueError(f"Blocked link in archive: {member.name}")
    tar.extractall(path=dest)


class BackupManager:
    def __init__(self, backup_dir="ransomware_backups"):
        self.backup_dir = backup_dir
        os.makedirs(backup_dir, exist_ok=True)
    
    def create_backup(self, source_dir, backup_name=None):
        if not backup_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"backup_{timestamp}"
        _check_name(backup_name)
        
        backup_path = os.path.join(self.backup_dir, f"{backup_name}.tar.gz")
        
        print(f"[*] Creating backup of: {source_dir}")
        print(f"[*] Backup file: {backup_path}")
        
        try:
            with tarfile.open(backup_path, "w:gz") as tar:
                tar.add(source_dir, arcname=os.path.basename(source_dir))
            
            backup_size = os.path.getsize(backup_path)
            backup_size_mb = backup_size / (1024 * 1024)
            
            metadata = {
                'backup_name': backup_name,
                'backup_path': backup_path,
                'source_dir': os.path.abspath(source_dir),
                'timestamp': datetime.now().isoformat(),
                'size_bytes': backup_size,
                'size_mb': round(backup_size_mb, 2)
            }
            
            metadata_path = os.path.join(self.backup_dir, f"{backup_name}_metadata.json")
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            print(f"[+] Backup created successfully")
            print(f"[+] Size: {backup_size_mb:.2f} MB")
            
            return metadata
        except Exception as e:
            print(f"[ERROR] Backup failed: {e}")
            return None
    
    def restore_backup(self, backup_name, restore_to=None):
        _check_name(backup_name)
        backup_path = os.path.join(self.backup_dir, f"{backup_name}.tar.gz")
        
        if not os.path.exists(backup_path):
            print(f"[ERROR] Backup not found: {backup_path}")
            return False
        
        if not restore_to:
            restore_to = os.path.join(self.backup_dir, f"restored_{backup_name}")
        
        print(f"[*] Restoring backup: {backup_name}")
        print(f"[*] Restore to: {restore_to}")
        
        try:
            os.makedirs(restore_to, exist_ok=True)
            
            with tarfile.open(backup_path, "r:gz") as tar:
                _safe_extract(tar, restore_to)
            
            print(f"[+] Backup restored successfully")
            return True
        except Exception as e:
            print(f"[ERROR] Restore failed: {e}")
            return False
    
    def list_backups(self):
        backups = []
        
        for filename in os.listdir(self.backup_dir):
            if filename.endswith('_metadata.json'):
                metadata_path = os.path.join(self.backup_dir, filename)
                try:
                    with open(metadata_path, 'r') as f:
                        metadata = json.load(f)
                        backups.append(metadata)
                except:
                    continue
        
        backups.sort(key=lambda x: x['timestamp'], reverse=True)
        return backups
    
    def delete_backup(self, backup_name):
        _check_name(backup_name)
        backup_path = os.path.join(self.backup_dir, f"{backup_name}.tar.gz")
        metadata_path = os.path.join(self.backup_dir, f"{backup_name}_metadata.json")
        
        try:
            if os.path.exists(backup_path):
                os.remove(backup_path)
            if os.path.exists(metadata_path):
                os.remove(metadata_path)
            
            print(f"[+] Backup deleted: {backup_name}")
            return True
        except Exception as e:
            print(f"[ERROR] Delete failed: {e}")
            return False
