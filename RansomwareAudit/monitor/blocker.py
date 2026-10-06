import os
import time
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from RansomwareAudit.scanner.entropy import calculate_entropy

"""EXPERIMENTAL: kill a process that writes many high-entropy files quickly.

Off by default: without --kill it only reports. Finding the writing process
by scanning open files with psutil is slow and racy (the file is often closed
before we look), so this is a prototype. Production tools get process
attribution from the OS (Endpoint Security on macOS, ETW/minifilters on
Windows, fanotify on Linux).
"""


class RansomwareBlocker(FileSystemEventHandler):
    def __init__(self, kill=False):
        self.kill = kill
        self.suspicious_processes = {}
        self.blocked_count = 0
        
    def on_modified(self, event):
        if event.is_directory:
            return
        
        filepath = event.src_path
        
        if '.git' in filepath or 'quarantine' in filepath:
            return
        
        try:
            entropy = calculate_entropy(filepath)
            
            if entropy > 7.8:
                process = self._get_modifying_process(filepath)
                
                if process:
                    proc_name = process.name()
                    
                    if proc_name not in self.suspicious_processes:
                        self.suspicious_processes[proc_name] = {
                            'pid': process.pid,
                            'count': 0,
                            'start': time.time()
                        }
                    
                    self.suspicious_processes[proc_name]['count'] += 1
                    
                    elapsed = time.time() - self.suspicious_processes[proc_name]['start']
                    
                    if self.suspicious_processes[proc_name]['count'] >= 10 and elapsed < 30:
                        if not self.kill:
                            print(f"[WOULD BLOCK] {proc_name} (PID {process.pid}), run with --kill to act")
                            return
                        self._kill_process(process)
                        self.blocked_count += 1
                        print(f"[BLOCKED] {proc_name} (PID: {process.pid}) - Encrypted {self.suspicious_processes[proc_name]['count']} files")
        except:
            pass
    
    def _get_modifying_process(self, filepath):
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    for item in proc.open_files():
                        if item.path == filepath:
                            return proc
                except:
                    continue
        except:
            pass
        return None
    
    def _kill_process(self, process):
        try:
            process.terminate()
            time.sleep(1)
            if process.is_running():
                process.kill()
        except:
            pass

def start_blocker(path, kill=False):
    handler = RansomwareBlocker(kill=kill)
    observer = Observer()
    observer.schedule(handler, path, recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Experimental process blocker")
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--kill", action="store_true", help="Actually terminate the process")
    a = ap.parse_args()
    start_blocker(a.path, kill=a.kill)
