import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime

class RansomwareLogger:
    def __init__(self, name="RansomwareAudit", log_dir="logs"):
        self.name = name
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        if not self.logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_formatter = logging.Formatter(
                '%(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            
            file_handler = RotatingFileHandler(
                os.path.join(log_dir, 'ransomware_audit.log'),
                maxBytes=10*1024*1024,
                backupCount=5
            )
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            
            error_handler = RotatingFileHandler(
                os.path.join(log_dir, 'errors.log'),
                maxBytes=10*1024*1024,
                backupCount=5
            )
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(file_formatter)
            
            self.logger.addHandler(console_handler)
            self.logger.addHandler(file_handler)
            self.logger.addHandler(error_handler)
    
    def info(self, message):
        self.logger.info(message)
    
    def debug(self, message):
        self.logger.debug(message)
    
    def warning(self, message):
        self.logger.warning(message)
    
    def error(self, message):
        self.logger.error(message)
    
    def critical(self, message):
        self.logger.critical(message)
    
    def scan_start(self, path):
        self.info(f"Scan started: {path}")
    
    def scan_complete(self, path, files_scanned, threats_found):
        self.info(f"Scan complete: {path} | Files: {files_scanned} | Threats: {threats_found}")
    
    def threat_detected(self, filepath, risk_score, reason):
        self.warning(f"THREAT: {filepath} | Score: {risk_score} | Reason: {reason}")
    
    def quarantine_action(self, filepath, action):
        self.info(f"Quarantine {action}: {filepath}")
    
    def backup_created(self, backup_name, size_mb):
        self.info(f"Backup created: {backup_name} | Size: {size_mb} MB")

logger = RansomwareLogger()
