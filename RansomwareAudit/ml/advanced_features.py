import os
import math
from RansomwareAudit.scanner.entropy import calculate_entropy
from RansomwareAudit.scanner.permissions import get_permissions, is_executable, is_world_writable

def extract_advanced_features(filepath):
    features = {}
    
    try:
        features['entropy'] = calculate_entropy(filepath)
    except:
        features['entropy'] = 0
    
    try:
        size = os.path.getsize(filepath)
        features['file_size_log'] = math.log10(size + 1)
    except:
        features['file_size_log'] = 0
    
    try:
        perms = get_permissions(filepath)
        features['is_executable'] = 1 if is_executable(perms) else 0
        features['is_world_writable'] = 1 if is_world_writable(perms) else 0
        features['is_hidden'] = 1 if os.path.basename(filepath).startswith('.') else 0
    except:
        features['is_executable'] = 0
        features['is_world_writable'] = 0
        features['is_hidden'] = 0
    
    try:
        mtime = os.path.getmtime(filepath)
        import time
        age_days = (time.time() - mtime) / 86400
        features['recently_modified'] = 1 if age_days < 7 else 0
    except:
        features['recently_modified'] = 0
    
    try:
        ext = os.path.splitext(filepath)[1].lower()
        from RansomwareAudit.engine.risk_engine import RANSOM_EXTENSIONS as suspicious_exts
        features['suspicious_extension'] = 1 if ext in suspicious_exts else 0
    except:
        features['suspicious_extension'] = 0
    
    try:
        with open(filepath, 'rb') as f:
            header = f.read(4)
        features['has_pe_header'] = 1 if header[:2] == b'MZ' else 0
    except:
        features['has_pe_header'] = 0
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read(1024)
            printable = sum(1 for byte in data if 32 <= byte <= 126)
            features['strings_ratio'] = printable / len(data) if len(data) > 0 else 0
    except:
        features['strings_ratio'] = 0
    
    return features
