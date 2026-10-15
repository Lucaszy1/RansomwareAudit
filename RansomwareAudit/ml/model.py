import hashlib
import hmac
import io
import os
import pickle
import json
import secrets
from datetime import datetime
import numpy as np

from RansomwareAudit.scanner.permissions import is_executable, is_world_writable

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("[WARNING] scikit-learn not installed. ML features disabled.")
    print("Install with: pip3 install scikit-learn")

def _age_days(file_data):
    """Days since modification. Accepts epoch seconds or an ISO timestamp."""
    mtime = file_data.get("mtime")
    if mtime is None:
        mtime = file_data.get("modified_time")
    try:
        if isinstance(mtime, str):
            mtime = datetime.fromisoformat(mtime).timestamp()
        if not mtime:
            return float("inf")
        return (datetime.now().timestamp() - float(mtime)) / 86400
    except (TypeError, ValueError):
        return float("inf")


def _key_path():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "ransomwareaudit", "model.key")


def _signing_key():
    """Secret used to sign saved models.

    Unpickling runs code, so a swapped .pkl is code execution. Every saved model
    gets an HMAC-SHA256 signature, and load_model() refuses anything that doesn't
    verify. The key lives outside the project folder (owner-only, 0600), or comes
    from RA_MODEL_KEY, so someone who can drop a .pkl next to the tool can't also
    forge its signature.
    """
    env = os.environ.get("RA_MODEL_KEY")
    if env:
        return env.encode()
    path = _key_path()
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32))
    with open(path, "rb") as f:
        return f.read()


def _sign(data):
    return hmac.new(_signing_key(), data, hashlib.sha256).hexdigest()


class RansomwareMLModel:
    def __init__(self, model_path="ransomware_ml_model.pkl", contamination=0.1):
        self.model_path = model_path
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        self.model = None
        self.feature_names = ['entropy', 'file_size', 'is_executable', 'is_hidden', 
                              'world_writable', 'recently_modified']
        self.training_history = []
        
        if SKLEARN_AVAILABLE:
            self.model = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100
            )
    
    def extract_features(self, file_data):
        """Six numeric features per file, matching the scanner's report fields."""
        perms = str(file_data.get("permissions", "000"))
        filename = file_data.get("file", "")
        size = file_data.get("size_bytes", file_data.get("size", 0)) or 0

        return [
            float(file_data.get("entropy", 0) or 0),
            float(np.log1p(size)),
            1.0 if is_executable(perms) else 0.0,
            1.0 if os.path.basename(filename).startswith(".") else 0.0,
            1.0 if is_world_writable(perms) else 0.0,
            1.0 if _age_days(file_data) < 7 else 0.0,
        ]

    def train(self, file_reports):
        if not SKLEARN_AVAILABLE:
            print("[ERROR] Cannot train: scikit-learn not installed")
            return False
        
        if len(file_reports) < 10:
            print(f"[WARNING] Need at least 10 files to train, got {len(file_reports)}")
            return False
        
        print(f"[*] Training ML model on {len(file_reports)} files...")
        
        X = []
        for file_data in file_reports:
            features = self.extract_features(file_data)
            X.append(features)
        
        X = np.array(X)
        
        X_scaled = self.scaler.fit_transform(X)
        
        self.model.fit(X_scaled)
        
        self.training_history.append({
            'timestamp': datetime.now().isoformat(),
            'num_samples': len(file_reports),
            'feature_names': self.feature_names
        })
        # Note: Isolation Forest is unsupervised. Each train() call refits from
        # scratch on the files given, it does not accumulate earlier data.
        
        print(f"[+] Model trained successfully on {len(X)} samples")
        return True
    
    def predict(self, file_data):
        if not SKLEARN_AVAILABLE or self.model is None:
            return 0, 0.5
        
        features = self.extract_features(file_data)
        X = np.array([features])
        X_scaled = self.scaler.transform(X)
        
        prediction = self.model.predict(X_scaled)[0]
        score = self.model.score_samples(X_scaled)[0]
        
        anomaly_score = -score
        
        is_anomaly = 1 if prediction == -1 else 0
        
        return is_anomaly, anomaly_score
    
    def predict_batch(self, file_reports):
        if not SKLEARN_AVAILABLE or self.model is None:
            return []
        
        results = []
        for file_data in file_reports:
            is_anomaly, score = self.predict(file_data)
            results.append({
                'file': file_data.get('file', 'unknown'),
                'is_anomaly': is_anomaly,
                'anomaly_score': float(score),
                'risk_level': 'HIGH' if is_anomaly else 'LOW'
            })
        
        return results
    
    def save_model(self):
        if not SKLEARN_AVAILABLE:
            return False
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'training_history': self.training_history
        }
        
        data = pickle.dumps(model_data)
        with open(self.model_path, 'wb') as f:
            f.write(data)
        with open(self.model_path + ".sig", 'w') as f:
            f.write(_sign(data))
        
        print(f"[+] Model saved to {self.model_path}")
        return True
    
    def load_model(self):
        if not SKLEARN_AVAILABLE:
            return False
        
        if not os.path.exists(self.model_path):
            print(f"[*] No saved model found at {self.model_path}")
            return False
        
        try:
            with open(self.model_path, 'rb') as f:
                data = f.read()
            try:
                with open(self.model_path + ".sig") as f:
                    sig = f.read().strip()
            except OSError:
                sig = ""
            if not hmac.compare_digest(sig, _sign(data)):
                print(f"[ERROR] Refusing to load {self.model_path}: signature missing or invalid. "
                      "Retrain the model on this machine.")
                return False
            model_data = pickle.load(io.BytesIO(data))
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self.training_history = model_data['training_history']
            
            print(f"[+] Model loaded from {self.model_path}")
            print(f"[*] Training history: {len(self.training_history)} sessions")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to load model: {e}")
            return False
    
    def get_model_info(self):
        if not SKLEARN_AVAILABLE:
            return {"available": False, "message": "scikit-learn not installed"}
        
        return {
            "available": True,
            "trained": self.model is not None,
            "feature_names": self.feature_names,
            "training_sessions": len(self.training_history),
            "model_path": self.model_path
        }
