import os
from datetime import datetime


def get_metadata(file_path):
    try:
        st = os.stat(file_path)
        return {
            "size_bytes": st.st_size,
            "mtime": st.st_mtime,  # epoch seconds, used by the ML features
            "modified_time": datetime.fromtimestamp(st.st_mtime).isoformat(),
            "extension": os.path.splitext(file_path)[1].lower(),
        }
    except OSError:
        return {"size_bytes": 0, "mtime": 0, "modified_time": "unknown", "extension": ""}
