import os
import stat


def get_permissions(file_path):
    """Octal permission string like '644', or '000' if unreadable."""
    try:
        return oct(os.stat(file_path).st_mode & 0o777)[-3:]
    except OSError:
        return "000"


def is_executable(perms):
    """True if any execute bit (owner/group/other) is set."""
    try:
        return int(perms, 8) & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) != 0
    except (TypeError, ValueError):
        return False


def is_world_writable(perms):
    try:
        return int(perms, 8) & stat.S_IWOTH != 0
    except (TypeError, ValueError):
        return False
