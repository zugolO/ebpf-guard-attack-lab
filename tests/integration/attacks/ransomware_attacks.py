"""Ransomware simulation attack generators."""

import subprocess


def mass_encrypt_files(target_dir: str, file_count: int = 100) -> subprocess.Popen:
    """Create files then bulk-rename .txt → .encrypted — classic ransomware pattern."""
    code = f"""\
import os, pathlib
d = pathlib.Path('{target_dir}')
for i in range({file_count}):
    (d / f'doc_{{i}}.txt').write_bytes(os.urandom(1024))
for f in d.glob('*.txt'):
    f.rename(f.with_suffix('.encrypted'))
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def drop_ransom_note(path: str = "/tmp/HOW_TO_DECRYPT.txt") -> subprocess.Popen:
    """Write a ransom note to a well-known filename."""
    return subprocess.Popen(
        ["python3", "-c",
         f"open('{path}','w').write('Your files are encrypted. Pay 1 BTC.')"],
        stderr=subprocess.DEVNULL,
    )


def delete_backups(backup_dir: str = "/tmp/test_backups") -> subprocess.Popen:
    """Delete *.bak files before encryption — shadow-copy deletion step."""
    return subprocess.Popen(
        ["find", backup_dir, "-name", "*.bak", "-delete"],
        stderr=subprocess.DEVNULL,
    )


def enumerate_documents(path: str = "/home") -> subprocess.Popen:
    """Walk a directory tree and read 512 bytes from every file — pre-encryption scan."""
    code = f"""\
import os
for root, dirs, files in os.walk('{path}'):
    for f in files:
        try:
            open(os.path.join(root, f), 'rb').read(512)
        except Exception:
            pass
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def rsync_backup(src: str, dst: str) -> subprocess.Popen:
    """Negative: rsync produces many reads/writes but is a legitimate backup tool."""
    return subprocess.Popen(
        ["rsync", "-a", src, dst],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
