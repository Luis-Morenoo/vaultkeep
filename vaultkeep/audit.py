""" Audit logging functionality """

import hashlib
import json
import datetime
import os
from .models import AuditLogEntry

def compute_hash(entry: AuditLogEntry) -> str:
    """Compute the SHA-256 hash of the audit log file."""
    
    #Get JSON string from entry.to_json()
    json_str = entry.to_json()

    # Encode to bytes
    # Return hashlib.sha246(...).hexdigest()
    return hashlib.sha256(json_str.encode("utf-8")).hexdigest()

def append_audit_log(path: str, operation: str, item_id: str, success: bool, prior_hash: str) -> str:
    """Compute the hash of the previous entry, appends it to the log file"""

    # Get current timestamp
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Create AuditLogEntry
    auditLog = AuditLogEntry(
        timestamp=ts,
        operation=operation,
        item_id=item_id,
        success=success,
        prior_hash=prior_hash
    )

    # Compute its hash with compute_hash()
    ch = compute_hash(auditLog)
 
    # Append JSON line to file with open(path, "a")
    with open(path, "a") as file:
        file.write(auditLog.to_json() + "\n")

    # Return the new hash
    return ch

def get_last_hash(path: str) -> str:
    """Get the hash of the last entry in the audit log file."""
    
    # Check if the audit log file exists, if not return "0" * 64
    if not os.path.exists(path):
        return "0" * 64

    with open(path, "r") as f:
        lines = f.readlines()

    if not lines:
        return "0" * 64
    
    # Parse last line and compute hash
    last_line = lines[-1].strip() 
    data = json.loads(last_line)
    entry = AuditLogEntry(
        timestamp=data["timestamp"],
        operation=data["operation"],
        item_id=data["item_id"],
        success=data["success"],
        prior_hash=data["prior_hash"]
    )
    return compute_hash(entry)


   