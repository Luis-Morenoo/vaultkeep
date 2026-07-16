from dataclasses import dataclass, field
from typing import Optional, List
import json


@dataclass
class KDFParameters:
    """Argon2id key derivation parameters stored in the vault header .
    Persisted alongside the vault so the master key can always be'
    re-derieved correctly, even if defaults change in future versions."""

    algorithm: str = "argon2id"                # Which KDF algorithm to use - alwasys argon2id for us
    salt: bytes = field(default_factory=bytes) # 16 random bytes unique to this vault - makes every vaults key diffrent even with the same password
    time_cost: int = 3                         # how many iterations Argon2id runs — more = slower = harder to brute force
    memory_cost: int = 65536                   # RAM required per guess in KiB (65536 = 64 MB) — chokes GPU attacks
    parallelism: int = 4                       # number of parallel CPU lanes — matches most modern quad-core machines
    
@dataclass
class VaultHeader:
    """The header of the vault file, containing all the information needed 
    to derive the master key and decrypt the vault data."""

    magic: bytes = b"VKEP"                                 # A magic number to identify the file format and check for corruption - always "VKEP" for us
    version: int = 1                                       # The vault file format version - allows for future changes while maintaining backward compatibility
    kdf_params: KDFParameters = None                       # The parameters used for key derivation, stored in the header so the master key can be re-derived correctly even if defaults change in future versions
    cipher: str = "aes-256-gcm"                            # The encryption algorithm used for the vault data - always aes-256-gcm for us
    vault_id: bytes = field(default_factory=bytes)         # 16 random bytes unique to this vault - used in key derivation and as associated data for encryption
    wrapped_data_key: bytes = field(default_factory=bytes) # The vault's data key, encrypted with the master key derived from the user's password

    def __post_init__(self):                  # Ensure kdf_params is initialized to a default if not provided                    
        if self.kdf_params is None:
            self.kdf_params = KDFParameters()

@dataclass
class VaultEntry:
    """A single entry in the vault, representing a username/password pair for 
    a service, along with optional notes and tags."""

    # --- Required fields (no defaults - must be provided) ---
    item_id: bytes                                # 16 random bytes unique to this entry - used as the nonce for encryption and to identify the entry
    service: str                                  # The name of the service or account this entry is for (e.g. "Gmail", "Facebook") - used for display and searching
    username: str                                 # The username or email associated with this entry - used for display and searching
    password: str                                 # The password for this entry - stored encrypted in the vault data
    
    # --- Optional fields (have defaults - can be ommitted) ---
    notes: Optional[str] = None                   # Optional additional notes or information about this entry - stored encrypted in the vault data    
    tags: List[str] = field(default_factory=list) # Optional list of tags or categories for this entry (e.g. ["work", "social"]) - stored encrypted in the vault data   

@dataclass
class VaultFile:
    """The complete vault file, containing the header and the list of entries.
    The header is stored in plaintext at the beginning of the file, while the 
    entries are stored encrypted in the vault data following the header."""

    # --- Required fields (no defaults - must be provided) ---
    header: VaultHeader                                     # The vault header containing metadata and key derivation parameters
    
    # --- Optional fields (have defaults - can be ommitted) ---
    entries: List[VaultEntry] = field(default_factory=list) # The list of entries in the vault - stored encrypted in the vault data

@dataclass
class AuditLogEntry:
    """A single entry in the audit log, representing an operation performed on the vault,
    such as adding, updating, or deleting an entry. Each entry is chained to the previous 
    one via a SHA-256 hash, making tampering detectable. """

    timestamp: str  # ISO 8601 formatted timestamp of when the operation occurred - used for auditing and tracking changes
    operation: str  # The type of operation performed (e.g. "add", "update", "delete") - used for auditing and tracking changes
    item_id: str    # The unique identifier of the entry affected by the operation (e.g. the item_id of the entry added, updated, or deleted) - used for auditing and tracking changes
    success: bool   # Whether the operation was successful or not - used for auditing and tracking changes
    prior_hash: str # SHA-256 hash of the previous log entry — if any entry is modified or deleted, this chain breaks and tampering becomes detectable
    
    def to_json(self) -> str: # Serialize the audit log entry to a JSON string for storage in the audit log file

        return json.dumps({
            "timestamp": self.timestamp,
            "operation": self.operation,
            "item_id": self.item_id,
            "success": self.success,
            "prior_hash": self.prior_hash
        })
    
