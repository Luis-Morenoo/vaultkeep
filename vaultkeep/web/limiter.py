"""Rate limiting configuration for the vaultkeep web interface"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Limits are tracked per client IP. In-memory storage is explicit: fine for a single
# local process, which is why the container runs one gunicorn worker.
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
