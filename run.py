"""Development entry point for the VaultKeep web interface.
Binds to localhost only. Debug mode (which allows code execution through the
Werkzeug debugger) is off unless VAULTKEEP_DEBUG=1 is set explicitly."""

import os
from vaultkeep.web.app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("VAULTKEEP_DEBUG") == "1")
