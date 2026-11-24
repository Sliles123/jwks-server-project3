"""Start the JWKS server on http://127.0.0.1:8080.

Set NOT_MY_KEY in the environment first, then run:

    python main.py
"""

from __future__ import annotations

import logging
import sys

from werkzeug.serving import make_server

from jwks_server import create_app, prepare_keys
from jwks_server.config import ConfigError, Settings

logger = logging.getLogger("jwks_server")


def main() -> int:
    """Run the server until interrupted. Returns a process exit code."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings()

    try:
        app = create_app(settings, provision_keys=False)
    except ConfigError as exc:
        logger.error("%s", exc)
        return 1

    # Bind the port before generating keys. Requests that arrive while keys
    # are being prepared wait in the socket backlog instead of being refused.
    server = make_server(settings.host, settings.port, app, threaded=True)
    prepare_keys(app)
    logger.info("JWKS server listening on http://%s:%d", settings.host, settings.port)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
