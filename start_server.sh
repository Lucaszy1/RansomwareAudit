#!/bin/bash
# Start the local web dashboard (binds to 127.0.0.1 by default).
# The startup line prints a URL containing the one-time access token.
exec python3 -m RansomwareAudit.web.app
