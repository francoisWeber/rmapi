#!/bin/sh
# Simple entrypoint - ensure directories exist and run as app user
# Create directories if they don't exist (before volume mounts take effect)
mkdir -p /home/app/.config/rmapi /home/app/.cache/rmapi /home/app/downloads

# On Linux, mounted volumes preserve host ownership which can cause permission issues
# On macOS, Docker Desktop handles this more leniently, but on Linux we need to fix it
# Try to fix permissions if we're running as root (before switching to app user)
if [ "$(id -u)" = "0" ]; then
    APP_UID=$(id -u app 2>/dev/null || echo 1000)
    APP_GID=$(id -g app 2>/dev/null || echo 1000)
    
    # Fix ownership of mounted volumes (works on Linux, safe on macOS)
    # Use find to avoid errors if directories don't exist or are read-only
    for dir in /home/app/.config/rmapi /home/app/.cache/rmapi /home/app/downloads; do
        if [ -d "$dir" ]; then
            # Try to change ownership - this will fail silently on macOS if not needed
            # On Linux, this fixes permissions for mounted volumes
            chown -R $APP_UID:$APP_GID "$dir" 2>/dev/null || true
            # Ensure directories are writable
            chmod -R u+rwX "$dir" 2>/dev/null || true
        fi
    done
fi

exec su-exec app "$@"
