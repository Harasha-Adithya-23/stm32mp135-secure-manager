#!/bin/sh

echo "=== Secure Manager Setup ==="

BASE_DIR="$(pwd)"

# Create directories if they don't exist

mkdir -p "$BASE_DIR/incoming"
mkdir -p "$BASE_DIR/approved"
mkdir -p "$BASE_DIR/rejected"

chmod 555 "$BASE_DIR"


# Incoming: writable

chmod 755 "$BASE_DIR/incoming"

# Approved/Rejection: not writable by normal users
chmod 555 "$BASE_DIR/approved"
chmod 555 "$BASE_DIR/rejected"

# Host executable (adjust name if needed)

if [ -f "$BASE_DIR/secure_manager_host" ]; then
chmod 555 "$BASE_DIR/secure_manager_host"
fi

echo ""
echo "Permissions configured:"
ls -ld "$BASE_DIR/incoming"
ls -ld "$BASE_DIR/approved"
ls -ld "$BASE_DIR/rejected"

echo ""
echo "Structure:"
echo "  incoming/  -> upload location"
echo "  approved/  -> Secure Manager output"
echo "  rejected/  -> Secure Manager output"

echo ""
echo "Setup complete."
