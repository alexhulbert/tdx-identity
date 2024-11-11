#!/bin/bash

set -e

cd identity_svc

RUSTFLAGS='-C target-feature=+crt-static' cargo build --target x86_64-unknown-linux-gnu --release
sleep 1

BINARY_PATH="../target/x86_64-unknown-linux-gnu/release/identity-svc"
cat "$BINARY_PATH" | ssh -p 10022 -o StrictHostKeyChecking=no root@localhost 'cat > ~/tdx-identity-server && chmod +x ~/tdx-identity-server'

echo
ssh -t -p 10022 -o StrictHostKeyChecking=no root@localhost "
    killall tdx-identity-server 2>/dev/null || true
    ~/tdx-identity-server
"
