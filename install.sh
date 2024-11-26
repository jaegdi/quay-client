#!/bin/bash

# Create configuration directories
mkdir -p ~/.config/qc
mkdir -p /etc/qc 2>/dev/null || true

# Create default config file
cat > ~/.config/qc/config.yaml << EOF
registry:
  url: https://quay.io
  secret_name: quay-admin
  namespace: scp-build
  organisation: ""
EOF

echo "Configuration file created at ~/.config/qc/config.yaml"
