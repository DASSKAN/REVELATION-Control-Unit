#!/usr/bin/env bash
# Self-signed certificate so phones can use GPS on the handheld page (browsers require HTTPS for GPS).
# Usage: bash tools/make_cert.sh 192.168.1.10     (the Control Unit laptop's Wi-Fi IP)
set -e
IP=${1:-192.168.1.10}
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/key.pem -out certs/cert.pem \
  -subj "/CN=revelation-cu" -addext "subjectAltName=IP:${IP},DNS:localhost"
echo "Created certs/cert.pem and certs/key.pem for ${IP}. Start with: python -m control_unit.server --https"
