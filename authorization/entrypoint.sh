#!/bin/sh
set -e

if [ ! -f jwt-private.pem ]; then
  echo "Generating RSA key pair..."
  openssl genrsa -out jwt-private.pem
  openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem
fi

if [ ! -f hs256/1234.key ]; then
  echo "Generating HS256 key..."
  mkdir -p hs256
  openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=' > hs256/1234.key
fi

exec /server
