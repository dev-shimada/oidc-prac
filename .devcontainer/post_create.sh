#!/bin/bash
set -e

# tools
echo "source /usr/share/bash-completion/completions/git" >> ~/.bashrc

echo export PATH="$PATH:$(go env GOPATH)/bin" >> ~/.bashrc

openssl genrsa > authorization/jwt-private.pem
openssl rsa -in authorization/jwt-private.pem -pubout -out authorization/jwt-public.pem

openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=' | tee authorization/hs256/1234.key > client/hs256/1234.key 
