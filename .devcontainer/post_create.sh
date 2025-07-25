#!/bin/bash
set -e

# tools
echo "source /usr/share/bash-completion/completions/git" >> ~/.bashrc

echo export PATH="$PATH:$(go env GOPATH)/bin" >> ~/.bashrc

openssl genrsa > authorization/jwt-private.pem
openssl rsa -in authorization/jwt-private.pem -pubout -out authorization/jwt-public.pem
