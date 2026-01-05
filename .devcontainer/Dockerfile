FROM --platform=$BUILDPLATFORM ghcr.io/dev-shimada/golang-1.25.3-trixie:latest AS vscode

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ENV LESSCHARSET utf-8

WORKDIR /workspace

RUN  <<EOF
apt-get update && apt-get install -y vim git unzip less bash-completion npm sqlite3
echo "source /usr/share/bash-completion/completions/git" >> ~/.bashrc
echo export PATH="$PATH:$(go env GOPATH)/bin" >> ~/.bashrc
go install -v golang.org/x/tools/gopls@latest
go install -v github.com/go-delve/delve/cmd/dlv@latest
go install -v github.com/cweill/gotests/gotests@latest
go install -v github.com/goreleaser/goreleaser/v2@latest
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin latest
npm i -g @anthropic-ai/claude-code
EOF

COPY . /workspace
