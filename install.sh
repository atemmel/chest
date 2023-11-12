#!/usr/bin/sh

set -e

go build ./cmd/chest
go build ./cmd/chest-cli

cp chest /usr/bin/
cp chest-cli /usr/bin/

cp etc/chest.service /etc/systemd/system/

mkdir -p /etc/chest

cp -r static /etc/chest/
cp -r templates /etc/chest/
