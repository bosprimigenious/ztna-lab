# Security Policy

## Scope

This repository is a loopback-only ZTNA/VPN architecture lab. It is not an
aTrust client, does not access BUPT, and does not contain a production VPN
gateway or a privileged Windows network helper.

Do not use this project to bypass an access-control system or connect to a
network without its owner's written authorization.

## Reporting

For a reproducible security issue in this repository, open a private GitHub
security advisory when enabled, or contact the repository owner before making
details public. Do not include passwords, OTP seeds, private keys, bearer
tokens, or real network addresses in an issue.

Reports should include the affected commit, a minimal reproduction, expected
and observed behavior, and whether any host network state was changed.

## Current security boundary

The automated tests and demo cover the disposable local simulation only. They
do not establish production readiness, Windows kernel isolation, real TUN/IPsec
or WireGuard behavior, or compatibility with any third-party gateway.
