# Verification Record

Environment: Windows, isolated Python 3.12 virtual environment, OpenSSL 3.0.16,
`cryptography 50.0.1`, and `pytest 9.1.1`.

Commands run from this directory:

```powershell
..\..\work\ztna-venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider
..\..\work\ztna-venv\Scripts\python.exe -B -m labztna.demo
..\..\work\ztna-venv\Scripts\python.exe -m pip check
```

The demo was also run between read-only `Get-NetRoute` and
`Get-DnsClientServerAddress` snapshots.

Results:

- `33 passed in 23.30s`.
- End-to-end demo completed password + TOTP login, TLS 1.3, signed manifest
  verification, heartbeat, framed `TCP_OPEN/TCP_DATA/FIN`, HTTP 200, and logout.
- The synthetic L3 path accepted an authorized CIDR and rejected an outside route.
- TLS 1.2, TOTP reuse, malformed grants, bad device signatures, replay/gap frames,
  illegal stream transitions, truncated frames, and manifest tampering were rejected.
- Missing posture fields failed closed. A stolen bearer token could not refresh a
  session without the enrolled device private key.
- A multi-frame response larger than 128 KiB decoded successfully, while frame and
  total response bounds remained enforced.
- Both `0.0.0.0/0` and two `/1` routes covering all IPv4 were rejected by registry
  and client plan validation.
- Logout revoked subsequent gateway access. Reclaimed virtual IPs received a new
  lease generation.
- The dry-run network helper previewed/applied/rolled back a signed route/DNS plan;
  its `mutates_os` capability remains `False`.
- The audit endpoint required a separate admin secret, and tests confirmed that
  password, OTP, and bearer token values were absent from returned events.
- Non-loopback listener/resource targets and reused certificate directories were rejected.
- Control and gateway used different leaf certificate/private-key files under the
  same disposable lab CA.
- Isolated `pip check` returned `No broken requirements found`.
- The before/after network snapshot returned
  `RoutesUnchanged=true` and `DnsServersUnchanged=true`.

The workstation's global Python environment was checked separately and has
pre-existing dependency conflicts across unrelated packages. It was therefore
excluded from the project readiness result; the isolated environment above is
the recorded verification environment.

The tests do not claim production readiness. They do not prove a real TUN/VNIC,
Windows kernel isolation, formal protocol security, independent-process state,
HA, performance under load, or compatibility with any third-party VPN gateway.
No system route, DNS setting, service, driver, firewall rule, or proxy setting
was changed by the PoC.
