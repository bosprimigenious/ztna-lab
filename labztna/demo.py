"""Run one disposable end-to-end request through the local lab."""

from __future__ import annotations

import json

from .auth import totp_now
from .client import LabClient
from .stack import LabStack


def main() -> None:
    with LabStack() as stack:
        assert stack.control is not None and stack.gateway is not None
        client = LabClient(
            ca_file=str(stack.bundle.ca_cert),
            control_address=stack.control.address,
            gateway_address=stack.gateway.address,
            manifest_verifier=stack.manifest_signer.verifier(),
        )
        login = client.login(stack.username, stack.password, totp_now(stack.otp_secret))
        manifest = client.resources()
        client.heartbeat()
        status, body, status_line = client.fetch("/hello")
        print(
            json.dumps(
                {
                    "tls": "TLS 1.3 only",
                    "status": status_line,
                    "body": json.loads(body),
                    "virtual_ip": login.virtual_ip,
                    "fake_dns": manifest.get("dns", {}),
                }
            )
        )
        print(f"authenticated resource={login.resource}, token_ttl={login.expires_in}s")
        client.logout()


if __name__ == "__main__":
    main()
