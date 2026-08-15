"""A resource server that charges for access, and settles with a Psy wallet.

This is the "earn" half of the loop. It is deliberately small, because the point
is that selling access needs almost nothing: answer 402 with what you accept,
then hand the caller's X-PAYMENT header to your own wallet's `x402_verify` and
serve the resource if it comes back valid.

Two properties worth noticing, both of which come from the wallet rather than
from this file:

  * The seller never runs a prover. Verification is a read against the indexer,
    so an ordinary web backend can take Psy payments.
  * The seller never trusts the header. `x402_verify` re-reads the amount and
    recipient from the chain, so a caller who inflates the figures in the
    payload is rejected even though the transaction is real.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable


class PaidResource:
    """One paywalled endpoint.

    verify(header) -> (ok: bool, detail: dict)
        Usually a call to the seller wallet's `x402_verify`.
    fulfil() -> str
        Produces the resource. Called ONLY after payment verifies, so anything
        expensive (including buying upstream data) belongs here.
    """

    def __init__(
        self,
        name: str,
        price_nano: int,
        pay_to: str,
        verify: Callable[[str], tuple[bool, dict]],
        fulfil: Callable[[], str],
        network: str = "psy-sepolia",
        port: int = 8410,
    ) -> None:
        self.name = name
        self.price_nano = price_nano
        self.pay_to = pay_to
        self.verify = verify
        self.fulfil = fulfil
        self.network = network
        self.port = port
        self.log: list[str] = []
        self._srv: HTTPServer | None = None

    # ── the 402 challenge ────────────────────────────────────────────────
    def challenge(self, path: str) -> bytes:
        return json.dumps({
            "x402Version": 1,
            "error": "payment required",
            "accepts": [{
                "scheme": "exact",
                "network": self.network,
                "maxAmountRequired": str(self.price_nano),
                "resource": path,
                "description": self.name,
                "payTo": self.pay_to,
                "asset": "PSY",
                "maxTimeoutSeconds": 300,
            }],
        }).encode()

    def start(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a):        # keep the transcript clean
                pass

            def _send(self, code: int, body: bytes, ctype="application/json", extra=None):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                header = self.headers.get("X-PAYMENT")
                if not header:
                    outer.log.append(f"402 · asked {outer.price_nano} nano for {self.path}")
                    self._send(402, outer.challenge(self.path))
                    return

                ok, detail = outer.verify(header)
                if not ok:
                    # A refusal is a normal outcome, not an incident: report why
                    # so the caller can fix it rather than blindly re-paying.
                    reason = detail.get("error", "payment did not verify")
                    outer.log.append(f"402 · refused: {reason}")
                    self._send(402, json.dumps({
                        "x402Version": 1, "error": reason,
                        "accepts": json.loads(outer.challenge(self.path))["accepts"],
                    }).encode())
                    return

                outer.log.append(
                    f"200 · accepted {detail.get('amountNano')} nano "
                    f"from Psy-{int(detail.get('payerUserId', 0)):08d}"
                )
                body = outer.fulfil().encode()
                self._send(200, body, "text/plain", {
                    "X-PAYMENT-RESPONSE": json.dumps({"success": True,
                                                      "txHash": detail.get("txHash")}),
                })

        self._srv = HTTPServer(("127.0.0.1", self.port), Handler)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def stop(self) -> None:
        if self._srv:
            self._srv.shutdown()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/resource"
