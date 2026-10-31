"""Request an x402 resource and parse its v2 payment challenge."""

from __future__ import annotations

import argparse
import base64
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def parse_payment_requirements(header_value: str) -> dict[str, Any]:
    """Decode the Base64 JSON PAYMENT-REQUIRED header and validate its shape."""
    try:
        decoded = base64.b64decode(header_value, validate=True)
        requirements = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("PAYMENT-REQUIRED is not valid Base64-encoded JSON") from error

    if not isinstance(requirements, dict) or requirements.get("x402Version") != 2:
        raise ValueError("Unsupported or malformed x402 payment requirements")
    resource = requirements.get("resource")
    accepts = requirements.get("accepts")
    if not isinstance(resource, dict) or not isinstance(accepts, list) or not accepts:
        raise ValueError("Payment requirements must include a resource and accepted options")
    for option in accepts:
        if not isinstance(option, dict) or not all(
            isinstance(option.get(key), str)
            for key in ("scheme", "network", "amount", "asset", "payTo")
        ):
            raise ValueError("Payment requirement option is missing required fields")
    return requirements


def request_challenge(url: str) -> dict[str, Any]:
    """Request a resource and return its x402 challenge, if payment is required."""
    request = Request(url, method="GET")
    try:
        with urlopen(request, timeout=5) as response:
            status, headers = response.status, response.headers
            response.read()
    except HTTPError as error:
        status, headers = error.code, error.headers
        error.close()
    except URLError as error:
        raise RuntimeError(f"Could not reach {url}: {error.reason}") from error

    if status != 402:
        raise RuntimeError(f"Expected HTTP 402, received HTTP {status}")
    header = headers.get("PAYMENT-REQUIRED")
    if not header:
        raise RuntimeError("HTTP 402 response did not include PAYMENT-REQUIRED")
    return parse_payment_requirements(header)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:8402/paid")
    args = parser.parse_args()

    try:
        requirements = request_challenge(args.url)
    except (RuntimeError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")

    print("Received HTTP 402 Payment Required")
    print(json.dumps(requirements, indent=2))
    print("\nParsed payment options:")
    for option in requirements["accepts"]:
        print(
            f"- {option['amount']} atomic units on {option['network']} "
            f"via {option['scheme']} to {option['payTo']}"
        )


if __name__ == "__main__":
    main()
