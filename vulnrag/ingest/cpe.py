def parse_cpe23(cpe: str) -> tuple[str | None, str | None]:
    """cpe:2.3:<part>:<vendor>:<product>:<version>:... -> (vendor, product)."""
    parts = cpe.split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return (None, None)
    vendor = parts[3] if parts[3] not in ("*", "-") else None
    product = parts[4] if parts[4] not in ("*", "-") else None
    return (vendor, product)
