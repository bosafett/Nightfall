from fastapi import Request

from nightfall.config import get_settings


def client_ip(request: Request) -> str:
    """Client address, honouring X-Forwarded-For only for the configured number of
    trusted proxies in front of the API (NIGHTFALL_FORWARDED_HOPS)."""
    hops = get_settings().forwarded_hops
    if hops > 0:
        chain = [
            p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()
        ]
        if len(chain) >= hops:
            return chain[-hops][:64]
    return request.client.host if request.client else "unknown"


def user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")[:512]
