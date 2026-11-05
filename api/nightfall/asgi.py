"""ASGI entrypoint: uvicorn nightfall.asgi:app (also the Vercel service entrypoint)."""

from nightfall.serverless import apply_platform_env

apply_platform_env()  # no-op unless running on Vercel

from nightfall.main import create_app  # noqa: E402

app = create_app()
