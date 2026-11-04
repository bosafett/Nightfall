"""ASGI entrypoint: uvicorn nightfall.asgi:app"""

from nightfall.main import create_app

app = create_app()
