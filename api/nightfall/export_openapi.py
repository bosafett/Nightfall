"""Writes the OpenAPI schema used to generate the web client's types.

python -m nightfall.export_openapi > openapi.json
"""

import json
import sys

from nightfall.main import create_app

if __name__ == "__main__":
    json.dump(create_app(check_settings=False).openapi(), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
