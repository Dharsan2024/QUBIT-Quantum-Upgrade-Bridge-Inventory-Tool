from __future__ import annotations

import uvicorn

from .app import create_app
from .settings import Settings

app = create_app()


def run() -> None:
    settings = Settings()
    uvicorn.run(
        "qubit_api.main:app",
        host=settings.bind_host,
        port=settings.bind_port,
        reload=False,
    )


if __name__ == "__main__":
    run()
