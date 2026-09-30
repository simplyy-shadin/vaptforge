from fastapi import FastAPI

from vaptforge import __version__

app = FastAPI(
    title="VAPTForge API",
    version=__version__,
    description="API surface for an authorized vulnerability assessment workflow.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
