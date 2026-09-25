"""Main FastAPI application."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from . import routes
from db.init import init_db

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


app = FastAPI(
    title=settings.app_name,
    description="Network Scanner API with OS fingerprinting and device classification",
    version="0.1.0"
)


@app.on_event("startup")
def on_startup():
    init_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes.router)

@app.get("/status", tags=["status"])
async def status():
    return {"status": "ok", "version": "0.1.0"}

@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(WEB_DIR / "index.html")

app.mount("/", StaticFiles(directory=WEB_DIR), name="web")
