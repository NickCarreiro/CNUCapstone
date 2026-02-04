from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.db_init import init_db
from app.routers import auth, files, health, ui

app = FastAPI(title=settings.app_name)

@app.on_event("startup")
def _startup():
    # Dev-friendly: keep schema in sync without needing Alembic yet.
    init_db()

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(files.router)
app.include_router(ui.router)
