import logging

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.db_init import init_db
from app.routers import auth, files, groups, health, ui

app = FastAPI(title=settings.app_name)

class _AccessFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        args = getattr(record, "args", ())
        if len(args) >= 3:
            path = str(args[2])
            if path.startswith("/ui/activity"):
                return False
        return True


logging.getLogger("uvicorn.access").addFilter(_AccessFilter())

@app.on_event("startup")
def _startup():
    # Dev-friendly: keep schema in sync without needing Alembic yet.
    init_db()

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(files.router)
app.include_router(ui.router)
app.include_router(groups.router)
