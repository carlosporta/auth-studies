from fastapi import FastAPI

from ecom.auth.routes import router as auth_router


def create_app():
    app = FastAPI()
    app.include_router(auth_router, prefix="/auth")

    # @app.on_event("startup")
    # async def startup():
    #     async_engine = create_async_engine(
    #         "sqlite+aiosqlite:///",
    #         connect_args={"check_same_thread": False},
    #         poolclass=StaticPool,
    #     )
    #     AsyncSessionMaker.configure(bind=async_engine)
    #     await create_tables(async_engine)

    return app
