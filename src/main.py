from fastapi import FastAPI
from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
        Manage your startup and shutdown tasks here.
    """
    pass


app = FastAPI(lifespan=lifespan)


@app.get("/")
async def root():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host='0.0.0.0', port=8000)
