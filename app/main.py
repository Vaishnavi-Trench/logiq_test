import os
import sys

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
sys.path.append(root_dir)
import uvicorn
from fastapi import FastAPI, Request
from dotenv import load_dotenv

from app.api.routes import api_router
from app.core.config import settings
from app.models.schemas import StatusResponse
from pltfrm import MongoDBManager, AIManager, RedisManager, ElasticsearchManager
from pltfrm import PropX
from pltfrm import Logger2 as Logger
from pltfrm import PromptManager

# Initialize FastAPI app
app = FastAPI(title=settings.APP_NAME)

# Include routers
app.include_router(api_router, prefix="/api")


# Health check endpoint
@app.get("/status", response_model=StatusResponse, tags=["health"])
async def root_status():
    """Check if the API is running."""
    Logger.info("api: Root status check requested")
    return StatusResponse(status="Ok", message="Service is running")


async def initialize_services():
    """Initialize all required services before starting the FastAPI app."""
    # Initialize PropX with command line arguments
    try:
        PropX.initialize()
    except Exception as e:
        Logger.error(f"Failed to initialize PropX: {e}")
        raise

    # Ensure log directory exists before initializing logger
    log_dir = PropX.get_property("logger.dir")
    if log_dir and log_dir.startswith("./"):
        # Convert relative path to absolute
        abs_log_dir = os.path.abspath(os.path.join(root_dir, log_dir[2:]))
        # Check if parent directory exists, create if not
        parent_dir = os.path.dirname(abs_log_dir)
        if parent_dir:  # Only create if parent_dir is not empty
            os.makedirs(parent_dir, exist_ok=True)

    # Initialize Logger with PropX configuration
    try:
        Logger.initialize()  # Initialize Logger only once
    except Exception as e:
        # We can't log the error because Logger isn't initialized yet
        pass

    # Initialize other services
    try:
        RedisManager.initialize()  # Initialize Redis only once
    except Exception as e:
        Logger.error(f"Failed to initialize Redis: {e}")

    Logger.info("main: Loading settings from PropX")

    try:
        settings.initialize_from_propx()
        app.title = settings.APP_NAME
        Logger.info(f"main: Application name set to '{settings.APP_NAME}'")
    except Exception as e:
        Logger.error(f"Failed to initialize settings: {e}")

    try:
        Logger.info("main: Initializing MongoDB connection")
        MongoDBManager.initialize()
    except Exception as e:
        Logger.error(f"Failed to initialize MongoDB: {e}")

    try:
        Logger.info("main: Initializing OpenAI client")
        AIManager.initialize()
    except Exception as e:
        Logger.error(f"Failed to initialize OpenAI: {e}")

    try:
        Logger.info("main: Initializing prompt manager")
        PromptManager.initialize()
    except Exception as e:
        Logger.error(f"Failed to initialize OpenAI: {e}")

    try:
        Logger.info("main: Initializing Elasticsearch manager")
        ElasticsearchManager.initialize()
    except Exception as e:
        Logger.error(f"Failed to initialize ElasticSearch: {e}")

    try:
        load_dotenv()
        Logger.info("main: Environment variables loaded")
    except Exception as e:
        Logger.error(f"Failed to load environment variables: {e}")
        # Continue without env vars


# Add middleware to the FastAPI application


@app.middleware("http")
async def log_request_payload(request: Request, call_next):
    """Log request payload before FastAPI validation."""
    # Only log specific endpoints we're interested in
    if "/api/siem/sentinel/sentinel_generate_kql_query/" in request.url.path:
        try:
            # Clone the request body
            body = await request.body()
            request_body = body.decode()

            # Log the raw request payload
            Logger.info(
                f"RAW REQUEST PAYLOAD (before validation) for {request.url.path}: {request_body}"
            )

            # Create a new request with the same body
            # Recreate the request body stream
            async def receive():
                return {"type": "http.request", "body": body}

            request._receive = receive
        except Exception as e:
            Logger.error(f"Failed to log request payload: {str(e)}")

    # Continue with the request
    response = await call_next(request)

    # If we got a 422 error, log it
    if response.status_code == 422 and "/api/siem/sentinel/" in request.url.path:
        Logger.error(f"Validation error (422) for {request.url.path}")

    return response


if __name__ == "__main__":
    # Run initialization
    import asyncio

    asyncio.run(initialize_services())

    # Get worker count with a fallback
    num_workers = PropX.get_property("module.max.workers") or 1

    Logger.info(f"main: Starting FastAPI with {num_workers} workers")

    # Start FastAPI server
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        workers=int(num_workers) if isinstance(num_workers, str) else num_workers,
        log_level="info",
    )
