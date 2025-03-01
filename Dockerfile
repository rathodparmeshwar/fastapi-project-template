FROM python:3.12-slim-bookworm AS builder

RUN pip install poetry==1.8.3

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

WORKDIR /app

COPY ../pyproject.toml ../poetry.lock ./
RUN touch README.md

RUN poetry lock --no-update
RUN --mount=type=cache,target=$POETRY_CACHE_DIR poetry install --only main

FROM python:3.12-slim-bookworm AS runtime

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY . /app
COPY .env /app/.env

# Run migrations and collect static files
RUN python manage.py collectstatic --noinput
CMD ["sh", "-c", "uvicorn src.main:api_application --host 0.0.0.0 --port 8000"]
