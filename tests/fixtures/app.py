from collections.abc import Generator
from typing import Any, Tuple

from fastapi.testclient import TestClient
import pytest
from fastapi import FastAPI
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from main import app
from db.models import User


# from tests.client_with_cookies import CookieConfigurableTestClient as TestClient
# from tests.pg_db_setup import insert_data


@pytest.fixture(scope="function")
def test_app() -> Generator[FastAPI, Any, None]:
    """
    Create a fresh database on each test case.
    """
    # Base.metadata.create_all(engine)  # Create the tables.
    # _app = start_application()
    # yield _app
    # Base.metadata.drop_all(engine)

    yield app