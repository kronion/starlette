import pytest

from starlette.applications import Starlette
from starlette.middleware.csrf import (
    COOKIE_NAME,
    HEADER_NAME,
    REASON_HEADER_INCORRECT,
    REASON_INCORRECT_LENGTH,
    REASON_INVALID_CHARACTERS,
    REASON_MISSING_COOKIE,
    REASON_MISSING_HEADER,
    SAFE_METHODS,
    CsrfMiddleware,
)
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route

TESTED_METHODS = {
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH",
}
UNSAFE_METHODS = TESTED_METHODS - set(SAFE_METHODS)


@pytest.fixture
def csrf_app():
    async def homepage(request):
        return PlainTextResponse("Homepage")

    async def simple_response(request):
        return Response("", status_code=200)

    routes = [
        Route("/", homepage),
        Route("/safe", simple_response, methods=SAFE_METHODS),
        Route("/unsafe", simple_response, methods=UNSAFE_METHODS),
    ]

    app = Starlette(routes=routes)
    app.add_middleware(CsrfMiddleware)

    return app


def test_initial_response_includes_cookie(csrf_app, test_client_factory):
    client = test_client_factory(csrf_app)
    assert COOKIE_NAME not in client.cookies

    response = client.get("/")
    assert COOKIE_NAME in response.cookies


def test_safe_methods_work_without_tokens(csrf_app, test_client_factory):
    client = test_client_factory(csrf_app)

    for method in SAFE_METHODS:
        response = client.request(method, "/safe")
        assert response.status_code == 200


def test_unsafe_methods_fail_without_header(csrf_app, test_client_factory):
    client = test_client_factory(csrf_app)

    # Make an initial request to receive a CSRF cookie
    response = client.get("/")

    for method in UNSAFE_METHODS:
        response = client.request(method, "/unsafe")
        assert response.status_code == 403
        assert response.text == REASON_MISSING_HEADER


def test_unsafe_methods_fail_without_cookie(csrf_app, test_client_factory):
    client = test_client_factory(csrf_app)

    for method in UNSAFE_METHODS:
        client.cookies.clear()  # Eliminate cookies returned in previous responses
        response = client.request(method, "/unsafe", headers={HEADER_NAME: "fake"})
        assert response.status_code == 403
        assert response.text == REASON_MISSING_COOKIE


def test_correct_header_succeeds(csrf_app, test_client_factory):
    client = test_client_factory(csrf_app)

    # Make an initial request to receive a CSRF cookie
    response = client.get("/")
    token = response.cookies[COOKIE_NAME]

    for method in UNSAFE_METHODS:
        response = client.request(method, "/unsafe", headers={HEADER_NAME: token})
        assert response.status_code == 200


def test_incorrect_header_length_fails(csrf_app, test_client_factory):
    client = test_client_factory(csrf_app)

    # Make an initial request to receive a CSRF cookie
    response = client.get("/")
    # Make a different value to submit with the wrong length
    incorrect_token = "x" * (len(response.cookies[COOKIE_NAME]) - 1)

    for method in UNSAFE_METHODS:
        response = client.request(
            method, "/unsafe", headers={HEADER_NAME: incorrect_token}
        )
        assert response.status_code == 403
        assert response.text == REASON_INCORRECT_LENGTH


def test_incorrect_header_charset_fails(csrf_app, test_client_factory):
    client = test_client_factory(csrf_app)

    # Make an initial request to receive a CSRF cookie
    response = client.get("/")
    # Make a different value to submit with non-alphanumeric characters
    incorrect_token = "*" * len(response.cookies[COOKIE_NAME])

    for method in UNSAFE_METHODS:
        response = client.request(
            method, "/unsafe", headers={HEADER_NAME: incorrect_token}
        )
        assert response.status_code == 403
        assert response.text == REASON_INVALID_CHARACTERS


def test_incorrect_header_fails(csrf_app, test_client_factory):
    client = test_client_factory(csrf_app)

    # Make an initial request to receive a CSRF cookie
    response = client.get("/")
    # Make a different value to submit with the correct length
    incorrect_token = "x" * len(response.cookies[COOKIE_NAME])

    for method in UNSAFE_METHODS:
        response = client.request(
            method, "/unsafe", headers={HEADER_NAME: incorrect_token}
        )
        assert response.status_code == 403
        assert response.text == REASON_HEADER_INCORRECT
