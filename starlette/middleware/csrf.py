import re
import secrets
import string

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

# Assume that anything not defined as "safe" by RFC7231 needs protection
SAFE_METHODS = ("GET", "HEAD", "OPTIONS", "TRACE")

CSRF_SECRET_LENGTH = 32
CSRF_TOKEN_LENGTH = 2 * CSRF_SECRET_LENGTH

COOKIE_NAME = "CSRF-TOKEN"
HEADER_NAME = "X-CSRF-TOKEN"
COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # One year in seconds

VALID_CSRF_TOKEN_CHARS = string.ascii_letters + string.digits
invalid_token_chars_re = re.compile("[^a-zA-Z0-9]")


class CsrfError(Exception):
    pass


REASON_MISSING_COOKIE = "CSRF cookie missing"
REASON_MISSING_HEADER = "CSRF header missing"
REASON_INCORRECT_LENGTH = "CSRF token has incorrect length"
REASON_INVALID_CHARACTERS = "CSRF token has invalid characters"
REASON_HEADER_INCORRECT = "CSRF header has incorrect value"


class CsrfMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        cookie_name: str = COOKIE_NAME,
        header_name: str = HEADER_NAME,
        cookie_max_age: int = COOKIE_MAX_AGE,
    ):
        super().__init__(app)
        self.cookie_name = cookie_name
        self.header_name = header_name
        self.cookie_max_age = cookie_max_age

    def _get_new_csrf_string(self) -> str:
        """
        Return a securely generated random string.
        The bit length of the returned value can be calculated with the formula:
            log_2(len(allowed_chars)^length)
        For example, with default `allowed_chars` (26+26+10), this gives:
          * length: 12, bit length =~ 71 bits
          * length: 22, bit length =~ 131 bits
        """

        return "".join(
            secrets.choice(VALID_CSRF_TOKEN_CHARS) for i in range(CSRF_SECRET_LENGTH)
        )

    def _mask_cipher_secret(self, secret: str) -> str:
        """
        Given a secret (assumed to be a string of VALID_CSRF_TOKEN_CHARS), generate a
        token by adding a mask and applying it to the secret.
        """

        mask = self._get_new_csrf_string()
        chars = VALID_CSRF_TOKEN_CHARS
        pairs = zip((chars.index(x) for x in secret), (chars.index(x) for x in mask))
        cipher = "".join(chars[(x + y) % len(chars)] for x, y in pairs)
        return mask + cipher

    def _unmask_cipher_token(self, token: str) -> str:
        """
        Given a token (assumed to be a string of CSRF_ALLOWED_CHARS, of length
        CSRF_TOKEN_LENGTH, and that its first half is a mask), use it to decrypt
        the second half to produce the original secret.
        """

        mask = token[:CSRF_SECRET_LENGTH]
        token = token[CSRF_SECRET_LENGTH:]
        chars = VALID_CSRF_TOKEN_CHARS
        pairs = zip((chars.index(x) for x in token), (chars.index(x) for x in mask))
        return "".join(chars[x - y] for x, y in pairs)  # Note negative values are ok

    def _create_token(self) -> str:
        csrf_secret = self._get_new_csrf_string()
        csrf_token = self._mask_cipher_secret(csrf_secret)
        return csrf_token

    def _get_or_create_token(self, request: Request) -> str:
        try:
            token = request.cookies[self.cookie_name]
        except KeyError:
            token = self._create_token()

        return token

    def _validate_token_structure(self, token: str) -> None:
        # Confirm both tokens are of length CSRF_TOKEN_LENGTH, all VALID_CSRF_TOKEN_CHARS.
        if len(token) != CSRF_TOKEN_LENGTH:
            raise CsrfError(REASON_INCORRECT_LENGTH)

        if invalid_token_chars_re.search(token):
            raise CsrfError(REASON_INVALID_CHARACTERS)

    def _does_token_match(self, first_token: str, second_token: str) -> bool:
        self._validate_token_structure(first_token)
        self._validate_token_structure(second_token)

        return secrets.compare_digest(
            self._unmask_cipher_token(first_token),
            self._unmask_cipher_token(second_token),
        )

    def _check(self, request: Request) -> None:
        # Confirm origin and host headers
        # TODO

        # We use OWASPs Double Submit Cookie method of CSRF validation.
        # First half of the check: a cookie, which attackers can submit but cannot read.
        # Note that the cookie does not need to change throughout the user's session.
        try:
            cookie_token = request.cookies[self.cookie_name]
        except KeyError:
            raise CsrfError(REASON_MISSING_COOKIE)

        # Second half of the check: a secondary header containing the same token.
        # The client must read the cookie in order to include this header, which thwarts
        # cross-site attackers (they don't have access to cookies).
        try:
            header_token = request.headers[self.header_name]
        except KeyError:
            raise CsrfError(REASON_MISSING_HEADER)

        if not self._does_token_match(cookie_token, header_token):
            raise CsrfError(REASON_HEADER_INCORRECT)

    async def dispatch(self, request: Request, call_next):
        token = self._get_or_create_token(request)
        response = None

        # If not a safe method, check for valid token
        if request.method not in SAFE_METHODS:
            try:
                self._check(request)
            except CsrfError as e:
                response = Response(str(e), status_code=403)

        # CSRF passed, so proceed with request as normal
        if response is None:
            response = await call_next(request)

        # Include the CSRF cookie to use in future requests.
        # If the cookie was already present, its max age will be updated.
        response.set_cookie(
            key=self.cookie_name, value=token, max_age=self.cookie_max_age
        )

        return response
