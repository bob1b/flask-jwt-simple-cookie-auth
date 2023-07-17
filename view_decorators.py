from functools import wraps
from flask import (current_app)
from typing import Any
from .tokens import (verify_jwt_in_request, after_request)


def jwt_sca(optional: bool = False, fresh: bool = False, refresh: bool = False, verify_type: bool = True,
            skip_revocation_check: bool = False) -> Any:
    """
        A decorator to protect a Flask endpoint with JSON Web Tokens.

        Any route decorated with this will require a valid JWT to be present in the request (unless optional=True, in
        which case no JWT is also valid) before the endpoint can be called.

        :param optional:
            If ``True``, allow the decorated endpoint to be accessed if no JWT is present in the request. Defaults to
            ``False``.

        :param fresh:
            If ``True``, require a JWT marked with ``fresh`` to be able to access this endpoint. Defaults to ``False``.

        :param refresh:
            If ``True``, requires a refresh JWT to access this endpoint. If ``False``, requires an access JWT to access
            this endpoint. Defaults to ``False``.

        :param verify_type:
            If ``True``, the token type (access or refresh) will be checked according to the ``refresh`` argument. If
            ``False``, type will not be checked and both access and refresh tokens will be accepted.

        :param skip_revocation_check:
            If ``True``, revocation status of the token will be *not* checked. If ``False``, revocation status of the
            token will be checked.
    """

    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):

            # token auto-refreshing and validation
            verify_jwt_in_request(optional, fresh, refresh, verify_type, skip_revocation_check)

            # run the controller
            response = current_app.ensure_sync(fn)(*args, **kwargs)

            # update any refreshed cookies in the response
            return after_request(response)
        return decorator

    return wrapper
