import logging
from typing import Any
from functools import wraps
from flask import (g, current_app)

from . import utils
from . import tokens
from . import cookies
from .config import config


_logger = logging.getLogger(__name__)

# TODO - protected decorator

def jwt_sca(fresh: bool = False,
            optional: bool = True,
            verify_type: bool = True,
            skip_revocation_check: bool = False) -> Any:
    """
        A controller decorator used for setting the desired authorization behavior. Also, use this decorator if you will
        be using get_current_user()

        :param optional:  If ``True``, allow the decorated endpoint to be accessed if no JWT is present in the request

        :param fresh:  If ``True``, require a JWT marked with ``fresh`` to be able to access this endpoint

        :param verify_type:  If ``True``, the token type (access or refresh) will be checked according to the
                             ``refresh`` argument. If ``False``, type will not be checked and both access and refresh
                             tokens will be accepted.

        :param skip_revocation_check:  If ``True``, revocation status of the token will be *not* checked. If ``False``,
                                       revocation status of the token will be checked
    """

    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            # token auto-refreshing and validation
            tokens.process_and_handle_tokens(optional=optional, fresh=fresh, verify_type=verify_type,
                                      skip_revocation_check=skip_revocation_check,  no_exception_on_expired=True)

            # run the controller
            response = current_app.ensure_sync(fn)(*args, **kwargs)

            # update any refreshed cookies in the response
            response = tokens.after_request(response)

            if config.clear_g_after_decorated_request:
                utils.clear_g_data()

            return response

        return decorator

    return wrapper
