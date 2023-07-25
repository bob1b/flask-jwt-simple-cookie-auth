import logging
from typing import Any
from functools import wraps
from flask import (g, current_app)
from . import cookies
from .tokens import (process_and_handle_tokens, after_request)

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
            _logger.info(f'** start access cookie: {cookies.get_access_cookie_value()}')

            # token auto-refreshing and validation
            process_and_handle_tokens(optional=optional, fresh=fresh, verify_type=verify_type,
                                      skip_revocation_check=skip_revocation_check,  no_exception_on_expired=True)

            # run the controller
            response = current_app.ensure_sync(fn)(*args, **kwargs)

            # update any refreshed cookies in the response
            _logger.info(f'** just before after_request: {cookies.get_access_cookie_value()}')
            _logger.info(f'** g = {g.__dict__}')
            response = after_request(response)

            # this should not be needed to prevent persistence of "g" data across requests
            for attr_name in ['_jwt_extended_jwt_user', '_jwt_extended_jwt_header', '_jwt_extended_jwt',
                              'new_access_token', 'new_refresh_token', 'unset_tokens']:
                g.pop(attr_name, None)

            return response

        return decorator

    return wrapper
