from typing import Any
from functools import wraps
from flask import current_app
from .tokens import (process_and_handle_tokens, after_request)

# TODO - protected decorator

def jwt_sca(fresh: bool = False,
            refresh: bool = False, # TODO - check this later, ignore for now
            optional: bool = True,
            verify_type: bool = True,
            skip_revocation_check: bool = False) -> Any:
    """
        A controller decorator used for setting the desired authorization behavior. Also, use this decorator if you will
        be using get_current_user()

        :param optional:  If ``True``, allow the decorated endpoint to be accessed if no JWT is present in the request

        :param fresh:  If ``True``, require a JWT marked with ``fresh`` to be able to access this endpoint

        :param refresh:  If ``True``, requires a refresh JWT to access this endpoint. If ``False``, requires an access
                         JWT to access this endpoint

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
            process_and_handle_tokens(optional=optional, fresh=fresh, refresh=refresh, verify_type=verify_type,
                                      skip_revocation_check=skip_revocation_check,  no_exception_on_expired=True)

            # run the controller
            response = current_app.ensure_sync(fn)(*args, **kwargs)

            # update any refreshed cookies in the response
            return after_request(response)
        return decorator

    return wrapper
