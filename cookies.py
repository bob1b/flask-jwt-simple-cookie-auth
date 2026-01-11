import logging
from flask import Response

from . import tokens_utils
from .config import config

_logger = logging.getLogger(__name__)


def set_cookies(cookie_type: str, response: Response, encoded_token: str, max_age=None, domain=None):
    """
        Modify a Flask Response to set a cookie containing the access/refresh JWT. Also sets the corresponding CSRF
        cookies

        :param cookie_type:  "access" or "refresh"

        :param response:  A Flask Response object.

        :param encoded_token:  The encoded token to set in the cookies.

        :param max_age:  The max age of the cookie. If this is None, it will use the ``JWT_SESSION_COOKIE`` option (see
                         :ref:`Configuration Options`). Otherwise, it will use this as the cookies ``max-age`` and the
                         JWT_SESSION_COOKIE option will be ignored. Values should be the number of seconds (as an
                         integer).

        :param domain:  The domain of the cookie. If this is None, it will use the ``JWT_COOKIE_DOMAIN`` option (see
                        :ref:`Configuration Options`). Otherwise, it will use this as the cookies ``domain`` and the
                        JWT_COOKIE_DOMAIN option will be ignored.
    """
    def _set(response_object: Response):
        response_object.set_cookie(cookie_name, value=encoded_token, httponly=True, **opt)
        if config.csrf_protect:
            response_object.set_cookie(
                csrf_cookie_name,
                value=tokens_utils.get_csrf_token_from_encoded_token(encoded_token),
                httponly=True,
                **opt
            )

    method = 'set_cookies()'

    if cookie_type == 'refresh':
        cookie_name = config.refresh_cookie_name
        csrf_cookie_name = config.refresh_csrf_cookie_name
    else:
        cookie_name = config.access_cookie_name
        csrf_cookie_name = config.access_csrf_cookie_name

    opt = {
        'secure': config.cookie_secure,
        'path': config.access_cookie_path,
        'samesite': config.cookie_samesite,
        'domain': domain or config.cookie_domain,
        'max_age': max_age or config.cookie_max_age
    }

    if not isinstance(response, Response):
        raise TypeError(f'{method}: expected response to be a Flask Response object, got {type(resp)}')

    _set(response)

