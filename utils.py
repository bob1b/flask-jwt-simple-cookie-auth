import logging
from typing import Optional
from flask import (Response, Request, request)
from .config import config
from . import tokens

_logger = logging.getLogger(__name__)


def get_access_cookie_value(req: Request = None) -> dict or None:
    """ returns the value (encoded token) of the access cookie """
    if not req:
        req = request
    return req.cookies.get(config.access_cookie_name)


def get_refresh_cookie_value(req: Request = None) -> dict or None:
    """ returns the value (encoded token) of the refresh cookie """
    if not req:
        req = request
    return req.cookies.get(config.refresh_cookie_name)


def set_cookies(cookie_type: str, response: Response, encoded_token: str, max_age=None, domain=None) -> None:
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
    if cookie_type == 'refresh':
        cookie_name = config.refresh_cookie_name
        csrf_cookie_name = config.refresh_csrf_cookie_name
    else:
        cookie_name = config.access_cookie_name
        csrf_cookie_name = config.access_csrf_cookie_name

    opt = {
        'max_age': max_age or config.cookie_max_age,
        'secure': config.cookie_secure,
        'domain': domain or config.cookie_domain,
        'path': config.access_cookie_path,
        'samesite': config.cookie_samesite
    }

    response.set_cookie(cookie_name, value=encoded_token, httponly=True, **opt)

    if config.csrf_protect:
        response.set_cookie(csrf_cookie_name, value=tokens.get_csrf_token(encoded_token), httponly=False, **opt)


def set_access_cookies(response: Response, encoded_access_token: str, max_age=None, domain=None) -> None:
    set_cookies('access', response, encoded_access_token, max_age, domain)


def set_refresh_cookies(
        response: Response, encoded_refresh_token: str, max_age: Optional[int] = None, domain: Optional[str] = None
) -> None:
    set_cookies('refresh', response, encoded_refresh_token, max_age, domain)


def unset_jwt_cookies(response: Response, domain: Optional[str] = None) -> None:
    """
    Modify a Flask Response to delete the cookies containing access or refresh JWTs.  Also deletes the corresponding
    CSRF cookies if applicable.

    :param response:  A Flask Response object

    :param domain:  Overrides the cookie domain. Otherwise, ``config.cookie_domain`` will be used
    """
    unset_cookies('access', response, domain)
    unset_cookies('refresh', response, domain)


def unset_cookies(cookie_type: str, response: Response, domain: Optional[str] = None) -> None:
    """
    Modify a Flask Response to delete the cookie containing an access JWT. Also deletes the corresponding CSRF cookie
    if applicable.

    ::cookie_type:: 'access' or 'refresh'

    :param response:  A Flask Response object

    :param domain:  The domain of the cookie. If this is None, it will use the ``JWT_COOKIE_DOMAIN`` option (see
                    :ref:`Configuration Options`). Otherwise, it will use this as the cookies ``domain`` and the
                    JWT_COOKIE_DOMAIN option will be ignored.
    """
    if cookie_type == 'refresh':
        cookie_name = config.refresh_cookie_name
        csrf_cookie_name = config.refresh_csrf_cookie_name
    else:
        cookie_name = config.access_cookie_name
        csrf_cookie_name = config.access_csrf_cookie_name

    opt = {
        'expires': 0,
        'secure': config.cookie_secure,
        'domain': domain or config.cookie_domain,
        'path': config.access_cookie_path,
        'samesite': config.cookie_samesite
    }

    _logger.info('\nunsetting access cookies')
    response.set_cookie(cookie_name, value="", httponly=True, **opt)

    if config.csrf_protect:
        response.set_cookie(csrf_cookie_name, value="", httponly=False, **opt)


def shorten(value, max_len=None):
    length = len(value)
    if max_len is None:
        max_len = 30
    if length <= max_len or max_len < 5:
        return value
    first_part_len = -(-max_len - 3) // 2  # round up division using two minuses
    last_part_len = (max_len - 3) - first_part_len
    first_part = value[:first_part_len]
    last_part = value[-last_part_len:]
    return f"{first_part}...{last_part}"
