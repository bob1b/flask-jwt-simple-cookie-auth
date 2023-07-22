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


def set_access_cookies(response: Response, encoded_access_token: str, max_age=None, domain=None) -> None:
    """
        Modify a Flask Response to set a cookie containing the access JWT. Also sets the corresponding CSRF cookies

        :param response:
            A Flask Response object.

        :param encoded_access_token:
            The encoded access token to set in the cookies.

        :param max_age:
            The max age of the cookie. If this is None, it will use the ``JWT_SESSION_COOKIE`` option (see
            :ref:`Configuration Options`). Otherwise, it will use this as the cookies ``max-age`` and the
            JWT_SESSION_COOKIE option will be ignored. Values should be the number of seconds (as an integer).

        :param domain:
            The domain of the cookie. If this is None, it will use the ``JWT_COOKIE_DOMAIN`` option (see
            :ref:`Configuration Options`). Otherwise, it will use this as the cookies ``domain`` and the
            JWT_COOKIE_DOMAIN option will be ignored.
    """

    data = { 
        'name': config.access_cookie_name,
        'value': encoded_access_token,
        'max_age': max_age or config.cookie_max_age,
        'secure': config.cookie_secure,
        'domain': domain or config.cookie_domain,
        'path': config.access_cookie_path,
        'samesite': config.cookie_samesite
    }
    # _logger.info(f'\naccess cookie: {json.dumps(data)}')

    response.set_cookie(
        config.access_cookie_name,
        value=encoded_access_token,
        max_age=max_age or config.cookie_max_age,
        secure=config.cookie_secure,
        httponly=True,
        domain=domain or config.cookie_domain,
        path=config.access_cookie_path,
        samesite=config.cookie_samesite,
    )

    if config.csrf_protect:
        response.set_cookie(
            config.access_csrf_cookie_name,
            value="TODO", # tokens.get_csrf_token(encoded_access_token),
            max_age=max_age or config.cookie_max_age,
            secure=config.cookie_secure,
            httponly=False,
            domain=domain or config.cookie_domain,
            path=config.access_csrf_cookie_path,
            samesite=config.cookie_samesite,
        )


def set_refresh_cookies(
        response: Response, encoded_refresh_token: str, max_age: Optional[int] = None, domain: Optional[str] = None
) -> None:
    """
    Modify a Flask Response to set a cookie containing the refresh JWT. Also sets the corresponding CSRF cookies

    :param response:
        A Flask Response object.

    :param encoded_refresh_token:
        The encoded refresh token to set in the cookies.

    :param max_age:
        The max age of the cookie. If this is None, it will use the
        ``JWT_SESSION_COOKIE`` option (see :ref:`Configuration Options`). Otherwise,
        it will use this as the cookies ``max-age`` and the JWT_SESSION_COOKIE option
        will be ignored. Values should be the number of seconds (as an integer).

    :param domain:
        The domain of the cookie. If this is None, it will use the
        ``JWT_COOKIE_DOMAIN`` option (see :ref:`Configuration Options`). Otherwise,
        it will use this as the cookies ``domain`` and the JWT_COOKIE_DOMAIN option
        will be ignored.
    """
    response.set_cookie(
        config.refresh_cookie_name,
        value=encoded_refresh_token,
        max_age=max_age or config.cookie_max_age,
        secure=config.cookie_secure,
        httponly=True,
        domain=domain or config.cookie_domain,
        path=config.refresh_cookie_path,
        samesite=config.cookie_samesite,
    )

    if config.csrf_protect:
        response.set_cookie(
            config.refresh_csrf_cookie_name,
            value="TODO", # tokens.get_csrf_token(encoded_refresh_token),
            max_age=max_age or config.cookie_max_age,
            secure=config.cookie_secure,
            httponly=False,
            domain=domain or config.cookie_domain,
            path=config.refresh_csrf_cookie_path,
            samesite=config.cookie_samesite,
        )


def unset_jwt_cookies(response: Response, domain: Optional[str] = None) -> None:
    """
    Modify a Flask Response to delete the cookies containing access or refresh
    JWTs.  Also deletes the corresponding CSRF cookies if applicable.

    :param response:
        A Flask Response object

    :param domain:
        Overrides the cookie domain. Otherwise, ``config.cookie_domain`` will be used
    """
    unset_access_cookies(response, domain)
    unset_refresh_cookies(response, domain)


def unset_access_cookies(response: Response, domain: Optional[str] = None) -> None:
    """
    Modify a Flask Response to delete the cookie containing an access JWT.
    Also deletes the corresponding CSRF cookie if applicable.

    :param response:
        A Flask Response object

    :param domain:
        The domain of the cookie. If this is None, it will use the
        ``JWT_COOKIE_DOMAIN`` option (see :ref:`Configuration Options`). Otherwise,
        it will use this as the cookies ``domain`` and the JWT_COOKIE_DOMAIN option
        will be ignored.
    """
    _logger.info('\nunsetting access cookies')
    response.set_cookie(
        config.access_cookie_name,
        value="",
        expires=0,
        secure=config.cookie_secure,
        httponly=True,
        domain=domain or config.cookie_domain,
        path=config.access_cookie_path,
        samesite=config.cookie_samesite,
    )

    if config.csrf_protect:
        response.set_cookie(
            config.access_csrf_cookie_name,
            value="",
            expires=0,
            secure=config.cookie_secure,
            httponly=False,
            domain=domain or config.cookie_domain,
            path=config.access_csrf_cookie_path,
            samesite=config.cookie_samesite,
        )


def unset_refresh_cookies(response: Response, domain: Optional[str] = None) -> None:
    """
        Modify a Flask Response to delete the cookie containing a refresh JWT. Also deletes the corresponding CSRF
        cookie if applicable.

        :param response:
            A Flask Response object

        :param domain:
            The domain of the cookie. If this is None, it will use the ``JWT_COOKIE_DOMAIN`` option
            (see :ref:`Configuration Options`). Otherwise, it will use this as the cookies ``domain`` and the
            JWT_COOKIE_DOMAIN option will be ignored.
    """
    response.set_cookie(
        config.refresh_cookie_name,
        value="",
        expires=0,
        secure=config.cookie_secure,
        httponly=True,
        domain=domain or config.cookie_domain,
        path=config.refresh_cookie_path,
        samesite=config.cookie_samesite,
    )

    if config.csrf_protect:
        response.set_cookie(
            config.refresh_csrf_cookie_name,
            value="",
            expires=0,
            secure=config.cookie_secure,
            httponly=False,
            domain=domain or config.cookie_domain,
            path=config.refresh_csrf_cookie_path,
            samesite=config.cookie_samesite,
        )


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
