import logging
from flask import (g, Response, Request, request)
from werkzeug.local import LocalProxy
from .user import get_current_user
from .config import config
from typing import (Any, Optional)

# Proxy to access the current user
current_user: Any = LocalProxy(lambda: get_current_user())

_logger = logging.getLogger(__name__)


def get_access_cookie_value(req: Request = None) -> dict or None:
    """ TODO """
    if not req:
        req = request
    return req.cookies.get(config.access_cookie_name)


def get_refresh_cookie_value(req: Request = None) -> dict or None:
    """ TODO """
    if not req:
        req = request
    return req.cookies.get(config.refresh_cookie_name)


def set_access_cookies(response: Response, encoded_access_token: str, max_age=None, domain=None) -> None:
    """
        Modify a Flask Response to set a cookie containing the access JWT. Also sets the corresponding CSRF cookies if
        ``JWT_CSRF_IN_COOKIES`` is ``True`` (see :ref:`Configuration Options`)

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
    import json
    data = { 
        'name': config.access_cookie_name,
        'value': encoded_access_token,
        'max_age': max_age or config.cookie_max_age,
        'secure': config.cookie_secure,
        'domain': domain or config.cookie_domain,
        'path': config.access_cookie_path,
        'samesite': config.cookie_samesite
    }
    _logger.info(f'\naccess cookie: {json.dumps(data)}')

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

    if config.csrf_protect and config.csrf_in_cookies:
        response.set_cookie(
            config.access_csrf_cookie_name,
            value=get_csrf_token(encoded_access_token),
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
    Modify a Flask Response to set a cookie containing the refresh JWT.
    Also sets the corresponding CSRF cookies if ``JWT_CSRF_IN_COOKIES`` is ``True``
    (see :ref:`Configuration Options`)

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

    if config.csrf_protect and config.csrf_in_cookies:
        response.set_cookie(
            config.refresh_csrf_cookie_name,
            value=get_csrf_token(encoded_refresh_token),
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
        TODO
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

    if config.csrf_protect and config.csrf_in_cookies:
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

    if config.csrf_protect and config.csrf_in_cookies:
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
