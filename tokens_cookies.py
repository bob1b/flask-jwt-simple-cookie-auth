import logging
from typing import (Union, Optional, Tuple)
from flask import (request, Request, Response, g)

from . import cookies
from .config import config
from . import jwt_exceptions

_logger = logging.getLogger(__name__)


def get_tokens_from_cookies() -> Tuple[str, str, Union[Tuple[None, None], Tuple[dict, dict]]]:
    """
        Check "flask.g" first and use that if it is set. This means that tokens have been created (user logged in) or
        the access token was refreshed. Exceptions are raised for missing authorization or CSRF
    """

    if hasattr(g, 'unset_tokens') and g.unset_tokens:
        err = f'Missing cookie <all unset>'
        _logger.error(err)
        # TODO - optionally do not raise exception
        raise jwt_exceptions.NoAuthorizationError(err)

    encoded_acc_token = get_token_from_cookie('access')
    encoded_ref_token = get_token_from_cookie('refresh')
    csrf_tokens = get_token_from_cookie('csrf')

    return encoded_acc_token, encoded_ref_token, csrf_tokens


def get_token_from_cookie(which, no_exception=True) -> Union[str, Tuple[Union[str, None], Union[str, None]]]:
    if which == 'access':
        if hasattr(g, 'new_access_token'):
            encoded_acc_token = g.new_access_token
        else:
            encoded_acc_token = request.cookies.get(config.access_cookie_name)
            if not encoded_acc_token:
                if not no_exception:
                    err = f'Missing access cookie "{config.access_cookie_name}"'
                    _logger.error(err)
                    raise jwt_exceptions.NoAuthorizationError(err)
        return encoded_acc_token

    elif which == 'refresh':
        if hasattr(g, 'new_refresh_token'):
            encoded_ref_token = g.new_refresh_token
        else:
            encoded_ref_token = request.cookies.get(config.refresh_cookie_name)
            if not no_exception:
                err = f'Missing refresh cookie "{config.refresh_cookie_name}"'
                _logger.error(err)
                raise jwt_exceptions.NoAuthorizationError(err)
        return encoded_ref_token

    elif which == 'csrf':
        csrf_access_value = request.cookies.get(config.access_csrf_cookie_name)
        if not csrf_access_value:
            if not no_exception:
                err = "Missing CSRF access token"
                _logger.error(err)
                raise jwt_exceptions.CSRFError(err)

        csrf_refresh_value = request.cookies.get(config.refresh_csrf_cookie_name)
        if not csrf_refresh_value:
            if not no_exception:
                err = "Missing CSRF refresh token"
                _logger.error(err)
                raise jwt_exceptions.CSRFError(err)

        return csrf_access_value, csrf_refresh_value

    else:
        err = f'get_token_from_cookie("{which}"): unknown token type'
        _logger.error(err)
        raise jwt_exceptions.WrongTokenError(err)


def get_access_cookie_value(req: Request = None) -> Optional[dict]:
    """ returns the value (encoded token) of the access cookie """
    if not req:
        req = request
    return req.cookies.get(config.access_cookie_name)


def get_refresh_cookie_value(req: Request = None) -> Optional[dict]:
    """ returns the value (encoded token) of the refresh cookie """
    if not req:
        req = request
    return req.cookies.get(config.refresh_cookie_name)


def set_access_cookies(response: Response, encoded_access_token: str, max_age=None, domain=None) -> None:
    cookies.set_cookies('access', response, encoded_access_token, max_age, domain)


def set_refresh_cookies(response: Response,
                        encoded_refresh_token: str,
                        max_age: Optional[int] = None,
                        domain: Optional[str] = None) -> None:
    cookies.set_cookies('refresh', response, encoded_refresh_token, max_age, domain)


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
        Modify a Flask Response to delete the cookie containing an access or refresh JWT. Also deletes the corresponding
        CSRF cookie if applicable

        * cookie_type - 'access' or 'refresh'
        * param response - A Flask Response object
        * param domain - The domain of the cookie. If this is None, it will use the ``JWT_COOKIE_DOMAIN`` option (see
                         :ref:`Configuration Options`). Otherwise, it will use this as the cookies ``domain`` and the
                         JWT_COOKIE_DOMAIN option will be ignored.
    """
    method = 'unset_cookies()'
    if cookie_type == 'refresh':
        cookie_name = config.refresh_cookie_name
        csrf_cookie_name = config.refresh_csrf_cookie_name
    else:
        cookie_name = config.access_cookie_name
        csrf_cookie_name = config.access_csrf_cookie_name

    opt = {
        'expires': 0,
        'secure': config.cookie_secure,
        'path': config.access_cookie_path,
        'samesite': config.cookie_samesite,
        'domain': domain or config.cookie_domain,
    }

    _logger.info(f'{method}: unsetting {cookie_type} cookies')

    if not isinstance(response, Response):
        raise TypeError(f'{method}: expected response to be a Flask Response object, got {type(response)}')

    response.set_cookie(cookie_name, value="", httponly=True, **opt)
    if config.csrf_protect:
        response.set_cookie(csrf_cookie_name, value="", httponly=True, **opt)
