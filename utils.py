import jwt
import logging
from typing import (Any, Optional)
from flask import (g, Response, Request, request)
from werkzeug.local import LocalProxy

from .config import config
from .internal_utils import get_jwt_manager
from .typing import (ExpiresDelta, Fresh)
from .tokens import _decode_jwt

# Proxy to access the current user
current_user: Any = LocalProxy(lambda: get_current_user())

_logger = logging.getLogger(__name__)


def get_jwt() -> dict:
    """
        In a protected endpoint, this will return the python dictionary which has the payload of the JWT that is
        accessing the endpoint. If no JWT is present due to ``jwt_sca(optional=True)``, an empty dictionary is
        returned.

        :return:
            The payload (claims) of the JWT in the current request
    """
    from .view_decorators import verify_jwt_in_request

    decoded_jwt = g.get("_jwt_extended_jwt", None)
    if decoded_jwt is None:
        verify_jwt_in_request(optional=True, no_exception_on_expired=True)
        decoded_jwt = g.get("_jwt_extended_jwt", None)

    if decoded_jwt is None:
        raise RuntimeError("You must call `@jwt_sca()` or `verify_jwt_in_request()` before using this method")
    return decoded_jwt


def get_jwt_header() -> dict:
    """
        In a protected endpoint, this will return the python dictionary which has the header of the JWT that is
        accessing the endpoint. If no JWT is present due to ``jwt_sca(optional=True)``, an empty dictionary is
        returned.

        :return:
            The headers of the JWT in the current request
    """
    from .view_decorators import verify_jwt_in_request

    decoded_header = g.get("_jwt_extended_jwt_header", None)
    if decoded_header is None:
        verify_jwt_in_request(optional=True, no_exception_on_expired=True)
        decoded_header = g.get("_jwt_extended_jwt", None)

    if decoded_header is None:
        raise RuntimeError("You must call `@jwt_sca()` or `verify_jwt_in_request()` before using this method")
    return decoded_header


def get_jwt_identity() -> Any:
    """
        In a protected endpoint, this will return the identity of the JWT that is accessing the endpoint. If no JWT is
        present due to ``jwt_sca(optional=True)``, ``None`` is returned.

        :return:
            The identity of the JWT in the current request
    """
    return get_jwt().get(config.identity_claim_key, None)


def get_current_user() -> Any:
    """
        In a protected endpoint, this will return the user object for the JWT that is accessing the endpoint.

        This is only usable if :meth:`~flask_jwt_extended.JWTManager.user_lookup_loader` is configured. If the user
        loader callback is not being used, this will raise an error.

        If no JWT is present due to ``jwt_sca(optional=True)``, ``None`` is returned.

        :return:
            The current user object for the JWT in the current request
    """

    get_jwt()  # Raise an error if not in a decorated context

    # tokens had expired at beginning of this request
    if hasattr(g, 'unset_tokens') and g.unset_tokens:
        _logger.info('current_user(): got g.unset_tokens, returning no-user')
        return None

    jwt_user_dict = g.get("_jwt_extended_jwt_user", None)
    if jwt_user_dict is None:
        raise RuntimeError("You must provide a `@jwt.user_lookup_loader` callback to use this method")
    return jwt_user_dict["loaded_user"]


def decode_token(encoded_token: str, csrf_value: Optional[str] = None, allow_expired: bool = False) -> dict:
    """
        Returns the decoded token (python dict) from an encoded JWT. This does all the checks to ensure that the decoded
        token is valid before returning it.

        This will not fire the user loader callbacks, save the token for access in protected endpoints, checked if a
        token is revoked, etc. This is purely used to ensure that a JWT is valid.

        :param encoded_token:
            The encoded JWT to decode.

        :param csrf_value:
            Expected CSRF double submit value (optional).

        :param allow_expired:
            If ``True``, do not raise an error if the JWT is expired.  Defaults to ``False``

        :return:
            Dictionary containing the payload of the JWT decoded JWT.
    """
    jwt_manager = get_jwt_manager()
    return jwt_manager.decode_jwt_from_config(encoded_token, csrf_value, allow_expired)


def set_current_user_from_token_string(access_token_string=False):
    try:
        # jwt_manager = get_jwt_manager()
        jwt_dict = _decode_jwt(encoded_token=access_token_string)
    except (NoAuthorizationError, ExpiredSignatureError) as e:
        if type(e) == NoAuthorizationError and not optional:
            raise
        if type(e) == ExpiredSignatureError and not no_exception_on_expired:
            raise
        g._jwt_extended_jwt = {}
        g._jwt_extended_jwt_header = {}
        g._jwt_extended_jwt_user = {"loaded_user": None}
        return None

    g._jwt_extended_jwt_user = _load_user(jwt_header, jwt_data)
    g._jwt_extended_jwt_header = jwt_header
    g._jwt_extended_jwt = jwt_data


def create_access_token(identity: Any, fresh: Fresh = False, expires_delta: Optional[ExpiresDelta] = None,
                        additional_claims=None, additional_headers=None):
    """
        Create a new access token.

        :param identity:
            The identity of this token. It can be any data that is json serializable. You can use
            :meth:`~flask_jwt_extended.JWTManager.user_identity_loader` to define a callback function to convert any
            object passed in into a json serializable format.

        :param fresh:
            If this token should be marked as fresh, and can thus access endpoints protected with
            ``@jwt_sca(fresh=True)``. Defaults to ``False``.

            This value can also be a ``datetime.timedelta``, which indicate how long this token will be considered
            fresh.

        :param expires_delta:
            A ``datetime.timedelta`` for how long this token should last before it expires. Set to False in order to
            disable expiration. If this is None, it will use the ``JWT_ACCESS_TOKEN_EXPIRES`` config value (see
            :ref:`Configuration Options`)

        :param additional_claims:
            Optional. A hash of claims to include in the access token.  These claims are merged into the default claims
            (exp, iat, etc.) and claims returned from the
            :meth:`~flask_jwt_extended.JWTManager.additional_claims_loader` callback. On conflict, these claims take
            precedence.

        :param additional_headers:
            Optional. A hash of headers to include in the access token. These headers are merged into the default
            headers (alg, typ) and headers returned from the
            :meth:`~flask_jwt_extended.JWTManager.additional_headers_loader` callback. On conflict, these headers take
            precedence.

        :return:
            An encoded access token
    """
    jwt_manager = get_jwt_manager()
    return jwt_manager.encode_jwt_from_config(
        claims=additional_claims,
        expires_delta=expires_delta,
        fresh=fresh,
        headers=additional_headers,
        identity=identity,
        token_type="access",
    )


def create_refresh_token(identity: Any, expires_delta: Optional[ExpiresDelta] = None, additional_claims=None,
                         additional_headers=None):
    """
        Create a new refresh token.

        :param identity:
            The identity of this token. It can be any data that is json serializable. You can use
            :meth:`~flask_jwt_extended.JWTManager.user_identity_loader` to define a callback function to convert any
            object passed in into a json serializable format.

        :param expires_delta:
            A ``datetime.timedelta`` for how long this token should last before it expires. Set to False in order to
            disable expiration. If this is None, it will use the ``JWT_REFRESH_TOKEN_EXPIRES`` config value (see
            :ref:`Configuration Options`)

        :param additional_claims:
            Optional. A hash of claims to include in the refresh token. These claims are merged into the default claims
            (exp, iat, etc) and claims returned from the :meth:`~flask_jwt_extended.JWTManager.additional_claims_loader`
            callback. On conflict, these claims take precedence.

        :param additional_headers:
            Optional. A hash of headers to include in the refresh token. These headers are merged into the default
            headers (alg, typ) and headers returned from the
            :meth:`~flask_jwt_extended.JWTManager.additional_headers_loader` callback. On conflict, these headers take
            precedence.

        :return:
            An encoded refresh token
    """
    jwt_manager = get_jwt_manager()
    return jwt_manager.encode_jwt_from_config(
        claims=additional_claims,
        expires_delta=expires_delta,
        fresh=False,
        headers=additional_headers,
        identity=identity,
        token_type="refresh",
    )


def get_unverified_jwt_headers(encoded_token: str) -> dict:
    """
        Returns the Headers of an encoded JWT without verifying the signature of the JWT.

        :param encoded_token:
            The encoded JWT to get the Header from.

        :return:
            JWT header parameters as python dict()
    """
    return jwt.get_unverified_header(encoded_token)


def get_jti(encoded_token: str) -> Optional[str]:
    """
        Returns the JTI (unique identifier) of an encoded JWT

        :param encoded_token:
            The encoded JWT to get the JTI from.

        :return:
            The JTI (unique identifier) of a JWT, if it is present.
    """
    return decode_token(encoded_token).get("jti")


def get_csrf_token(encoded_token: str) -> str:
    """
        Returns the CSRF double submit token from an encoded JWT.

        :param encoded_token:
            The encoded JWT

        :return:
            The CSRF double submit token (string)
    """
    token = decode_token(encoded_token, allow_expired=True)
    return token["csrf"]


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


def current_user_context_processor() -> Any:
    return {"current_user": get_current_user()}

