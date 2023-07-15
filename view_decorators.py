from datetime import (datetime, timezone)
from functools import wraps
from typing import (Any, Optional, Sequence, Tuple, Union)
from flask import (current_app, g, request)

from .config import config
from jwt import ExpiredSignatureError
from .tokens import refresh_expiring_jwts, after_request
from .exceptions import (CSRFError, FreshTokenRequired, NoAuthorizationError, UserLookupError)
from .internal_utils import (custom_verification_for_token, has_user_lookup, user_lookup, verify_token_not_blocklisted,
                             verify_token_type)
from .utils import (decode_token, get_unverified_jwt_headers)

LocationType = Union[str, Sequence, None]


def _verify_token_is_fresh(jwt_header: dict, jwt_data: dict) -> None:
    fresh = jwt_data["fresh"]
    if isinstance(fresh, bool):
        if not fresh:
            raise FreshTokenRequired("Fresh token required", jwt_header, jwt_data)
    else:
        now = datetime.timestamp(datetime.now(timezone.utc))
        if fresh < now:
            raise FreshTokenRequired("Fresh token required", jwt_header, jwt_data)


def verify_jwt_in_request(
    optional: bool = False,
    no_exception_on_expired: bool = False,
    fresh: bool = False,
    refresh: bool = False,
    verify_type: bool = True,
    skip_revocation_check: bool = False,
) -> Optional[Tuple[dict, dict]]:
    """
        Verify that a valid JWT is present in the request, unless ``optional=True`` in
        which case no JWT is also considered valid.

        :param optional:
            If ``True``, do not raise an error if no JWT is present in the request. Defaults to ``False``.

        :param no_exception_on_expired:
            If ``True``, do not raise an error if no JWT is expired. Defaults to ``False``.

        :param fresh:
            If ``True``, require a JWT marked as ``fresh`` in order to be verified. Defaults to ``False``.

        :param refresh:
            If ``True``, requires a refresh JWT to access this endpoint. If ``False``, requires an access JWT to access
            this endpoint. Defaults to ``False``

        :param verify_type:
            If ``True``, the token type (access or refresh) will be checked according to the ``refresh`` argument. If
            ``False``, type will not be checked and both access and refresh tokens will be accepted.

        :param skip_revocation_check:
            If ``True``, revocation status of the token will *not* be checked. If ``False``, revocation status of the
            token will be checked.

        :return:
            A tuple containing the jwt_header and the jwt_data if a valid JWT is present in the request. If
            ``optional=True`` and no JWT is in the request, ``None`` will be returned instead. Raise an exception if an
            invalid JWT is in the request.
    """
    if request.method in config.exempt_methods:
        return None

    try:
        jwt_data, jwt_header = _decode_jwt_from_request(
            fresh,
            refresh=refresh,
            verify_type=verify_type,
            skip_revocation_check=skip_revocation_check,
        )
        refresh_expiring_jwts()

    except (NoAuthorizationError, ExpiredSignatureError) as e:
        if type(e) == NoAuthorizationError and not optional:
            raise
        if type(e) == ExpiredSignatureError and not no_exception_on_expired:
            raise
        g._jwt_extended_jwt = {}
        g._jwt_extended_jwt_header = {}
        g._jwt_extended_jwt_user = {"loaded_user": None}
        return None

    # Save these at the very end so that they are only saved in the request
    # context if the token is valid and all callbacks succeed
    g._jwt_extended_jwt_user = _load_user(jwt_header, jwt_data)
    g._jwt_extended_jwt_header = jwt_header
    g._jwt_extended_jwt = jwt_data

    return jwt_header, jwt_data


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
            verify_jwt_in_request(optional, fresh, refresh, verify_type, skip_revocation_check)
            response = current_app.ensure_sync(fn)(*args, **kwargs)
            return after_request(response) # update any refreshed cookies
        return decorator

    return wrapper


def _load_user(jwt_header: dict, jwt_data: dict) -> Optional[dict]:
    if not has_user_lookup():
        return None

    identity = jwt_data[config.identity_claim_key]
    user = user_lookup(jwt_header, jwt_data)
    if user is None:
        error_msg = f"user_lookup returned None for {identity}"
        raise UserLookupError(error_msg, jwt_header, jwt_data)
    return {"loaded_user": user}


def _decode_jwt_from_cookies(refresh: bool) -> Tuple[str, Optional[str]]:
    # Check "flask.g" first and use that if it is set. This means that tokens have been created (user logged in) or the
    # access token was refreshed

    if hasattr(g, 'unset_tokens') and g.unset_tokens:
        raise NoAuthorizationError(f'Missing cookie <all unset>')

    if not refresh: # access token
        cookie_key = config.access_cookie_name
        if hasattr(g, 'new_access_token'):
            encoded_token = g.new_access_token
        else:
            encoded_token = request.cookies.get(cookie_key)
    else: # refresh token
        cookie_key = config.refresh_cookie_name
        if hasattr(g, 'new_refresh_token'):
            encoded_token = g.new_refresh_token
        else:
            encoded_token = request.cookies.get(cookie_key)

    if not encoded_token:
        raise NoAuthorizationError(f'Missing cookie "{cookie_key}"')

    if config.csrf_protect and request.method in config.csrf_request_methods:
        csrf_value = request.cookies.get(config.access_csrf_cookie_name)
        if not csrf_value:
            raise CSRFError("Missing CSRF token")
    else:
        csrf_value = None

    return encoded_token, csrf_value


def _decode_jwt_from_request(
        fresh: bool, refresh: bool = False, verify_type: bool = True, skip_revocation_check: bool = False
) -> Tuple[dict, dict]:

    errors = []
    decoded_token = None
    try:
        encoded_token, csrf_token = _decode_jwt_from_cookies(refresh) # this method checks flask.g before actual cookies
        decoded_token = decode_token(encoded_token, csrf_token)
        jwt_header = get_unverified_jwt_headers(encoded_token)
    except NoAuthorizationError as e:
        jwt_header = False
        errors.append(str(e))

    if not decoded_token:
        err_msg = f"Missing JWT in cookies ({'; '.join(errors)})"
        raise NoAuthorizationError(err_msg)

    # Additional verifications provided by this extension
    if verify_type:
        verify_token_type(decoded_token, refresh)

    if fresh:
        _verify_token_is_fresh(jwt_header, decoded_token)

    if not skip_revocation_check:
        verify_token_not_blocklisted(jwt_header, decoded_token)

    custom_verification_for_token(jwt_header, decoded_token)

    return decoded_token, jwt_header
