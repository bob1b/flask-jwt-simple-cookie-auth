import jwt
import uuid
from datetime import (datetime, timedelta, timezone)
from hmac import compare_digest
from json import JSONEncoder
from typing import (Any, Iterable, List, Type, Union)
from flask import current_app, request, g
from .config import config
from .utils import get_jwt_identity, get_jwt,set_access_cookies, set_refresh_cookies, decode_token, unset_jwt_cookies
from jwt import ExpiredSignatureError

from .exceptions import (CSRFError, JWTDecodeError)
from .typing import (ExpiresDelta, Fresh)


def expires_in_seconds(self, use_refresh_expiration_delta=False):
    token_data = decode_token(self.token, allow_expired=True)
    expires_in = token_data["exp"] - datetime.timestamp(datetime.now(timezone.utc))

    if use_refresh_expiration_delta and type(self) == AccessToken:
        expires_in = expires_in - timedelta(hours=1).total_seconds() + timedelta(days=30).total_seconds()
    return expires_in


def _encode_jwt(
    algorithm: str,
    audience: Union[str, Iterable[str]],
    claim_overrides: dict,
    csrf: bool,
    expires_delta: ExpiresDelta,
    fresh: Fresh,
    header_overrides: dict,
    identity: Any,
    identity_claim_key: str,
    issuer: str,
    json_encoder: Type[JSONEncoder],
    secret: str,
    token_type: str,
    nbf: bool,
) -> str:
    now = datetime.now(timezone.utc)

    if isinstance(fresh, timedelta):
        fresh = datetime.timestamp(now + fresh)

    token_data = {
        "fresh": fresh,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "type": token_type,
        identity_claim_key: identity,
    }

    if nbf:
        token_data["nbf"] = now

    if csrf:
        token_data["csrf"] = str(uuid.uuid4())

    if audience:
        token_data["aud"] = audience

    if issuer:
        token_data["iss"] = issuer

    if expires_delta:
        token_data["exp"] = now + expires_delta

    if claim_overrides:
        token_data.update(claim_overrides)

    return jwt.encode(token_data, secret, algorithm, json_encoder=json_encoder, headers=header_overrides)


def _decode_jwt(
    algorithms: List,
    allow_expired: bool,
    audience: Union[str, Iterable[str]],
    csrf_value: str,
    encoded_token: str,
    identity_claim_key: str,
    issuer: str,
    leeway: int,
    secret: str,
    verify_aud: bool,
) -> dict:
    options = {"verify_aud": verify_aud}
    if allow_expired:
        options["verify_exp"] = False

    # This call verifies the ext, iat, and nbf claims
    # This optionally verifies the exp and aud claims if enabled
    decoded_token = jwt.decode(
        encoded_token, secret, algorithms=algorithms, audience=audience, issuer=issuer, leeway=leeway, options=options
    )

    # Make sure that any custom claims we expect in the token are present
    if identity_claim_key not in decoded_token:
        raise JWTDecodeError("Missing claim: {}".format(identity_claim_key))

    if "type" not in decoded_token:
        decoded_token["type"] = "access"

    if "fresh" not in decoded_token:
        decoded_token["fresh"] = False

    if "jti" not in decoded_token:
        decoded_token["jti"] = None

    if csrf_value:
        if "csrf" not in decoded_token:
            raise JWTDecodeError("Missing claim: csrf")
        if not compare_digest(decoded_token["csrf"], csrf_value):
            raise CSRFError("CSRF double submit tokens do not match")

    return decoded_token


def access_token_has_expired():
    # TODO - probably will need to use jwt to check expiration, look for code raising ExpiredSignatureError
    pass


def refresh_expiring_jwts():
    """ Refresh access tokens for this request that will be expiring soon OR already have expired """
    method = f'refresh_expiring_jwts()'

    if hasattr(g.checked_expiring) and g.checked_expiring == True: # already checked for expiring JWTs
        return
    g.checked_expiring = True

    enc_access_token = request.cookies.get('access_token_cookie')
    enc_refresh_token = request.cookies.get('refresh_token_cookie')
    csrf_token = request.cookies.get('csrf_access_token')

    if jwt2.access_token_has_expired(): # TODO - add new method
        access_token_data = decode_token(enc_access_token, csrf_token, allow_expired=True)
        user_id = access_token_data.get(config.get('JWT_IDENTITY_CLAIM'))
    else:
        # token hasn't yet expired, get the info so that we can further check validity
        access_token_data = get_jwt()
        user_id = get_jwt_identity()

    # user is not logged in, nothing to do
    if not access_token_data:
        return

# TODO - check rest of below logic

    # We need a valid expired token (which is present in the Access Token table) in order to generate a new
    #   access token for this user session
    # Also, we need an unexpired refresh token or else we cannot grant a new access token to the user
    access_token = find_access_token_by_string(enc_access_token, user_id) # expired is ok
    refresh_token = find_refresh_token_by_string(enc_refresh_token, user_id)

    if not access_token:
        _logger.warning(f'{method}: no ACCESS TOKEN. Cannot determine expiration nor refresh, user_id = {user_id}\n {enc_access_token}')
        return

    # found unexpired access token - no need to refresh
    if access_token and access_token.expires_in_seconds() > 0:
        return

    # access token has expired
    expired_access_token = access_token
    access_token_expires_in_seconds = expired_access_token.expires_in_seconds()
    refresh_token_expires_in_seconds = refresh_token.expires_in_seconds()

    # catch instances when we cannot refresh the access token
    if not expired_access_token or not refresh_token or refresh_token_expires_in_seconds < 0:
        g.unset_tokens = True
        # TODO - update current_user
        if not expired_access_token:
            _logger.warning(f'{method}: missing ACCESS TOKEN. Cannot grant new token')
        elif not refresh_token:
            _logger.warning(f'{method}: missing REFRESH TOKEN. Cannot grant new token')
        else: # no refresh token expired
            _logger.warning(f'{method}: expired REFRESH TOKEN. {-1 * refresh_token_expires_in_seconds} seconds ' +
                            'since access token expiration. Cannot grant new token')
        return

    # refresh the access token
    user = User.query.get(user_id)
    _logger.info(f'{method}: user #{user.id} {-1 * access_token_expires_in_seconds} seconds since access ' +
                 f"'token expiration. Refreshing access token ...")

    access_token = user.create_access_token(request=request, replace=expired_access_token)
    g.unset_tokens = False
    g.new_access_token = access_token

    modified_cookies = request.cookies.copy()
    modified_cookies['access_token_cookie'] = access_token
    request.cookies = modified_cookies
    # TODO - update current_user - XXX this might be causing the CSRF issue?


def after_request(response):

    # Set the new access token as a response cookie
    if hasattr(g, "new_access_token"):
        _logger.info(f"g.new_access_token = {g.new_access_token} ***")
        set_access_cookies(response, g.new_access_token)

    if hasattr(g, "new_refresh_token"):
        _logger.info(f"g.new_refresh_token = {g.new_refresh_token} ***")
        set_refresh_cookies(response, g.new_refresh_token)

    # Unset jwt cookies in the response (e.g. user logged out)
    if hasattr(g, "unset_tokens") and g.unset_tokens:
        _logger.info(f" g.unset tokens = {g.unset_tokens} *** ")
        unset_jwt_cookies(response)

    return response


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


def verify_token_type(decoded_token: dict, refresh: bool) -> None:
    if not refresh and decoded_token["type"] == "refresh":
        raise WrongTokenError("Only non-refresh tokens are allowed")
    elif refresh and decoded_token["type"] != "refresh":
        raise WrongTokenError("Only refresh tokens are allowed")


def verify_token_not_blocklisted(jwt_header: dict, jwt_data: dict) -> None:
    jwt_manager = get_jwt_manager()
    if jwt_manager.token_in_blocklist_callback(jwt_header, jwt_data):
        raise RevokedTokenError(jwt_header, jwt_data)


def custom_verification_for_token(jwt_header: dict, jwt_data: dict) -> None:
    jwt_manager = get_jwt_manager()
    if not jwt_manager.token_verification_callback(jwt_header, jwt_data):
        error_msg = "User claims verification failed"
        raise UserClaimsVerificationError(error_msg, jwt_header, jwt_data)


def get_jwt() -> dict:
    """
        In a protected endpoint, this will return the python dictionary which has the payload of the JWT that is
        accessing the endpoint. If no JWT is present due to ``jwt_sca(optional=True)``, an empty dictionary is
        returned.

        :return:
            The payload (claims) of the JWT in the current request
    """

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
