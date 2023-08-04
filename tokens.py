import jwt
import json
import uuid
import logging
import traceback

from json import JSONEncoder
from hmac import compare_digest
from jwt import ExpiredSignatureError
from flask import (request, g, current_app)
from datetime import (datetime, timedelta, timezone)
from typing import (Any, Iterable, Type, Union, Optional, Tuple)

from . import utils
from . import types
from . import cookies
from . import refresh
from . import jwt_user
from . import jwt_manager
from .config import config
from . import jwt_exceptions

_logger = logging.getLogger(__name__)


def process_and_handle_tokens(fresh: bool = False,
                              optional: bool = False,
                              verify_type: bool = True,
                              auto_refresh: bool = False,
                              skip_revocation_check: bool = False,
                              no_exception_on_expired: bool = False) -> Optional[Tuple[dict, dict]]:
    """
        :param optional:
            If ``True``, do not raise an error if no JWT is present in the request. Defaults to ``False``.

        :param no_exception_on_expired:
            If ``True``, do not raise an error if a JWT has expired. Defaults to ``False``.

        :param fresh:
            If ``True``, require a JWT marked as ``fresh`` in order to be verified. Defaults to ``False``.

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

        jwt_header example:    { "alg": "HS256", "typ": "JWT" }
    """
    if request.method in config.exempt_methods:
        return None

    try:
        # Check if the request even has cookies. get_tokens_from_cookies() checks "flask.g" and will use the refreshed
        # access token if there is one
        enc_access_token, enc_refresh_token, csrf_tokens = get_tokens_from_cookies()
        if not enc_access_token or not enc_refresh_token: # TODO - csrf
            return None

        jwt_header = jwt.get_unverified_header(enc_access_token)

        opt = {
            "fresh": fresh,
            "leeway": config.leeway,
            "jwt_header": jwt_header,  # unverified headers
            "csrf_tokens": csrf_tokens,
            "verify_type": verify_type,
            "issuer": config.decode_issuer,
            "audience": config.decode_audience,
            "enc_access_token": enc_access_token,
            "enc_refresh_token": enc_refresh_token,
            "algorithms": config.decode_algorithms,
            "skip_revocation_check": skip_revocation_check,
            "identity_claim_key": config.identity_claim_key,
            "verify_aud": config.decode_audience is not None,
            "no_exception_on_expired": no_exception_on_expired,
            "auto_refresh": auto_refresh if auto_refresh is not None else False,
            "validate_csrf_for_this_request": config.csrf_protect and request.method in config.csrf_request_methods
        }

        dec_access_token, dec_refresh_token = decode_and_validate_tokens(opt)

    # all exceptions relating to bad tokens should be caught here so that set_no_user() can be called
    except (jwt_exceptions.NoAuthorizationError, ExpiredSignatureError, jwt_exceptions.RevokedTokenError) as e:

        if type(e) == jwt_exceptions.NoAuthorizationError and not optional:
            _logger.error(f'{type(e)}: {e}')
            raise

        if type(e) == ExpiredSignatureError and not no_exception_on_expired:
            _logger.error(f'{type(e)}: {e}')
            raise
        jwt_user.set_no_user()
        return None

    except Exception as e:
        _logger.error(f'process_and_handle_tokens(): exception: {e}, {traceback.format_exc()}')
        return None

    # Save these at the very end so that they are only saved in the request context if the token is valid and all
    # callbacks succeed
    jwt_user.set_current_user(opt['jwt_header'], dec_access_token)

    return dec_access_token


def decode_token(encoded_token: str, no_exception=True) -> dict:
    try:
        token_dict = jwt.decode(encoded_token,
                                None,  # secret - None means to use the secret in the app config
                                issuer=config.decode_issuer,
                                audience=config.decode_audience,
                                algorithms=config.decode_algorithms,
                                options={"verify_signature": False})
        # _logger.info(f"decode_token(): {utils.shorten(encoded_token, 30)} -> {json.dumps(token_dict, indent=2)}")
        return token_dict

    except Exception as e:
        err = f'decode_token(): exception in jwt.decode({utils.shorten(encoded_token, 30)}): {e}'
        _logger.error(err)
        if not no_exception:
            raise


def decode_and_validate_tokens(opt: dict) -> Tuple[Union[dict, None], Union[dict, None]]:
    """
        Accepts dict of options, which includes "enc_access_token" and "enc_refresh_token" (from cookies). Performs
        validation on the tokens as they are decoded

        If validation and decoding was successful, a tuple of the access and refresh dicts is returned. Otherwise, a
        tuple (None, None) is returned
    """

    # decoded tokens (dicts)
    dec_access_token = None
    dec_refresh_token = None
    # csrf_tokens = opt['csrf_tokens'] # TODO - do we need to do validate csrf_tokens in here?

    # TODO - check if access or refresh token is missing from the tables
    # TODO - validate access and refresh tokens

    try:
        dec_access_token, dec_refresh_token = token_validation(opt)
        return dec_access_token, dec_refresh_token

    except ExpiredSignatureError as e:
        e.jwt_header = opt['jwt_header']
        if opt.get('auto_refresh'):
            refresh.refresh_expiring_jwts()

            # TODO - if the token is still expired or otherwise invalid, to what value will .jwt_data be set?
            print("$$$  auto-refreshed after ExpiredSignatureError: now rerunnign token validation")
            e.jwt_data = token_validation(opt)

        if not opt['no_exception_on_expired']:
            _logger.error(f'{type(e)}: {e}')
            raise
        return dec_access_token, dec_refresh_token

    except jwt_exceptions.NoAuthorizationError as e:
        if (type(e) == jwt_exceptions.NoAuthorizationError or type(e) == ExpiredSignatureError) \
           and not opt['no_exception_on_expired']:
            _logger.error(f'{type(e)}: {e}')
            raise
        jwt_user.set_no_user()
        return None, None



def token_validation(opt) -> [dict, dict]:
    """
        Validate a token string using JWT package decode():
          * Ensure there is an identity_claim and CSRF value in the decoded data
          * Ensures that the CSRF value in the token data matches what was passed in to the method # TODO
          * Ensures that the access and refresh tokens are found in their respective tables

        Throws exceptions when there is a validation issue with the tokens
    """
    if not opt['enc_access_token'] or not opt['enc_refresh_token']:
        return None, None

    # options = {"verify_aud": opt['verify_aud']} # verify audience   # TODO
    # if opt['allow_expired']:
        # options["verify_exp"] = False # verify expiration  # TODO

    # Verify the ext, iat, and nbf (not before) claims. This optionally verifies the expiration and audience claims
    # if enabled. Exceptions are raised for invalid conditions, e.g. token expiration
    dec_access_token = decode_token(opt['enc_access_token'])
    dec_refresh_token = decode_token(opt['enc_refresh_token'])

    if not dec_access_token:
        err = f"Missing or bad access JWT"
        _logger.error(err)
        raise jwt_exceptions.NoAuthorizationError(err)

    if not dec_refresh_token:
        err = f"Missing or bad refresh JWT"
        _logger.error(err)
        raise jwt_exceptions.NoAuthorizationError(err)

    user_id = dec_access_token.get(current_app.config.get('JWT_IDENTITY_CLAIM'))
    if not user_id:
        err = "No user ID in access token"
        _logger.error(err)
        raise jwt_exceptions.NoAuthorizationError(err)

    if not opt['skip_revocation_check']:
        verify_token_not_blocklisted(opt, user_id=user_id)

    # TODO - where are the jwt_headers verified??? unverified_headers -> jwt_headers

    # TODO - are these needed?
    if "type" not in dec_access_token:
        dec_access_token["type"] = "access"
    if "fresh" not in dec_access_token:
        dec_access_token["fresh"] = False
    if "jti" not in dec_access_token:
        dec_access_token["jti"] = None

    if opt['verify_type']:
        verify_token_type(dec_access_token, is_refresh=False)
        verify_token_type(dec_refresh_token, is_refresh=True)

    if opt['fresh'] and opt['jwt_header']:
        verify_token_is_fresh(opt['jwt_header'], dec_access_token)

    # check if either token has expired
    access_expires = token_dict_expires_in_seconds(dec_access_token)
    if access_expires <= 0:
        raise ExpiredSignatureError(f'Access token has expired {access_expires} seconds ago')
    refresh_expires = token_dict_expires_in_seconds(dec_refresh_token)
    if refresh_expires <= 0:
        raise ExpiredSignatureError(f'Refresh token has expired {refresh_expires} seconds ago')

    custom_verification_for_token(opt['jwt_header'], dec_access_token)

    # Make sure that any custom claims we expect in the token are present
    if opt['identity_claim_key'] not in dec_access_token:
        err = f"Missing claim: {opt['dentity_claim_key']}"
        _logger.error(err)
        raise jwt_exceptions.JWTDecodeError(err)

    if opt['csrf_tokens'] and "csrf" not in dec_access_token:
        err = "Missing claim: csrf"
        _logger.error(err)
        raise jwt_exceptions.JWTDecodeError(err)

    if opt['validate_csrf_for_this_request']:
        if (not opt['csrf_tokens'] or len(opt['csrf_tokens']) < 1) and "csrf" in dec_access_token:
            err = "csrf is in access token but value not passed to token_validation()"
            _logger.error(err)
            raise jwt_exceptions.JWTDecodeError(err)

        if opt['csrf_tokens'] and "csrf" in dec_access_token:
            c1 = dec_access_token["csrf"]
            c2 = opt['csrf_tokens'][0]
            if not c1:
                err = f"Falsy CSRF token value in access token"
                _logger.error(err)
                raise jwt_exceptions.CSRFError(err)
            if not c2:
                err = f"Falsy CSRF token value in cookies"
                _logger.error(err)
                raise jwt_exceptions.CSRFError(err)

            if not compare_digest(c1, c2):
                err = f"CSRF double submit tokens do not match: {utils.shorten(c1,30)} != {utils.shorten(c2,30)}"
                _logger.error(err)
                raise jwt_exceptions.CSRFError(err)

    return dec_access_token, dec_refresh_token


def encode_jwt(nbf: Optional[bool] = None,
               csrf: Optional[bool] = None,
               issuer: Optional[str] = None,
               secret: Optional[str] = None,
               identity: Optional[Any] = None,
               algorithm: Optional[str] = None,
               fresh: Optional[types.Fresh] = None,
               token_type: Optional[str] = 'access',
               claim_overrides: Optional[dict] = None,
               header_overrides: Optional[dict] = None,
               identity_claim_key: Optional[str] = None,
               audience: Union[str, Iterable[str]] = False,
               json_encoder: Optional[Type[JSONEncoder]] = None,
               expires_delta: Optional[types.ExpiresDelta] = None) -> str:
    method = 'encode_jwt()'
    jwt_man = jwt_manager.get_jwt_manager()
    now = datetime.now(timezone.utc)

    if nbf is None:
        nbf = config.encode_nbf

    if csrf is None:
        csrf = config.csrf_protect

    if algorithm is None:
        algorithm = config.algorithm

    if issuer is None:
        issuer = config.encode_issuer

    if audience is None:
        audience = config.encode_audience

    if json_encoder is None:
        json_encoder = config.json_encoder

    if identity_claim_key is None:
        identity_claim_key = config.identity_claim_key

    if isinstance(fresh, timedelta):
        fresh = datetime.timestamp(now + fresh)

    # TODO - this will need to be rewritten
    if not identity:
        identity = jwt_man.user_identity_callback(identity) # identity data would have to come from somewhere

    if secret is None:
        secret = jwt_man.encode_key_callback(identity)

    token_data = {
        "fresh": fresh,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "type": token_type,
        identity_claim_key: identity,
    }

    if nbf:
        token_data["nbf"] = now

    if issuer:
        token_data["iss"] = issuer

    if audience:
        token_data["aud"] = audience

    if csrf:
        token_data["csrf"] = str(uuid.uuid4())

    if expires_delta is None:
        if token_type == "access":
            expires_delta = config.access_expires
        else:
            expires_delta = config.refresh_expires

    if expires_delta:
        token_data["exp"] = now + expires_delta

    if claim_overrides:
        token_data.update(claim_overrides)

    try:
        token = jwt.encode(token_data, secret, algorithm, json_encoder=json_encoder, headers=header_overrides)
        return token
    except Exception as e:
        err = f'{method}: exception in jwt.encode({json.dumps(token_data)}): {e}'
        _logger.error(err)


def after_request(response):
    """ Set the new access token as a response cookie """
    method = 'after_request()'
    if hasattr(g, "new_access_token"):
        _logger.info(f"{method}: g.new_access_token = {utils.shorten(g.new_access_token, 40)} ***")
        cookies.set_access_cookies(response, g.new_access_token)

    if hasattr(g, "new_refresh_token"):
        _logger.info(f"{method}: g.new_refresh_token = {utils.shorten(g.new_refresh_token, 40)} ***")
        cookies.set_refresh_cookies(response, g.new_refresh_token)

    # Unset jwt cookies in the response (e.g. user logged out)
    if hasattr(g, "unset_tokens") and g.unset_tokens:
        _logger.info(f"{method}: g.unset tokens = {g.unset_tokens} *** ")
        cookies.unset_jwt_cookies(response)

    return response


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


def get_jwt(no_exception=True) -> dict:
    """
        This will return the python dict containing JWT payload of the client accessing the endpoint. If no JWT is
        present due to ``jwt_sca(optional=True)``, an empty dict is returned.
            :return:  The payload (claims) of the JWT in the current request
    """
    decoded_jwt = g.get("_jwt_extended_jwt", None)
    if decoded_jwt is None:
        process_and_handle_tokens(optional=True, no_exception_on_expired=True)
        decoded_jwt = g.get("_jwt_extended_jwt", None)

    if decoded_jwt is None:
        err = "get_jwt(): found no decoded_jwt"
        _logger.error(err)
        if not no_exception:
            raise RuntimeError(err)
    return decoded_jwt


def get_jwt_header(no_exception=True) -> dict:
    """
        In a protected endpoint, this will return the python dictionary which has the header of the JWT that is
        accessing the endpoint. If no JWT is present due to ``jwt_sca(optional=True)``, an empty dictionary is
        returned.
            :return:  The headers of the JWT in the current request, e.g.; {"alg": "HS256", "typ": "JWT"}
    """
    decoded_header = g.get("_jwt_extended_jwt_header", None)
    if decoded_header is None:
        process_and_handle_tokens(optional=True, no_exception_on_expired=True)
        decoded_header = g.get("_jwt_extended_jwt", None)

    if decoded_header is None:
        err = "get_jwt_header(): found no decoded_header info"
        _logger.error(err)
        if not no_exception:
            raise RuntimeError(err)

    return decoded_header


def get_jwt_identity() -> Any:
    """
        In a protected endpoint, this will return the identity of the JWT that is accessing the endpoint. If no JWT is
        present due to ``jwt_sca(optional=True)``, ``None`` is returned. Returns the identity of the JWT in the current
        request
    """
    decoded_jwt = get_jwt()
    if not decoded_jwt:
        return
    return decoded_jwt.get(config.identity_claim_key, None)


# TODO - rewrite this method
def get_csrf_token_from_encoded_token(encoded_token: str) -> str: # TODO
    """
        Returns the CSRF double submit token from an encoded JWT.
          :param encoded_token:  The encoded JWT
          :return:  The CSRF double submit token (string)
    """

    token = decode_token(encoded_token)
    return token["csrf"]


def find_token_object_by_string(user_id: int,
                                encrypted_token: str,
                                token_class: Any,
                                return_all: bool = False) -> Any:
    results = token_class.query.filter_by(token=encrypted_token, user_id=user_id)
    if return_all:
        return results.all()
    return results.one_or_none()


def token_dict_expires_in_seconds(dec_token):
    return int(dec_token["exp"] - datetime.timestamp(datetime.now(timezone.utc)))


def expires_in_seconds(token_obj: Any,
                       no_exception: bool = True,
                       use_refresh_expiration_delta: bool = False) -> Optional[int]:
    """
        token_obj: a Token model (ie. Sqlalchemy) object

        TODO - probably want to allow external modules to set this method somehow so it'll match its own token model.
               For example, .token might not be the correct field name for token data in every app's Token model
   """
    method = 'expires_in_seconds()'

    jwt_man = jwt_manager.get_jwt_manager()

    try:
        dec_access_token = jwt.decode(token_obj.token,
                                      secret=None, # TODO - jwt_man.encode_key_callback(identity),
                                      algorithms=config.decode_algorithms, options={"verify_signature": False})
    except Exception as e: # TODO - use correct exception name here and in token_has_expired()
        err = f'{method}: exception in jwt.decode(): {e}'
        _logger.error(err)
        if not no_exception:
            raise
        return

    expires_in = token_dict_expires_in_seconds(dec_access_token)

    # Use refresh token expiration for an access token. Used for determining if the access token is still refreshable
    access_token_class, _ = jwt_man.get_token_classes()
    if use_refresh_expiration_delta and type(token_obj) == access_token_class:
        # Adjust the expiration time from access delta to refresh delta
        expires_in = expires_in - config.access_expires.total_seconds() + config.refresh_expires.total_seconds()
    return expires_in


def access_token_has_expired(token_obj: Any,
                             fresh_required: bool = False, # TODO
                             use_refresh_expiration_delta: bool = False) -> bool:
    try:
        expires_in = expires_in_seconds(token_obj, use_refresh_expiration_delta=use_refresh_expiration_delta)
        return expires_in <= 0
    except ExpiredSignatureError as e:
        return True


def refresh_token_has_expired(token_obj: Any) -> bool:
    try:
        expires_in = expires_in_seconds(token_obj)
        return expires_in <= 0
    except ExpiredSignatureError as e:
        return True


def token_is_refreshable(token_obj: Any,) -> bool:
    return not access_token_has_expired(token_obj, use_refresh_expiration_delta=True)


def verify_token_type(decoded_token: dict, is_refresh: bool) -> None:
    t = decoded_token["type"]
    if not is_refresh and t == "refresh":
        err = f'verify_token_type(): expected access token but got type: "{t}"'
        _logger.error(err)
        raise jwt_exceptions.WrongTokenError(err)
    elif is_refresh and t != "refresh":
        err = f'verify_token_type(): expected refresh token but got type: "{t}"'
        _logger.error(err)
        raise jwt_exceptions.WrongTokenError(err)


def verify_token_not_blocklisted(opt: dict, user_id: Optional[int]) -> None:
    """
        Call the callback first, if there is one. Then check if the access and refresh tokens are present, for the
        user_id if given, in the AccessToken and RefreshToken tables. If not, then the tokens are considered to be
        blocklisted

        Raises a RevokedTokenError exception if either token is blocklisted. Otherwise, returns nothing
    """
    method = f'verify_token_not_blocklisted()'

    jwt_man = jwt_manager.get_jwt_manager()
    if 0 and jwt_man.token_in_blocklist_callback:
        if jwt_man.token_in_blocklist_callback(opt): # TODO - this method should be called if the user tries to use a
                                                     #        revoked token to access a protected endpoint
            _logger.error(f'{method}: token is blacklisted: {opt["jwt_header"]}, {opt.get("jwt_data", {})}')
            raise jwt_exceptions.RevokedTokenError(opt["jwt_header"], opt.get("jwt_data", {}))

    access_token_class, refresh_token_class = jwt_man.get_token_classes()
    enc_access_token = opt['enc_access_token']
    enc_refresh_token = opt['enc_refresh_token']

    # missing values for encoded access or refresh tokens?
    if not enc_access_token:
        _logger.error(f'{method}: missing enc_access_token, cannot determine if token is blocklisted. Assuming it is')
        raise jwt_exceptions.RevokedTokenError(opt["jwt_header"], opt.get("jwt_data", {}))
    if not enc_refresh_token:
        _logger.error(f'{method}: missing enc_refresh_token, cannot determine if token is blocklisted. Assuming it is')
        raise jwt_exceptions.RevokedTokenError(opt["jwt_header"], opt.get("jwt_data", {}))

    # access and refresh tokens not in tables?
    access_token_query = access_token_class.query.filter_by(token=enc_access_token)
    refresh_token_query = refresh_token_class.query.filter_by(token=enc_refresh_token)

    user_text = ''
    if user_id:
        access_token_query = access_token_query.filter_by(user_id=user_id)
        refresh_token_query = refresh_token_query.filter_by(user_id=user_id)
        user_text = f'for user #{user_id}'

    if not access_token_query.all():
        _logger.error(f'{method}: access token ({utils.shorten(enc_access_token, 30)}) {user_text} not found ' +
                      f'in table (i.e. blocklisted): {opt.get("jwt_data", {})}')
        raise jwt_exceptions.RevokedTokenError(opt["jwt_header"], opt.get("jwt_data", {}))

    # refresh token not in table?
    if not refresh_token_query.all():
        _logger.error(f'{method}: refresh token ({utils.shorten(enc_access_token, 30)}) {user_text} not found '+
                      f'in table (i.e. blocklisted): {opt.get("jwt_data", {})}')
        raise jwt_exceptions.RevokedTokenError(opt["jwt_header"], opt.get("jwt_data", {}))


def custom_verification_for_token(jwt_header: dict, jwt_data: dict) -> None:
    jwt_man = jwt_manager.get_jwt_manager()
    if not jwt_man.token_verification_callback(jwt_header, jwt_data):
        error_msg = "User claims verification failed"
        _logger.error(error_msg)
        raise jwt_exceptions.UserClaimsVerificationError(error_msg, jwt_header, jwt_data)


def create_access_token(identity: Any,
                        additional_claims=None,
                        additional_headers=None,
                        fresh: types.Fresh = False,
                        expires_delta: Optional[types.ExpiresDelta] = None):
    """
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

        :return:  An encoded access token
    """
    expires_delta = expires_delta or config.access_expires
    return encode_jwt(claim_overrides=additional_claims, expires_delta=expires_delta, fresh=fresh,
                      header_overrides=additional_headers, identity=identity, token_type="access")


def create_refresh_token(identity: Any,
                         additional_claims=None,
                         additional_headers=None,
                         expires_delta: Optional[types.ExpiresDelta] = None):
    """
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
            (exp, iat, etc.) and claims returned from the :meth:`~flask_jwt_extended.JWTManager.additional_claims_loader`
            callback. On conflict, these claims take precedence.

        :param additional_headers:
            Optional. A hash of headers to include in the refresh token. These headers are merged into the default
            headers (alg, typ) and headers returned from the
            :meth:`~flask_jwt_extended.JWTManager.additional_headers_loader` callback. On conflict, these headers take
            precedence.

        :return:  An encoded refresh token
    """
    expires_delta = expires_delta or config.refresh_expires
    return encode_jwt(claim_overrides=additional_claims, expires_delta=expires_delta,
                      header_overrides=additional_headers, identity=identity, token_type="refresh")


def verify_token_is_fresh(jwt_header: Union[dict, None], jwt_data: dict) -> None:
    fresh = jwt_data["fresh"]
    if isinstance(fresh, bool):
        if not fresh:
            err = "Fresh token required"
            _logger.error(err)
            raise jwt_exceptions.FreshTokenRequired(err, jwt_header, jwt_data)
    else:
        now = datetime.timestamp(datetime.now(timezone.utc))
        if fresh < now:
            err = "Fresh token required"
            _logger.error(err)
            raise jwt_exceptions.FreshTokenRequired(err, jwt_header, jwt_data)


def get_user_id_from_token(encoded_token: str = None, decoded_token_dict: dict = None) -> Optional[str]:
    return decode_token(encoded_token).get(config.identity_claim_key)
