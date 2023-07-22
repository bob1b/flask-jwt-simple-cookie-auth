import jwt
import json
import uuid
import logging
from json import JSONEncoder
from flask import (request, g)
from hmac import compare_digest
from jwt import ExpiredSignatureError
from datetime import (datetime, timedelta, timezone)
from typing import (Any, Iterable, List, Type, Union, Optional, Tuple)

from . import user
from . import utils
from . import typing
from . import exceptions
from . import jwt_manager
from .config import config


_logger = logging.getLogger(__name__)


def process_and_handle_tokens(fresh: bool = False,
                              optional: bool = False,
                              verify_type: bool = True,
                              skip_revocation_check: bool = False,
                              no_exception_on_expired: bool = False) -> Optional[Tuple[dict, dict]]:
    """
        :param optional:
            If ``True``, do not raise an error if no JWT is present in the request. Defaults to ``False``.

        :param no_exception_on_expired:
            If ``True``, do not raise an error if no JWT is expired. Defaults to ``False``.

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
    """
    if request.method in config.exempt_methods:
        return None

    try:
        encoded_token, refresh_token, csrf_token = get_tokens_from_cookies()  # this method checks "flask.g" before cookies
        unverified_headers = jwt.get_unverified_header(encoded_token)

        print(f'\nencoded token = {utils.shorten(encoded_token, 30)}')
        print(f'refresh token = {utils.shorten(refresh_token, 30)}')
        print("unverified_headers = ", unverified_headers)

        dec_access_token, dec_refresh_token, jwt_header = decode_and_validate_tokens(
            encoded_token,  refresh_token, unverified_headers, csrf_token=csrf_token, fresh=fresh,
            verify_type=verify_type, skip_revocation_check=skip_revocation_check
        )

    # catch
    except (exceptions.NoAuthorizationError, ExpiredSignatureError) as e:

        if type(e) == exceptions.NoAuthorizationError and not optional:
            _logger.error(f'{type(e)}: {e}')
            raise
        if type(e) == ExpiredSignatureError and not no_exception_on_expired:
            _logger.error(f'{type(e)}: {e}')
            raise
        user.set_no_user()
        return None

    # Save these at the very end so that they are only saved in the request context if the token is valid and all
    # callbacks succeed
    user.set_current_user(jwt_header, jwt_data)

    return jwt_header, jwt_data


def decode_token(encoded_token: str):
    token_dict = jwt.decode(encoded_token,
                            None,  # secret
                            issuer=config.decode_issuer,
                            audience=config.decode_audience,
                            algorithms=config.decode_algorithms,
                            options={"verify_signature": False})
    print(f"decode_token: {utils.shorten(encoded_token, 30)} -> {json.dumps(token_dict, indent=2)}")
    return token_dict


def decode_and_validate_tokens(
        enc_access_token: str,
        enc_refresh_token: str,
        unverified_headers: Any,
        fresh: bool = False,
        verify_type: bool = True,
        auto_refresh: bool = True,
        allow_expired: bool = False,
        csrf_token: Optional[str] = None,
        skip_revocation_check: bool = False,
) -> Tuple[Union[dict, None], Union[dict, None], Union[dict, None]]:

    # """ TODO
    #     Decode and validate access and refresh token strings
    #
    #     Returns the decoded token (python dict) from an encoded JWT. This does all the checks to ensure that the decoded
    #     token is valid before returning it.
    #
    #     This will not fire the user loader callbacks, save the token for access in protected endpoints, check if a
    #     token is revoked, etc. This is purely used to ensure that a JWT is valid.
    #
    #         :param encoded_token:  The encoded JWT to decode.
    #         :param encoded_token:  The encoded JWT to decode.
    #         :param csrf_value:  Expected CSRF double submit value (optional).
    #         :param auto_refresh:  if a token has expired, attempt to refresh (regenerate and save) it using the refresh
    #                               token
    #         :param allow_expired:  If ``True``, do not raise an error if the JWT is expired. Use this when just checking
    #                                the expiration time, i.e. .expires_in_seconds()
    #         :return:  Dictionary containing the payload of the JWT decoded JWT.
    # """
    errors = []
    dec_access_token = None
    dec_refresh_token = None
    opt = {
        "fresh": fresh,
        "leeway": config.leeway,
        "csrf_value": csrf_token,
        "verify_type": verify_type,
        "allow_expired": allow_expired,
        "issuer": config.decode_issuer,
        "audience": config.decode_audience,
        "enc_access_token": enc_access_token,
        "enc_refresh_token": enc_refresh_token,
        "algorithms": config.decode_algorithms,
        "skip_revocation_check": skip_revocation_check,
        "identity_claim_key": config.identity_claim_key,
        "verify_aud": config.decode_audience is not None,
    }

    jwt_header = None
    jwt_man = jwt_manager.get_jwt_manager()

    try:
        print("\naccess")
        dec_access_token = decode_token(enc_access_token)
        print("\nrefresh")
        dec_refresh_token = decode_token(enc_refresh_token)

        opt['secret'] = jwt_man.decode_key_callback(unverified_headers, dec_access_token)
        dec_access_token, dec_refresh_token = validate_jwt(**opt)

    except ExpiredSignatureError as e:
        e.jwt_header = unverified_headers
        if auto_refresh:
            refresh_expiring_jwts()

            # TODO - if the token is still expired or otherwise invalid, to what value will .jwt_data be set?
            e.jwt_data = validate_jwt(**opt)

        if not allow_expired:
            _logger.error(f'{type(e)}: {e}')
            raise

    except exceptions.NoAuthorizationError as e:
        errors.append(str(e))
        print('exception', e)
        if (type(e) == exceptions.NoAuthorizationError or type(e) == ExpiredSignatureError) and not allow_expired:
            _logger.error(f'{type(e)}: {e}')
            raise
        user.set_no_user()
        return None, None, None

    return dec_access_token, dec_refresh_token, jwt_header


def validate_jwt(enc_access_token: str,
                 enc_refresh_token: str,
                 fresh: bool = False,
                 issuer: str = None,
                 leeway: int = None,
                 secret: str = None,
                 csrf_value: str = None,
                 verify_aud: bool = True,
                 verify_type: bool = True,
                 algorithms: List = None,
                 allow_expired: bool = False,
                 identity_claim_key: str = None,
                 skip_revocation_check: bool = False,
                 jwt_header: Union[dict, None] = None,
                 audience: Union[str, Iterable[str]] = None) -> [dict, dict]:
    """
        Validate a token string using JWT package decode(). Ensure there is an identity_claim and CSRF value in the
        decoded data. Ensures that the CSRF value in the token data matches what was passed in to the method

        Throws exceptions when there is an issue with the tokens
    """

    options = {"verify_aud": verify_aud} # verify audience
    if allow_expired:
        options["verify_exp"] = False # verify expiration

    # Verify the ext, iat, and nbf (not before) claims. This optionally verifies the expiration and audience claims
    # if enabled. Exceptions are raised for invalid conditions, e.g. token expiration
    dec_access_token = decode_token(enc_access_token)
    dec_refresh_token = decode_token(enc_refresh_token)

    # TODO - are these needed?
    if "type" not in dec_access_token:
        dec_access_token["type"] = "access"

    if "fresh" not in dec_access_token:
        dec_access_token["fresh"] = False

    if "jti" not in dec_access_token:
        dec_access_token["jti"] = None

    # Token verification provided by this extension
    if not allow_expired:
        if not dec_access_token:
            err = f"Missing or bad access JWT"
            _logger.error(err)
            raise exceptions.NoAuthorizationError(err)
        if not dec_refresh_token:
            err = f"Missing or bad refresh JWT"
            _logger.error(err)
            raise exceptions.NoAuthorizationError(err)

    if verify_type:
        verify_token_type(dec_access_token, is_refresh=False)
        verify_token_type(dec_refresh_token, is_refresh=True)

    if fresh and jwt_header:
        verify_token_is_fresh(jwt_header, dec_access_token)

    if not skip_revocation_check and jwt_header:
        verify_token_not_blocklisted(jwt_header, dec_access_token)

    custom_verification_for_token(jwt_header, dec_access_token)
    # TODO - need custom verification for refresh token?

    # Make sure that any custom claims we expect in the token are present
    if identity_claim_key not in dec_access_token:
        err = f"Missing claim: {identity_claim_key}"
        _logger.error(err)
        raise exceptions.JWTDecodeError(err)

    if csrf_value and "csrf" not in dec_access_token:
        err = "Missing claim: csrf"
        _logger.error(err)
        raise exceptions.JWTDecodeError(err)

    if not csrf_value and "csrf" in dec_access_token:
        err = "csrf is in access token but value not passed to validate_jwt()"
        _logger.error(err)
        raise exceptions.JWTDecodeError(err)

    if csrf_value and "csrf" in dec_access_token:
        if not compare_digest(dec_access_token["csrf"], csrf_value):
            err = "CSRF double submit tokens do not match"
            _logger.error(err)
            raise exceptions.CSRFError(err)

    return dec_access_token, dec_refresh_token


def encode_jwt(nbf: Optional[bool] = None,
               csrf: Optional[bool] = None,
               issuer: Optional[str] = None,
               secret: Optional[str] = None,
               identity: Optional[Any] = None,
               algorithm: Optional[str] = None,
               token_type: Optional[str] = 'access',
               fresh: Optional[typing.Fresh] = None,
               claim_overrides: Optional[dict] = None,
               header_overrides: Optional[dict] = None,
               identity_claim_key: Optional[str] = None,
               audience: Union[str, Iterable[str]] = False,
               json_encoder: Optional[Type[JSONEncoder]] = None,
               expires_delta: Optional[typing.ExpiresDelta] = None) -> str:

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
        print(f"calling user_identity_callback(): identity = {identity}")
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

    return jwt.encode(token_data, secret, algorithm, json_encoder=json_encoder, headers=header_overrides)


def access_token_has_expired(token_obj: Any,
                             fresh_required: bool = False, # TODO
                             access_token_class: Any = None,
                             use_refresh_expiration_delta: bool = False) -> bool:
    try:
        expires_in = expires_in_seconds(token_obj,
                                        token_class=access_token_class,
                                        use_refresh_expiration_delta=use_refresh_expiration_delta)
        return expires_in <= 0
    except ExpiredSignatureError as e:
        return True


def refresh_token_has_expired(token_obj: Any,
                              refresh_token_class: Any = None) -> bool:
    try:
        expires_in = expires_in_seconds(token_obj, token_class=refresh_token_class)
        return expires_in <= 0
    except ExpiredSignatureError as e:
        return True


def refresh_expiring_jwts(access_token_class=None, refresh_token_class=None, db=None, user_class=None):
    """
        Refresh access token for this request/session if it has expired

        In order to refresh access tokens:
            - we need a valid expired token which is also present in the Access Token table
            - we need an unexpired refresh token

        If the access token cannot be refreshed, both access and refresh tokens are unset
    """
    method = f'refresh_expiring_jwts()'

    if hasattr(g, 'checked_expiring') and g.checked_expiring == True: # already checked for expiring JWTs
        return
    g.checked_expiring = True

    enc_access_token , enc_refresh_token, csrf_token = get_tokens_from_cookies()

    if not enc_access_token or not enc_refresh_token or not csrf_token:
        print(f"missing token: A-{utils.shorten(enc_access_token,20)}, R-{utils.shorten(enc_refresh_token, 20)} ' +"
              f"f'C-{utils.shorten(csrf_token, 20)}")
        g.unset_tokens = True
        return

    user_id = get_jwt_identity()
    if not user_id:
        print("user not logged in")
        g.unset_tokens = True
        return

    user_obj = user_class.query.get(user_id)
    if not user_obj:
        _logger.error(f'{method}: could not find user object for cookie user id #{user_id}')
        g.unset_tokens = True
        return


    access_token_obj = find_access_token_by_string(user_id, enc_access_token, access_token_class=access_token_class)
    refresh_token_obj = find_refresh_token_by_string(user_id, enc_refresh_token, refresh_token_class=refresh_token_class)

    if not access_token_obj:
        _logger.warning(
            f'{method}: no ACCESS TOKEN matching cookie. Cannot determine expiration nor refresh, user_id = {user_id}')
        g.unset_tokens = True
        return

    if not refresh_token_obj:
        _logger.warning(
            f'{method}: no REFRESH TOKEN matching cookie. Cannot refresh, user_id = {user_id}')
        g.unset_tokens = True
        return

    if not access_token_has_expired(access_token_obj, access_token_class=access_token_class):
        return

    # token hasn't yet expired, get the info so that we can further check validity
    dec_access_token, dec_refresh_token, jwt_header = decode_and_validate_tokens(
        enc_access_token, enc_refresh_token, None, csrf_token=csrf_token, allow_expired=True)
    user_id = dec_access_token.get(config.get('JWT_IDENTITY_CLAIM'))
    expired_access_token = access_token_obj

    # user is not logged in, nothing to do
    if not dec_access_token:
        g.unset_tokens = True
        return

    # TODO - token_is_refreshable()
    # check if token cannot be refreshed (it is older than the refresh token)
    if access_token_has_expired(access_token_obj, access_token_class=access_token_class, use_refresh_expiration_delta=True):
        _logger.info(f'{method}: user #{user_id} access token cannot be refreshed because it is older than the ' +
                     'refresh token expiration')
        g.unset_tokens = True
        return

    if refresh_token_has_expired(refresh_token_obj, refresh_token_class=refresh_token_class):
        _logger.info(f'{method}: user #{user_id} refresh token has expired. Access token cannot be refreshed')
        g.unset_tokens = True
        return

    # refresh the access token
    _logger.info(f'{method}: user #{user_id} {-1 * expires_in_seconds(expired_access_token)} seconds since access ' +
                 f"'token expiration. Refreshing access token ...")

    # TODO - is this the correct method to call here?
    access_token = user.create_or_update_user_access_token(user, db=db, access_token_class=access_token_class,
                                                           update_existing=expired_access_token)
    g.unset_tokens = False
    g.new_access_token = access_token

    # TODO - update current_user - XXX this might be causing the CSRF issue?
    # TODO - do we need this?
    # user.update_current_user()
    # jwt_data, jwt_header = validate_request_jwt()
    # user.update_current_user(jwt_header, jwt_data)


def after_request(response):
    """ Set the new access token as a response cookie """
    print("*** after_request() ***")
    if hasattr(g, "new_access_token"):
        _logger.info(f"g.new_access_token = {utils.shorten(g.new_access_token, 40)} ***")
        utils.set_access_cookies(response, g.new_access_token)

    if hasattr(g, "new_refresh_token"):
        _logger.info(f"g.new_refresh_token = {utils.shorten(g.new_refresh_token, 40)} ***")
        utils.set_refresh_cookies(response, g.new_refresh_token)

    # Unset jwt cookies in the response (e.g. user logged out)
    if hasattr(g, "unset_tokens") and g.unset_tokens:
        _logger.info(f" g.unset tokens = {g.unset_tokens} *** ")
        utils.unset_jwt_cookies(response)

    return response


def get_token_from_cookie(which) -> str:
    if which == 'access':
        if hasattr(g, 'new_access_token'):
            encoded_acc_token = g.new_access_token
        else:
            encoded_acc_token = request.cookies.get(config.access_cookie_name)
            if not encoded_acc_token:
                err = f'Missing access cookie "{config.access_cookie_name}"'
                _logger.error(err)
                raise exceptions.NoAuthorizationError(err)
        return encoded_acc_token

    elif which == 'refresh':
        if hasattr(g, 'new_refresh_token'):
            encoded_ref_token = g.new_refresh_token
        else:
            encoded_ref_token = request.cookies.get(config.refresh_cookie_name)
        return encoded_ref_token

    elif which == 'csrf':
        if config.csrf_protect and request.method in config.csrf_request_methods:
            csrf_value = request.cookies.get(config.access_csrf_cookie_name)
            if not csrf_value:
                err = "Missing CSRF token"
                _logger.error(err)
                raise exceptions.CSRFError(err)
        else:
            csrf_value = None
        return csrf_value

    else:
        err = f'get_token_from_cookie("{which}"): unknown token type'
        _logger.error(err)
        raise exceptions.WrongTokenError(err)


def get_tokens_from_cookies() -> Tuple[str, str, Optional[str]]:
    """
        Check "flask.g" first and use that if it is set. This means that tokens have been created (user logged in) or
        the access token was refreshed. Exceptions are raised for missing authorization or CSRF
    """

    if hasattr(g, 'unset_tokens') and g.unset_tokens:
        err = f'Missing cookie <all unset>'
        _logger.error(err)
        raise exceptions.NoAuthorizationError(err)

    encoded_acc_token = get_token_from_cookie('access')
    encoded_ref_token = get_token_from_cookie('refresh')
    csrf_token = get_token_from_cookie('csrf')

    return encoded_acc_token, encoded_ref_token, csrf_token


def get_jwt() -> dict:
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
        err = "You must call `@jwt_sca()` or `process_and_handle_tokens()` before using this method"
        _logger.error(err)
        raise RuntimeError(err)
    return decoded_jwt


def get_jwt_header() -> dict:
    """
        In a protected endpoint, this will return the python dictionary which has the header of the JWT that is
        accessing the endpoint. If no JWT is present due to ``jwt_sca(optional=True)``, an empty dictionary is
        returned.
            :return:  The headers of the JWT in the current request
    """
    decoded_header = g.get("_jwt_extended_jwt_header", None)
    if decoded_header is None:
        process_and_handle_tokens(optional=True, no_exception_on_expired=True)
        decoded_header = g.get("_jwt_extended_jwt", None)

    if decoded_header is None:
        err = "You must call `@jwt_sca()` or `process_and_handle_tokens()` before using this method"
        _logger.error(err)
        raise RuntimeError(err)
    return decoded_header


def get_jwt_identity() -> Any:
    """
        In a protected endpoint, this will return the identity of the JWT that is accessing the endpoint. If no JWT is
        present due to ``jwt_sca(optional=True)``, ``None`` is returned. Returns the identity of the JWT in the current
        request
    """
    return get_jwt().get(config.identity_claim_key, None)


# TODO - rewrite this method
def get_csrf_token(encoded_token: str) -> str: # TODO
    """
        Returns the CSRF double submit token from an encoded JWT.
          :param encoded_token:  The encoded JWT
          :return:  The CSRF double submit token (string)
    """
    token = decode_and_validate_tokens(encoded_token, None, None, allow_expired=True)
    return token["csrf"]



def find_access_token_by_string(user_id: int,
                                encrypted_token: str,
                                return_all: bool = False,
                                access_token_class: Any = None) -> Any:
    results = access_token_class.query.filter_by(token=encrypted_token, user_id=user_id)
    if return_all:
        return results.all()
    return results.one_or_none()


def find_refresh_token_by_string(user_id: int,
                                 encrypted_token: str,
                                 return_all: bool = False,
                                 refresh_token_class: Any = None) -> Any:
    results = refresh_token_class.query.filter_by(token=encrypted_token, user_id=user_id)
    if return_all:
        return results.all()
    return results.one_or_none()


def expires_in_seconds(token_obj: Any,
                       token_class: Any = None,
                       use_refresh_expiration_delta: bool = False) -> int:
    """
        token_obj: a Token model (ie. Sqlalchemy) object

        TODO - probably want to allow external modules to set this method somehow so it'll match its own token model.
               For example, .token might not be the correct field name for token data in every app's Token model
   """
    jwt_man = jwt_manager.get_jwt_manager()
    # identity = jwt_man.user_identity_callback({})
    dec_access_token = jwt.decode(token_obj.token,
                                  secret=None, # jwt_man.encode_key_callback(identity),
                                  algorithms=config.decode_algorithms, options={"verify_signature": False})
    expires_in = dec_access_token["exp"] - datetime.timestamp(datetime.now(timezone.utc))

    # Use refresh token expiration for an access token. Used for determining if the access token is still refreshable
    if use_refresh_expiration_delta and type(token_obj) == token_class:
        # Adjust the expiration time from access delta to refresh delta
        expires_in = expires_in - config.access_expires.total_seconds() + config.refresh_expires.total_seconds()
    return expires_in


def verify_token_type(decoded_token: dict, is_refresh: bool) -> None:
    import json
    print(f'verify_token_type(): refresh = {is_refresh}, dict in = {json.dumps(decoded_token, indent=2)}')
    t = decoded_token["type"]
    if not is_refresh and t == "refresh":
        err = f'verify_token_type(): expected access token but got type: "{t}"'
        _logger.error(err)
        raise exceptions.WrongTokenError(err)
    elif is_refresh and t != "refresh":
        err = f'verify_token_type(): expected refresh token but got type: "{t}"'
        _logger.error(err)
        raise exceptions.WrongTokenError(err)


def verify_token_not_blocklisted(jwt_header: dict, jwt_data: dict) -> None:
    jwt_man = jwt_manager.get_jwt_manager()
    if jwt_man.token_in_blocklist_callback(jwt_header, jwt_data):
        _logger.error(f'token is blacklisted: {jwt_header}, {jwt_data}')
        raise exceptions.RevokedTokenError(jwt_header, jwt_data)


def custom_verification_for_token(jwt_header: dict, jwt_data: dict) -> None:
    jwt_man = jwt_manager.get_jwt_manager()
    if not jwt_man.token_verification_callback(jwt_header, jwt_data):
        error_msg = "User claims verification failed"
        _logger.error(error_msg)
        raise exceptions.UserClaimsVerificationError(error_msg, jwt_header, jwt_data)


def create_access_token(identity: Any,
                        additional_claims=None,
                        additional_headers=None,
                        fresh: typing.Fresh = False,
                        expires_delta: Optional[typing.ExpiresDelta] = None):
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
    return encode_jwt(claim_overrides=additional_claims, expires_delta=expires_delta, fresh=fresh,
                      header_overrides=additional_headers, identity=identity, token_type="access")


def create_refresh_token(identity: Any,
                         additional_claims=None,
                         additional_headers=None,
                         expires_delta: Optional[typing.ExpiresDelta] = None):
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
    return encode_jwt(claim_overrides=additional_claims, expires_delta=expires_delta,
                      header_overrides=additional_headers, identity=identity, token_type="refresh")


def verify_token_is_fresh(jwt_header: Union[dict, None], jwt_data: dict) -> None:
    fresh = jwt_data["fresh"]
    if isinstance(fresh, bool):
        if not fresh:
            err = "Fresh token required"
            _logger.error(err)
            raise exceptions.FreshTokenRequired(err, jwt_header, jwt_data)
    else:
        now = datetime.timestamp(datetime.now(timezone.utc))
        if fresh < now:
            err = "Fresh token required"
            _logger.error(err)
            raise exceptions.FreshTokenRequired(err, jwt_header, jwt_data)


# def get_unverified_jwt_headers(encoded_token: str) -> dict:
#     """
#         Returns the Headers of an encoded JWT without verifying the signature of the JWT.
#             :param encoded_token:  The encoded JWT to get the Header from.
#             :return:  JWT header parameters as python dict()
#     """
#     return jwt.get_unverified_header(encoded_token)


def get_user_id_from_token(encoded_token: str = None, decoded_token_dict: dict = None) -> Optional[str]:
    """
        Returns the JTI (unique identifier)
            :param encoded_token:  The encoded JWT from which to get the JTI (optional)
            :param decoded_token_dict:  Dict from a previously decoded token string (optional
            :return:  return the unique identifier (JTI) of a JWT, if it is present
    """
    return decode_and_validate_tokens(encoded_token).get("jti") # TODO - use a different method?
