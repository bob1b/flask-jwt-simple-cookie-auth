import jwt
import uuid
from datetime import (datetime, timedelta, timezone)
from hmac import compare_digest
from json import JSONEncoder
from typing import (Any, Iterable, List, Type, Union)
from flask import current_app

from flask import request, g
from .config import config
from ..flask_jwt_simple_cookie_auth import (get_jwt_identity, get_jwt, set_access_cookies,
                                            verify_jwt_in_request, decode_token, unset_jwt_cookies)
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

    return jwt.encode(
        token_data,
        secret,
        algorithm,
        json_encoder=json_encoder,  # type: ignore
        headers=header_overrides,
    )


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
        encoded_token,
        secret,
        algorithms=algorithms,
        audience=audience,
        issuer=issuer,
        leeway=leeway,
        options=options,
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


@current_app.before_request
def refresh_expiring_jwts():
    # TODO - move method to flask_jwt_simple_cookie_auth?
    """ Refresh access tokens for this request that will be expiring soon OR already have expired """
    method = f'refresh_expiring_jwts()'
    enc_access_token = request.cookies.get('access_token_cookie')
    enc_refresh_token = request.cookies.get('refresh_token_cookie')
    csrf_token = request.cookies.get('csrf_access_token')

    try:
        verify_jwt_in_request(optional=True)
    except ExpiredSignatureError:
        access_token_data = decode_token(enc_access_token, csrf_token, allow_expired=True)
        user_id = access_token_data.get(config.get('JWT_IDENTITY_CLAIM'))
    except Exception as e:
        _logger.error(f'exception: {method}: {e}')
        return str(e), 500
    else:
        # token hasn't yet expired, get the info so that we can further check validity
        access_token_data = get_jwt()
        user_id = get_jwt_identity()

    if not access_token_data:
        return

    # We need a valid expired token (which is present in the Access Token table) in order to generate a new
    #   access token for this user session
    # Also, we need an unexpired refresh token or else we cannot grant a new access token to the user
    access_token = find_access_token_by_string(enc_access_token, user_id) # expired is ok
    refresh_token = find_refresh_token_by_string(enc_refresh_token, user_id)

    if not access_token:
        # _logger.warning(f'{method}: no ACCESS TOKEN. Cannot determine expiration nor refresh, user_id = {user_id}\n {enc_access_token}')
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

    db.session.delete(expired_access_token) # delete the old expired token
    access_token = user.create_access_token(request=request)
    g.unset_tokens = False
    g.new_access_token = access_token

    modified_cookies = request.cookies.copy()
    modified_cookies['access_token_cookie'] = access_token
    request.cookies = modified_cookies
    # TODO - update current_user - XXX this might be causing the CSRF issue?

@app.after_request
def after_request(response):

    # Set the new access token as a response cookie
    if hasattr(g, "new_access_token"):
        _logger.info(f"g.new_accestoken = {g.new_access_token} ***")
        set_access_cookies(response, g.new_access_token)

    # Unset jwt cookies in the response (e.g. user logged out)
    if hasattr(g, "unset_tokens") and g.unset_tokens:
        _logger.info(f" g.unset tokens = {g.unset_tokens} *** ")
        unset_jwt_cookies(response)

    return response
