import logging
from flask import current_app
from hmac import compare_digest
from jwt import ExpiredSignatureError
from datetime import (datetime, timezone)
from typing import (Union, Optional, Tuple)

from . import utils
from . import jwt_user
from . import jwt_manager

from . import tokens
from . import tokens_utils
from . import tokens_refresh
from . import tokens_encode_decode

from .config import config
from . import jwt_exceptions

_logger = logging.getLogger(__name__)


def decode_and_validate_tokens(opt: dict) -> Tuple[Union[dict, None], Union[dict, None]]:
    """
        Accepts dict of options, which includes "enc_access_token" and "enc_refresh_token" (from cookies). Performs
        validation on the tokens as they are decoded

        If "auto_refresh" is enabled and the refresh token is valid, then an expired token will be replaced wth a new
        token.

        If validation and decoding was successful, a tuple of the access and refresh dicts is returned. Otherwise, a
        tuple (None, None) is returned
    """
    method = f'tokens.decode_and_validate_tokens()'

    # decoded token dicts
    dec_access_token = None
    dec_refresh_token = None
    # csrf_tokens = opt['csrf_tokens'] # TODO - do we need to do validate csrf_tokens in here?

    try:
        dec_access_token, dec_refresh_token = token_validation(opt)

        if opt.get('auto_refresh'):
            ret_val = tokens_refresh.refresh_expiring_jwts()

            # if a value was returned, tokens were refreshed
            if ret_val:
                new_access_token, new_refresh_token = ret_val
                _logger.info(f"** {method}: refreshed access token {utils.shorten_middle(new_access_token, 30)}")

                # TODO - if the token is still expired or otherwise invalid, to what value will .jwt_data be set?
                opt['enc_access_token'] = new_access_token
                opt['enc_refresh_token'] = new_refresh_token
                print(f"validating new access token: {utils.shorten_middle(new_access_token, 30)}")

                # rerun token validation
                dec_access_token, dec_refresh_token = token_validation(opt)
                print(f"\ndone validating new access token, {tokens_utils.displayable_from_decoded_token(dec_access_token)}")
                return dec_access_token, dec_refresh_token

        return dec_access_token, dec_refresh_token

    except ExpiredSignatureError as e:



        # If set, show exception when token has expired
        if not opt.get('no_exception_on_expired', True):
            _logger.error(f'{method}: no_exception_on_expired=False, exception is: {type(e)}: {e}')
            raise
        print(f"{method}: returning REFRESHED dec_access_token: {tokens_utils.displayable_from_decoded_token(dec_access_token)} ")
        return dec_access_token, dec_refresh_token

    except jwt_exceptions.NoAuthorizationError as e:
        if (type(e) == jwt_exceptions.NoAuthorizationError or type(e) == ExpiredSignatureError) \
           and not opt['no_exception_on_expired']:
            _logger.error(f'{type(e)}: {e}')
            raise
        _logger.error(f'{method}: got exception {e} - setting no-user')
        jwt_user.set_no_user()
        return None, None


def token_validation(opt) -> [dict, dict]:
    """
        Validate a token string using JWT package decode():
          * Ensure there is an identity_claim and CSRF value in the decoded data
          * Ensures that the CSRF value in the token data matches what was passed in to the method # TODO
          * Ensures that the access and refresh tokens are found in their respective tables

        Throws exceptions when there is a validation issue with the tokens

        Returns  `dec_access_token` dict and `dec_refresh_token` dicts
    """
    method = f'token_validation()'
    if not opt.get('enc_access_token') or not opt.get('enc_refresh_token'):
        if not opt.get('enc_access_token'):
            print("**** enc_access_token not supplied!")
        if not opt.get('enc_refresh_token'):
            print("**** enc_refresh_token not supplied!")

        return None, None

    # options = {"verify_aud": opt['verify_aud']} # verify audience   # TODO
    # if opt['allow_expired']:
        # options["verify_exp"] = False # verify expiration  # TODO

    # Verify the ext, iat, and nbf (not before) claims. This optionally verifies the expiration and audience claims
    # if enabled. Exceptions are raised for invalid conditions, e.g. token expiration
    dec_access_token = tokens_encode_decode.decode_token(opt['enc_access_token'])
    dec_refresh_token = tokens_encode_decode.decode_token(opt['enc_refresh_token'])

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

    # check if the access and refresh tokens are in the table and match the claimed user id
    if not opt.get('skip_revocation_check', False):
        found_token = verify_token_not_block_listed(opt, user_id=user_id) # TODO - should found_token be used for something?

    # TODO - where are the jwt_headers verified??? unverified_headers -> jwt_headers

    if "fresh" not in dec_access_token:
        dec_access_token["fresh"] = False
    if "jti" not in dec_access_token:
        dec_access_token["jti"] = None

    if opt.get('verify_type', True):
        verify_token_type(dec_access_token, is_refresh=False)
        verify_token_type(dec_refresh_token, is_refresh=True)

    if opt.get('fresh', False):
        verify_token_is_fresh(opt.get('jwt_header'), dec_access_token)

    # check if either token has expired
    access_expires = tokens_utils.token_dict_expires_in_seconds(dec_access_token)
    if access_expires <= 0:
        raise ExpiredSignatureError(f'Access token {tokens_utils.displayable_from_decoded_token(dec_access_token)} has expired ' +
                                    f'{-1 * access_expires} seconds ago')
    refresh_expires = tokens_utils.token_dict_expires_in_seconds(dec_refresh_token)
    if refresh_expires <= 0:
        raise ExpiredSignatureError(f'Refresh token has expired {-1 * refresh_expires} seconds ago')

    # Make sure that any custom claims we expect in the token are present
    if not tokens_utils.get_jwt_identity(dec_access_token, get_jwt_if_none=False):
        err = f"{method}: Missing jwt identity claim: '{config.identity_claim_key}'"
        _logger.error(err)
        raise jwt_exceptions.JWTDecodeError(err)

    if opt.get('csrf_tokens') and "csrf" not in dec_access_token:
        err = "Missing claim: csrf"
        _logger.error(err)
        raise jwt_exceptions.JWTDecodeError(err)

    if opt.get('validate_csrf_for_this_request'):
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

            if 0 and not compare_digest(c1, c2): # TODO - re-enable CSRF
                err = f"CSRF double submit tokens do not match: {utils.shorten_middle(c1,30)} != {utils.shorten_middle(c2,30)}"
                _logger.error(err)
                raise jwt_exceptions.CSRFError(err)

    return dec_access_token, dec_refresh_token

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


def verify_token_not_block_listed(opt: dict, user_id: Optional[int]) -> object:
    """
        Call the callback first, if there is one. Then check if the access and refresh tokens are present, for the
        user_id if given, in the AccessToken and RefreshToken tables. If not, then the tokens are considered to be
        blocklisted

        Raises a RevokedTokenError exception if either token is blocklisted

        Returns: the found token. If the token was not valid, an exception would have been raised before returning
    """
    method = f'verify_token_not_block_listed()'

    jwt_man = jwt_manager.get_jwt_manager()

    # TODO - reimplement this
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
    found_access_token = tokens.find_token_object_by_string(
        user_id=user_id,
        token_class=access_token_class,
        encrypted_token=enc_access_token
    )

    found_refresh_token = tokens.find_token_object_by_string(user_id=user_id,
                                                                token_class=refresh_token_class,
                                                                encrypted_token=enc_refresh_token)

    user_text = f'for user #{user_id}' if user_id else ''
    if not found_access_token:
        _logger.error(f'{method}: access token ({utils.shorten_middle(enc_access_token, 30)}) {user_text} not found ' +
                      f'in table (i.e. blocklisted): {opt.get("jwt_data", {})}')
        raise jwt_exceptions.RevokedTokenError(opt["jwt_header"], opt.get("jwt_data", {}))

    # refresh token not in table?
    if not found_refresh_token:
        _logger.error(f'{method}: refresh token ({utils.shorten_middle(enc_refresh_token, 30)}) {user_text} not found '+
                      f'in table (i.e. blocklisted): {opt.get("jwt_data", {})}')
        raise jwt_exceptions.RevokedTokenError(opt["jwt_header"], opt.get("jwt_data", {}))

    return found_access_token


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
