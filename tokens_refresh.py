import jwt
import json
import time
import logging
from flask import g, request
from sqlalchemy import orm

from . import utils
from . import jwt_user
from . import jwt_manager

from . import tokens
from . import tokens_utils
from . import tokens_cookies
from . import tokens_encode_decode

_logger = logging.getLogger(__name__)
Session = orm.sessionmaker()

def refresh_expiring_jwts(user_class=None):
    """
        Refresh access token for this request/session if it has expired

        In order to refresh access tokens:
            - we need a valid expired token which is present in the Access Token table
            - we need a valid and unexpired refresh token

        If the access token cannot be refreshed, both access and refresh tokens are unset
    """
    method = f'refresh_expiring_jwts()'

    if hasattr(g, 'checked_expiring') and g.checked_expiring == True: # already checked for expiring JWTs
        _logger.info(f'{method}: already checking_expiring tokens, returning')
        return
    g.checked_expiring = True

    enc_access_token , enc_refresh_token, csrf_tokens = tokens_cookies.get_tokens_from_cookies()
    _logger.info(f"{method}:  [{request.url}] {tokens_utils.displayable_from_encoded_token(enc_access_token)}")
    if not enc_access_token or not enc_refresh_token or not csrf_tokens[0] or not csrf_tokens[1]:
        _logger.info(f'{method}: no tokens, returning')
        return

    jwt_man = jwt_manager.get_jwt_manager()
    access_token_class, refresh_token_class = jwt_man.get_token_classes()


    session = jwt_man.get_db().session
    found_access_token = tokens.find_token_object_by_string(
            enc_access_token, token_class=access_token_class, session=session, lock_if_found=True)

    found_refresh_token = tokens.find_token_object_by_string(enc_refresh_token, token_class=refresh_token_class)

    if not found_access_token:
        _logger.warning(f'{method}: no ACCESS TOKEN matching cookie. Cannot determine expiration nor refresh')
        jwt_user.set_no_user()
        return

    if not found_refresh_token:
        _logger.warning(f'{method}: no REFRESH TOKEN matching cookie. Cannot refresh')
        jwt_user.set_no_user()
        return

    # check if the access token has expired
    if tokens_utils.access_token_has_expired(found_access_token):
        _logger.info(f'{method}: access token has expired')
        jwt_user.set_no_user()
        return

    # if the refresh token has expired, then we can't refresh the access token
    refresh_has_expired = tokens_utils.refresh_token_has_expired(found_refresh_token)
    if refresh_has_expired:
        _logger.info(f'{method}: refresh token has expired. Access token cannot be refreshed (but access token is '+
                     'valid for now')

    # the access token hasn't expired yet. Check if it's time to refresh it
    _logger.info(f"{method}: access token hasn't expired yet")

    dec_access_token = tokens_encode_decode.decode_token(enc_access_token) # TODO - do we need to validate the token?
    jwt_header = jwt.get_unverified_header(enc_access_token)

    # ensure the user_id in the cookies matches the access and refresh tokens from the tables
    # TODO - shouldn't this check be in token validation?
    user_obj = jwt_user.load_user(jwt_header=jwt_header, dec_access_token=dec_access_token)
    if not user_obj:
        _logger.warning(f'{method}: unable to load user from decoded access token: {json.dumps(dec_access_token)},'+
                        ' cannot refresh access token')
        jwt_user.set_no_user()
        return

    if found_access_token.user_id != user_obj.id:
        _logger.warning(
            f'{method}: access token #{found_access_token.id} relates to user #{found_access_token.user_id} ' +
            f'instead of expected user #{user_obj.id}. Cannot refresh')
        jwt_user.set_no_user()
        return

    if found_refresh_token.user_id != user_obj.id:
        _logger.warning(
            f'{method}: refresh token #{found_refresh_token.id} relates to user #{found_refresh_token.user_id}'+
            f' instead of expected user #{user_obj.id}. Cannot refresh')
        jwt_user.set_no_user()
        return

    # tokens have passed validation and can be refreshed. check if it's time to refresh the token
    if not tokens_utils.is_time_to_refresh_the_access_token(found_access_token):
        return # success - no tokens returned because we didn't refresh anything

    _logger.info(f'{method}: CAN REFRESH THE ACCESS TOKEN ANYTIME NOW')
    _logger.info(f'{method}: user #{user_obj.id} {-1 * tokens_utils.expires_in_seconds(found_access_token)} seconds '+
                 f'since access token expiration. Refreshing access token ...')

    # refresh the access token
    # TODO - optionally refresh at a random time during the ready-to-refresh time (reducing change of race conditions)
    # TODO - set old token (found_access_token) to expire in a little while
    #
    access_token = jwt_user.create_user_access_token(user_obj)
    _logger.info(f"\trefreshed access token {tokens_utils.displayable_from_encoded_token(enc_access_token)} -> " +
          f"{tokens_utils.displayable_from_encoded_token(access_token)}")
    print("\tsleeping")
    time.sleep(5)
    print('\tdone sleeping')
    # end of session

    g.new_access_token = access_token

    # update current_user
    jwt_header = jwt.get_unverified_header(access_token)
    print("refresh_tokens() END: calling set_current_user()")
    jwt_user.set_current_user(jwt_header, dec_access_token)
    return access_token, enc_refresh_token
