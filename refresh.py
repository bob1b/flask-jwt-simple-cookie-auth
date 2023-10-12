import jwt
import json
import time
import logging
from flask import g, request
from sqlalchemy import orm

from . import utils
from . import tokens
from . import jwt_user
from . import jwt_manager

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

    enc_access_token , enc_refresh_token, csrf_tokens = tokens.get_tokens_from_cookies()
    print(f"\n{method}:  [{request.url}] {tokens.displayable_from_encoded_token(enc_access_token)}")
    if not enc_access_token or not enc_refresh_token or not csrf_tokens[0] or not csrf_tokens[1]:
        _logger.info(f'{method}: no tokens, returning')
        return

    jwt_man = jwt_manager.get_jwt_manager()
    access_token_class, refresh_token_class = jwt_man.get_token_classes()

    # begin session
    db = jwt_man.get_db()
    session = db.session
    session.begin_nested()
    found_access_token, is_just_expired_access_token = \
        tokens.find_token_object_by_string(
            enc_access_token, token_class=access_token_class, session=session, lock_if_found=True)

    found_refresh_token, _ = tokens.find_token_object_by_string(enc_refresh_token, token_class=refresh_token_class)

    if not found_access_token:
        _logger.warning(f'{method}: no ACCESS TOKEN matching cookie. Cannot determine expiration nor refresh')
        jwt_user.set_no_user()
        session.commit()
        return

    if not found_refresh_token:
        _logger.warning(f'{method}: no REFRESH TOKEN matching cookie. Cannot refresh')
        jwt_user.set_no_user()
        session.commit()
        return

    # if the refresh token has expired, then we can't refresh the access token
    if tokens.refresh_token_has_expired(found_refresh_token):
        _logger.info(f'{method}: refresh token has expired. Access token cannot be refreshed')
        jwt_user.set_no_user()
        session.commit()
        return

    # if the access token is a "just expired" token, then treat it as valid for the next short interval
    if is_just_expired_access_token:
        _logger.info(f"{method}: access token has 'just expired', so there's nothing to refresh")
        session.commit()
        return enc_access_token, enc_refresh_token

    # if the access token hasn't expired yet, then we don't need to do anything
    if not tokens.access_token_has_expired(found_access_token):
        _logger.info(f"{method}: access token hasn't expired yet, returning")
        session.commit()
        return enc_access_token, enc_refresh_token

    # token has expired. Get more info so that we can refresh it
    print(f'\ttoken has expired: {tokens.displayable_from_encoded_token(enc_access_token)}, is_just_expired = ' +
          f'{is_just_expired_access_token}')
    expired_access_token = found_access_token

    # check if token cannot be refreshed (it is older than the refresh token)
    if not tokens.token_is_refreshable(expired_access_token):
        _logger.info(
            f'{method}: access token cannot be refreshed because it is older than the refresh token expiration')
        jwt_user.set_no_user()
        session.commit()
        return

    dec_access_token = tokens.decode_token(enc_access_token) # TODO - do we need to validate the token?
    jwt_header = jwt.get_unverified_header(enc_access_token)

    # ensure the user_id in the cookies matches the access and refresh tokens from the tables
    # TODO - shouldn't this check be in token validation?
    user_obj = jwt_user.load_user(jwt_header=jwt_header, dec_access_token=dec_access_token)
    if not user_obj:
        _logger.warning(f'{method}: unable to load user from decoded access token: {json.dumps(dec_access_token)},'+
                        ' cannot refresh access token')
        jwt_user.set_no_user()
        session.commit()
        return

    if found_access_token.user_id != user_obj.id:
        _logger.warning(
            f'{method}: access token #{found_access_token.id} relates to user #{found_access_token.user_id} ' +
            f'instead of expected user #{user_obj.id}. Cannot refresh')
        jwt_user.set_no_user()
        session.commit()
        return

    if found_refresh_token.user_id != user_obj.id:
        _logger.warning(
            f'{method}: refresh token #{found_refresh_token.id} relates to user #{found_refresh_token.user_id}'+
            f' instead of expected user #{user_obj.id}. Cannot refresh')
        jwt_user.set_no_user()
        session.commit()
        return

    # tokens have passed validation and can be refreshed
    _logger.info(f'{method}: user #{user_obj.id} {-1 * tokens.expires_in_seconds(expired_access_token)} seconds since '+
                 f'access token expiration. Refreshing access token ...')

    # refresh the access token
    access_token = jwt_user.create_or_update_user_access_token(user_obj,
                                                               update_existing=expired_access_token,
                                                               session=session)
    print(f"\trefresh token {tokens.displayable_from_encoded_token(enc_access_token)} -> " +
          f"{tokens.displayable_from_encoded_token(access_token)}")
    print("\tsleeping")
    time.sleep(10)
    print('\tdone sleeping')
    print('\nUNLOCK\n')
    session.commit() # also unlocks the access_token row
    # end of session

    g.new_access_token = access_token

    # update current_user
    jwt_header = jwt.get_unverified_header(access_token)
    print("refresh_tokens() END: calling set_current_user()")
    jwt_user.set_current_user(jwt_header, dec_access_token)
    return access_token, enc_refresh_token
