import logging

from flask import (g, request)
from typing import (Any, Optional, Union)
from werkzeug.local import LocalProxy
from datetime import (timedelta, datetime, timezone)

from . import utils
from . import tokens
from . import cookies
from . import jwt_manager
from .config import config
from . import jwt_exceptions

_logger = logging.getLogger(__name__)

# Proxy to access the current user
current_user: Any = LocalProxy(lambda: get_current_user())


def login_user(user_obj: object):
    # create cookies and save in 'g' so they will be applied to the response
    g.new_access_token = create_or_update_user_access_token(user_obj, fresh=True)
    g.new_refresh_token = create_user_refresh_token(user_obj)

    _logger.info(f"login_user(): g.new_access_token = {utils.shorten_middle(g.new_access_token, 30)}")
    _logger.info(f"              g.new_refresh_token = {utils.shorten_middle(g.new_refresh_token, 30)}")

    # remove tokens for this user that are completely expired (non-refreshable)
    remove_user_expired_tokens(user_obj)


def logout_user(user_obj, logout_all_sessions=False):
    method = f'logout_user({user_obj.id}, logout_all_sessions={logout_all_sessions})'

    jwt_man = jwt_manager.get_jwt_manager()
    access_token_class, refresh_token_class = jwt_man.get_token_classes()
    db = jwt_man.get_db()

    if logout_all_sessions:
        return user_obj.logout_all_user_sessions()

    if not logout_all_sessions:  # if we logged out all sessions, then all tokens have already been removed
        user_tokens = []

        # invalidate access token
        access_cookie_value = cookies.get_access_cookie_value()
        if not access_cookie_value:
            _logger.warning(f'{method}: no access_cookie_value for user #{user_obj.id}, cannot invalidate access token')
        else:
            found_access_token, is_just_expired_access_token = tokens.find_token_object_by_string(
                user_id=user_obj.id,
                token_class=access_token_class,
                allow_just_expired_tokens=True, # if user logged out using a 'just expired' token, then revoke that token
                encrypted_token=access_cookie_value,
            )
            if not found_access_token:
                _logger.warning(f'{method}: no AccessToken(s) found for cookie value "{access_cookie_value}", ' +
                                f'user #{user_obj.id}')
            else:
                user_tokens = user_tokens + [found_access_token]

        # invalidate refresh token
        refresh_cookie_value = cookies.get_refresh_cookie_value()
        if not refresh_cookie_value:
            _logger.warning(
                f'{method}: no refresh_cookie_value for user #{user_obj.id}, cannot invalidate access token')
        else:
            found_refresh_token, _ = tokens.find_token_object_by_string(
                user_id=user_obj.id,
                token_class=refresh_token_class,
                encrypted_token=access_cookie_value,
            )
            if not found_refresh_token:
                _logger.warning(f'{method}: no RefreshToken(s) found for cookie value "{refresh_cookie_value}", ' +
                                f'user #{user_obj.id}')
            else:
                user_tokens = user_tokens + [found_refresh_token]

        for token in user_tokens:
            _logger.info(f'{method}: deleting token: {token}')
            db.session.delete(token)  # TODO - create user function for this
        db.session.commit()

        _logger.info(f'logging out, setting unset to true, currently g = {g.__dict__}')
        set_no_user()


def logout_all_user_sessions(self):
    """ Flask shell method """
    if utils.is_flask_shell():
        yes_no = input(f'This will log out ALL user sessions for user: {self}. OK? [y/N]')
        if yes_no.lower() != 'y':
            print("Canceled. No changes")
            return

    self.remove_user_expired_tokens(expire_all_tokens=True)


def remove_user_expired_tokens(user_obj: object, expire_all_tokens=False):
    """
        Remove expired access and refresh tokens for this user. Access Tokens expire in a shorter amount of time than
          Refresh Tokens, but Access Tokens can be refreshed. So, only consider Access tokens to be expired if they
          are older than the Refresh Token expiration.

        Otherwise, we might end up deleting still in-use Access Tokens if the user has multiple sessions of the same
          login across multiple devices
    """
    method = f'remove_expired_tokens(user #{user_obj.id} ({user_obj.email}))'

    jwt_man = jwt_manager.get_jwt_manager()
    access_token_class, refresh_token_class = jwt_man.get_token_classes()
    db = jwt_man.get_db()

    removed_access_count = 0
    removed_refresh_count = 0
    user_tokens = access_token_class.query.filter_by(user_id=user_obj.id).all() + \
                  refresh_token_class.query.filter_by(user_id=user_obj.id).all()

    for token_obj in user_tokens:
        # check if this token is not refreshable
        if not tokens.token_is_refreshable(token_obj) or expire_all_tokens:
            if type(token_obj) == access_token_class:
                removed_access_count = removed_access_count + 1
            else: # refresh token
                removed_refresh_count = removed_refresh_count + 1
            db.session.delete(token_obj)
    if removed_access_count + removed_refresh_count > 0:
        db.session.commit()
        message = f'{method}: removed {removed_access_count} expired access tokens and {removed_refresh_count } ' + \
                   'refresh tokens'
        _logger.info(message)


def create_or_update_user_access_token(user_obj: object, fresh: bool=False, update_existing: Optional[object]=None,
                                       session: Optional[object]=None):
    """ create token and set JWT access cookie (includes CSRF) """
    method = f"User.create_or_update_user_access_token({user_obj})"

    jwt_man = jwt_manager.get_jwt_manager()
    access_token_class, _ = jwt_man.get_token_classes()

    if not session:
        db = jwt_man.get_db()
        session = db.session

    user_agent = None
    if request:
        user_agent = request.headers.get("User-Agent")

    access_token = tokens.create_access_token(identity=user_obj.id, fresh=fresh)
    g.unset_tokens = False
    g.new_access_token = access_token

    if update_existing and type(update_existing) == access_token_class:
        _logger.info(f"{method}: Replaced access_token #{update_existing.id} with new token value = " +
                     utils.shorten_middle(access_token, 40))

        # Save old token value and when it expired. We can use this for very recent requests that are still using the
        # old token
        update_existing.old_token = update_existing.token
        update_existing.old_token_expired_at = datetime.utcnow()
        _logger.info(f"{method}: old token: {utils.shorten_middle(update_existing.old_token, 30)}, expired at "+
                     f"{update_existing.old_token_expired_at}")

        # Update the access token value and user agent
        update_existing.token = access_token
        update_existing.user_agent = user_agent
    else:
        _logger.info(f"{method}: Created new access_token = {utils.shorten_middle(access_token, 40)}")
        access_token_obj = access_token_class(token=access_token, user_id=user_obj.id, user_agent=user_agent)
        session.add(access_token_obj)
    session.commit()
    return access_token


def create_user_refresh_token(user_obj: object):
    """ create token and set JWT refresh cookie """
    method = f"User.create_user_refresh_token({user_obj})"

    jwt_man = jwt_manager.get_jwt_manager()
    _, refresh_token_class = jwt_man.get_token_classes()

    db = jwt_man.get_db()
    refresh_token = tokens.create_refresh_token(identity=user_obj.id)
    g.unset_tokens = False
    g.new_refresh_token = refresh_token

    _logger.info(f"{method}: Created new refresh_token = {utils.shorten_middle(refresh_token, 40)}")
    refresh_token_obj = refresh_token_class(token=refresh_token, user_id=user_obj.id)
    db.session.add(refresh_token_obj)
    db.session.commit()
    return refresh_token


def set_no_user():
    g.unset_tokens = True
    g._jwt_extended_jwt = {}
    g._jwt_extended_jwt_header = {}
    g._jwt_extended_jwt_user = None


def set_current_user(jwt_header, dec_access_token):
    method = f'jwt_user.set_current_user()'
    g.unset_tokens = False
    g._jwt_extended_jwt = dec_access_token
    g._jwt_extended_jwt_header = jwt_header

    user_obj = load_user(jwt_header=jwt_header, dec_access_token=dec_access_token)
    if not user_obj:
        _logger.warning(f'{method}: attempted to load user from jwt_header={jwt_header}, dec_access_token=' +
                        f'{dec_access_token}. Setting no-user')
        set_no_user()
        return

    # call user loader (@jwt.user_lookup_loader), if it was set by the calling application. It should return
    #  {"loaded_user": user}, where user is the sqlalchemy user object for the user id found in jwt_data["sub"]
    g._jwt_extended_jwt_user = {'loaded_user': user_obj.id} # TODO - fresh


def load_user(jwt_header: dict, dec_access_token: dict) -> Optional[object]:
    """
        return the looked-up user object given the decoded access token dict
    """
    if not has_user_lookup():
        _logger.error(f'load_user(): cannot lookup user if there is no user lookup method set. dec_access_token = ' +
                      f'{dec_access_token}')
        return None

    if not dec_access_token:
        return None

    identity = tokens.get_jwt_identity(dec_access_token)
    jwt_man = jwt_manager.get_jwt_manager()
    user = jwt_man.user_lookup_callback and jwt_man.user_lookup_callback(jwt_header, dec_access_token)
    if user is None:
        error_msg = f"user_lookup returned None for {identity}"
        _logger.error(error_msg)
        raise jwt_exceptions.UserLookupError(error_msg, jwt_header, dec_access_token)
    return user


def has_user_lookup() -> bool:
    jwt_man = jwt_manager.get_jwt_manager()
    return jwt_man.user_lookup_callback is not None


def get_user_token_info():
    access_token = tokens.get_token_from_cookie('access', no_exception=True)
    if not access_token:
        return {}
    data = tokens.decode_token(access_token, no_exception=True)
    if data and 'exp' in data:
        exp_seconds = tokens.token_dict_expires_in_seconds(data)
        if exp_seconds >= 0:
            data['exp_seconds'] = f'exp {exp_seconds} seconds from now'
        else:
            data['exp_seconds'] = f'exp {-1 * exp_seconds} seconds ago'
    return data


def get_current_user() -> Union[object, None]:
    """
        If a user is logged in, this will return the user object (dict) for the JWT that is accessing the endpoint.
        If no user is logged in, returns None.

        This method checks g.unset_tokens in case the user was logged out or had their tokens revoked at the beginning
        of the current request
    """

    # unset_tokens=True means user auth tokens expired at beginning of this request
    if hasattr(g, 'unset_tokens') and g.unset_tokens:
        _logger.info('current_user(): got g.unset_tokens, returning no-user')
        return

    dec_access_token = tokens.get_jwt()
    if dec_access_token is None:
        return
    return load_user(jwt_header={}, dec_access_token=dec_access_token)


def current_user_context_processor() -> Any:
    return {"current_user": get_current_user()}
