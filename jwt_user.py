import logging

from flask import (g, request)
from datetime import timedelta
from typing import (Any, Optional)
from werkzeug.local import LocalProxy

from . import utils
from . import tokens
from . import cookies
from . import jwt_manager
from .config import config
from . import jwt_exceptions

_logger = logging.getLogger(__name__)

# Proxy to access the current user
current_user: Any = LocalProxy(lambda: get_current_user())


def login_user(user_obj, access_token_class=None, refresh_token_class=None, db=None):
    # create cookies and save in 'g' so they will be applied to the response
    g.new_access_token = create_or_update_user_access_token(user_obj, access_token_class=access_token_class, db=db)
    g.new_refresh_token = create_user_refresh_token(user_obj, refresh_token_class=refresh_token_class, db=db)
    _logger.info(f"\nlogin_user(): g.new_access_token = {utils.shorten(g.new_access_token, 30)}")
    _logger.info(f"              g.new_refresh_token = {utils.shorten(g.new_refresh_token, 30)}")

    # remove tokens for this user that are completely expired (non-refreshable)
    remove_user_expired_tokens(user_obj,access_token_class=access_token_class, refresh_token_class=refresh_token_class,
                               db=db)


def logout_user(user_obj, access_token_class=None, refresh_token_class=None, logout_all_sessions=False, db=None):
    method = f'logout_user({user_obj.id}, logout_all_sessions={logout_all_sessions})'

    if not logout_all_sessions:  # if we logged out all sessions, then all tokens have already been removed
        user_tokens = []

        # invalidate access token
        access_cookie_value = cookies.get_access_cookie_value()
        if not access_cookie_value:
            _logger.warning(f'{method}: no access_cookie_value for user #{user_obj.id}, cannot invalidate access token')
        else:
            found_access_tokens = tokens.find_token_object_by_string(
                encrypted_token=access_cookie_value, user_id=user_obj.id, return_all=True, token_class=access_token_class
            )
            if not found_access_tokens:
                _logger.warning(f'{method}: no AccessToken(s) found for cookie value "{access_cookie_value}", ' +
                                f'user #{user_obj.id}')
            else:
                user_tokens = user_tokens + found_access_tokens

        # invalidate refresh token
        refresh_cookie_value = cookies.get_refresh_cookie_value()
        if not refresh_cookie_value:
            _logger.warning(
                f'{method}: no refresh_cookie_value for user #{user_obj.id}, cannot invalidate access token')
        else:
            found_refresh_tokens = tokens.find_token_object_by_string(
                encrypted_token=access_cookie_value, user_id=user_obj.id, return_all=True, token_class=refresh_token_class
            )
            if not found_refresh_tokens:
                _logger.warning(f'{method}: no RefreshToken(s) found for cookie value "{refresh_cookie_value}", ' +
                                f'user #{user_obj.id}')
            else:
                user_tokens = user_tokens + found_refresh_tokens

        for token in user_tokens:
            _logger.info(f'{method}: deleting token: {token}')
            db.session.delete(token)  # TODO - create user function for this
        db.session.commit()

        _logger.info(f'logging out, setting unset to true, currently g = {g.__dict__}')
        g.unset_tokens = True


def remove_user_expired_tokens(user_obj, access_token_class=None, refresh_token_class=None, db=None):
    """
        Remove expired access and refresh tokens for this user. Access Tokens expire in a shorter amount of time than
          Refresh Tokens, but Access Tokens can be refreshed. So, only consider Access tokens to be expired if they
          are older than the Refresh Token expiration.

        Otherwise, we might end up deleting still in-use Access Tokens if the user has multiple sessions of the same
          login across multiple devices
    """
    method = f'remove_expired_tokens(user #{user_obj.id} ({user_obj.email}))'

    removed_access_count = 0
    removed_refresh_count = 0
    user_tokens = access_token_class.query.filter_by(user_id=user_obj.id).all() + \
                  refresh_token_class.query.filter_by(user_id=user_obj.id).all()

    for token_obj in user_tokens:
        # check if this token is not refreshable
        expires_in_seconds = tokens.expires_in_seconds(token_obj,
                                                       token_class=access_token_class,
                                                       use_refresh_expiration_delta=True)
        if int(expires_in_seconds) < 0:
            if type(token_obj) == access_token_class:
                removed_access_count = removed_access_count + 1
            else: # refresh token
                removed_refresh_count = removed_refresh_count + 1
            db.session.delete(token_obj)
    if removed_access_count + removed_refresh_count > 0:
        db.session.commit()
        _logger.info(f'{method}: removed {removed_access_count} expired access tokens and {removed_refresh_count } ' +
                     'refresh tokens')


def create_or_update_user_access_token(user_obj,
                                       db=None,
                                       fresh=False,
                                       update_existing=None,
                                       access_token_class=None,
                                       expires_delta=timedelta(minutes=15)):
    """ create token and set JWT access cookie (includes CSRF) """
    method = f"User.create_user_access_token({user_obj})"

    user_agent = None
    if request:
        user_agent = request.headers.get("User-Agent")

    access_token = tokens.create_access_token(identity=user_obj.id, fresh=fresh, expires_delta=expires_delta)
    g.unset_tokens = False
    g.new_access_token = access_token

    if update_existing and type(update_existing) == access_token_class:
        _logger.info(f"{method}: Replaced access_token #{update_existing.id} with new token value = " +
                     utils.shorten(access_token, 40))
        update_existing.token = access_token
        update_existing.user_agent = user_agent
    else:
        _logger.info(f"{method}: Created new access_token = {utils.shorten(access_token, 40)}")
        access_token_obj = access_token_class(token=access_token, user_id=user_obj.id, user_agent=user_agent)
        db.session.add(access_token_obj)
    db.session.commit()
    return access_token


def create_user_refresh_token(user_obj, expires_delta=timedelta(weeks=2), refresh_token_class=None, db=None):
    """ create token and set JWT refresh cookie """
    method = f"User.create_user_refresh_token({user_obj})"
    refresh_token = tokens.create_refresh_token(identity=user_obj.id, expires_delta=expires_delta)
    g.unset_tokens = False
    g.new_refresh_token = refresh_token

    _logger.info(f"{method}: Created new refresh_token = {utils.shorten(refresh_token, 40)}")
    refresh_token_obj = refresh_token_class(token=refresh_token, user_id=user_obj.id)
    db.session.add(refresh_token_obj)
    db.session.commit()
    return refresh_token


def set_no_user():
    g._jwt_extended_jwt = {}
    g._jwt_extended_jwt_header = {}
    g._jwt_extended_jwt_user = {"loaded_user": None}


# TODO - test this well
def set_current_user(jwt_header, dec_access_token):
    g._jwt_extended_jwt = dec_access_token
    g._jwt_extended_jwt_header = jwt_header
    g._jwt_extended_jwt_user = load_user(jwt_header, dec_access_token) # TODO - this is just the user_id ?


def load_user(jwt_header: dict, dec_access_token: dict) -> Optional[dict]:
    if not has_user_lookup() or not dec_access_token:
        return None

    identity = dec_access_token[config.identity_claim_key]
    user = user_lookup(jwt_header, dec_access_token)
    if user is None:
        error_msg = f"user_lookup returned None for {identity}"
        _logger.error(error_msg)
        raise jwt_exceptions.UserLookupError(error_msg, jwt_header, dec_access_token)
    return {"loaded_user": user}


def has_user_lookup() -> bool:
    jwt_man = jwt_manager.get_jwt_manager()
    return jwt_man.user_lookup_callback is not None


def user_lookup(*args, **kwargs) -> Any:
    jwt_man = jwt_manager.get_jwt_manager()
    return jwt_man.user_lookup_callback and jwt_man.user_lookup_callback(*args, **kwargs)


# TODO - go through this again
def get_current_user() -> Any:
    """
        In a protected endpoint, this will return the user object for the JWT that is accessing the endpoint.

        This is only usable if :meth:`~flask_jwt_extended.JWTManager.user_lookup_loader` is configured. If the user
        loader callback is not being used, this will raise an error.

        If no JWT is present due to ``jwt_sca(optional=True)``, ``None`` is returned.

        :return:
            The current user object for the JWT in the current request
    """
    tokens.get_jwt()  # Raise an error if not in a decorated context

    # tokens had expired at beginning of this request
    if hasattr(g, 'unset_tokens') and g.unset_tokens:
        _logger.info('current_user(): got g.unset_tokens, returning no-user')
        return None

    jwt_user_dict = g.get("_jwt_extended_jwt_user", None)
    if jwt_user_dict is None:
        err = "You must provide a `@jwt.user_lookup_loader` callback to use this method"
        # raise RuntimeError(err)
        _logger.error(err)
        return

    return jwt_user_dict["loaded_user"]


def current_user_context_processor() -> Any:
    return {"current_user": get_current_user()}