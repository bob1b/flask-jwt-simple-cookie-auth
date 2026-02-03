import logging

from flask import (g, request)
from typing import (Any, Optional, Union)
from werkzeug.local import LocalProxy
import datetime

from . import utils
from . import tokens
from . import cookies
from . import jwt_manager
from . import tokens_utils
from . import tokens_create
from . import tokens_cookies
from . import tokens_encode_decode
from . import jwt_exceptions

_logger = logging.getLogger(__name__)

# Proxy to access the current user
current_user: Any = LocalProxy(lambda: JWTUser.get_current_user())

class JWTUser:

    def login_user(self):
        # create cookies and save in 'g' so they will be applied to the response
        g.new_access_token = self.create_user_access_token(fresh=True)
        g.new_refresh_token = self.create_user_refresh_token()

        _logger.info(f"login_user(): g.new_access_token = {utils.shorten_middle(g.new_access_token, 30)}")
        _logger.info(f"              g.new_refresh_token = {utils.shorten_middle(g.new_refresh_token, 30)}")

        # remove tokens for this user that are completely expired (non-refreshable)
        self.remove_user_expired_tokens()

    def logout_user(self, logout_all_sessions=False):
        method = f'logout_user({self.id}, logout_all_sessions={logout_all_sessions})'

        jwt_man = jwt_manager.get_jwt_manager()
        access_token_class, refresh_token_class = jwt_man.get_token_classes()
        db = jwt_man.get_db()

        if logout_all_sessions:
            return self.logout_all_user_sessions()

        # If we get here, we're not removing all user session tokens. We'll need to only remove the session tokens for this
        # session
        user_tokens = []

        # invalidate access token
        access_cookie_value = tokens_cookies.get_access_cookie_value()
        if not access_cookie_value:
            _logger.warning(f'{method}: no access_cookie_value for user #{self.id}, cannot invalidate access token')
        else:
            found_access_token = tokens.find_token_object_by_string(
                user_id=self.id,
                token_class=access_token_class,
                encrypted_token=access_cookie_value,
            )
            if not found_access_token:
                _logger.warning(f'{method}: no AccessToken(s) found for cookie value "{access_cookie_value}", ' +
                                f'user #{self.id}')
            else:
                user_tokens = user_tokens + [found_access_token]

        # invalidate refresh token
        refresh_cookie_value = tokens_cookies.get_refresh_cookie_value()
        if not refresh_cookie_value:
            _logger.warning(
                f'{method}: no refresh_cookie_value for user #{self.id}, cannot invalidate access token')
        else:
            found_refresh_token = tokens.find_token_object_by_string(
                user_id=self.id,
                token_class=refresh_token_class,
                encrypted_token=access_cookie_value,
            )
            if not found_refresh_token:
                _logger.warning(f'{method}: no RefreshToken(s) found for cookie value "{refresh_cookie_value}", ' +
                                f'user #{self.id}')
            else:
                user_tokens = user_tokens + [found_refresh_token]

        for token in user_tokens:
            _logger.info(f'{method}: deleting token: {token}')
            db.session.delete(token)  # TODO - create user function for this
        db.session.commit()

        _logger.info(f'logging out, setting unset to true, currently g = {g.__dict__}')
        JWTUser.set_no_user()

    def logout_all_user_sessions(self):
        """ can be used as a Flask shell method """
        if utils.is_flask_shell():
            yes_no = input(f'This will log out ALL user sessions for user: {self.id}. OK? [y/N]')
            if yes_no.lower() != 'y':
                print("Canceled. No changes")
                return

        self.remove_user_expired_tokens(expire_all_tokens=True)

    def remove_user_expired_tokens(self, expire_all_tokens=False):
        """
            Remove expired access and refresh tokens for this user. Access Tokens expire in a shorter amount of time than
              Refresh Tokens, but Access Tokens can be refreshed. So, only consider Access tokens to be expired if they
              are older than the Refresh Token expiration.

            Otherwise, we might end up deleting still in-use Access Tokens if the user has multiple sessions of the same
              login across multiple devices
        """
        method = f'remove_expired_tokens(user #{self.id} ({self.email}))'

        jwt_man = jwt_manager.get_jwt_manager()
        access_token_class, refresh_token_class = jwt_man.get_token_classes()
        db = jwt_man.get_db()

        removed_access_count = 0
        removed_refresh_count = 0
        user_tokens = access_token_class.query.filter(access_token_class.user_id == self.id,
                                                      access_token_class.expire_at.isnot(None)).all() + \
                      refresh_token_class.query.filter(refresh_token_class.user_id == self.id,
                                                       refresh_token_class.expire_at.isnot(None)).all()

        for token_obj in user_tokens:
            # check if this token has expired
            if expire_all_tokens or token_obj.expire_at > datetime.datetime.now(datetime.UTC):
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

    def create_user_access_token(self, fresh: bool=False, previous_token: Union[int, object]=None) -> str:
        """ create a token and set the JWT access cookie (includes CSRF) """
        method = f"User.create_user_access_token(user#{self.id})"

        jwt_man = jwt_manager.get_jwt_manager()
        access_token_class, _ = jwt_man.get_token_classes()
        session = jwt_man.get_db().session

        user_agent = None
        if request:
            user_agent = request.headers.get("User-Agent")

        # create the encoded access token string
        access_token = tokens_create.create_access_token(identity=self.id, fresh=fresh)

        # set flags so the user cookies will be updated at the end of the request
        g.unset_tokens = False
        g.new_access_token = access_token

        _logger.info(f"{method}: Created new access_token = {utils.shorten_middle(access_token, 40)}")

        # create a new access_token object in which to save the access_token (string) value. Also save the previous_token's
        # ID if supplied
        access_token_obj = access_token_class(token=access_token, user_id=self.id, user_agent=user_agent)
        session.add(access_token_obj)
        if previous_token:
            # if the previous token is passed in as an integer ID
            if isinstance(previous_token, int):
                access_token_obj.previous_token_id = previous_token
            else: # if the previous token is passed in as an object
                access_token_obj.previous_token_id = previous_token.id
        session.commit()
        return access_token

    def create_user_refresh_token(self):
        """ create a token and set the JWT refresh cookie """
        method = f"User.create_user_refresh_token({self})"

        jwt_man = jwt_manager.get_jwt_manager()
        _, refresh_token_class = jwt_man.get_token_classes()

        db = jwt_man.get_db()
        refresh_token = tokens_create.create_refresh_token(identity=self.id)
        g.unset_tokens = False
        g.new_refresh_token = refresh_token

        _logger.info(f"{method}: Created new refresh_token = {utils.shorten_middle(refresh_token, 40)}")
        refresh_token_obj = refresh_token_class(token=refresh_token, user_id=self.id)
        db.session.add(refresh_token_obj)
        db.session.commit()
        return refresh_token

    @classmethod
    def set_no_user(cls):
        g.unset_tokens = True
        g._jwt_extended_jwt = {}
        g._jwt_extended_jwt_header = {}
        g._jwt_extended_jwt_user = None

    @classmethod
    def set_current_user(cls, jwt_header: dict, dec_access_token: dict):
        method = f'jwt_user.set_current_user()'
        g.unset_tokens = False
        g._jwt_extended_jwt = dec_access_token
        g._jwt_extended_jwt_header = jwt_header

        user_obj = cls.load_user(jwt_header=jwt_header, dec_access_token=dec_access_token)
        if not user_obj:
            _logger.warning(f'{method}: attempted to load user from jwt_header={jwt_header}, dec_access_token=' +
                            f'{dec_access_token}. Setting no-user')
            cls.set_no_user()
            return

        # call the user loader `user_lookup_loader` if it was set by the calling application. It should return
        #  {"loaded_user": user}, where user is the sqlalchemy user object for the user id found in `jwt_data["sub"]`
        g._jwt_extended_jwt_user = {'loaded_user': user_obj.id} # TODO - fresh

    @classmethod
    def load_user(cls, jwt_header: dict, dec_access_token: dict) -> Optional[object]:
        """
            return the looked-up user object given the decoded access token dict
        """
        if not cls.has_user_lookup():
            _logger.error(f'load_user(): cannot lookup user if there is no user lookup method set. dec_access_token = ' +
                          f'{dec_access_token}')
            return None

        if not dec_access_token:
            return None

        identity = tokens_utils.get_jwt_identity(dec_access_token)
        jwt_man = jwt_manager.get_jwt_manager()
        user = jwt_man.user_lookup_callback and jwt_man.user_lookup_callback(jwt_header, dec_access_token)
        if user is None:
            error_msg = f"user_lookup returned None for {identity}"
            _logger.error(error_msg)
            raise jwt_exceptions.UserLookupError(error_msg, jwt_header, dec_access_token)
        return user

    @classmethod
    def has_user_lookup(cls) -> bool:
        jwt_man = jwt_manager.get_jwt_manager()
        return jwt_man.user_lookup_callback is not None

    @classmethod
    def get_user_token_info(cls):
        access_token = tokens_cookies.get_token_from_cookie('access', no_exception=True)
        if not access_token:
            return {}
        data = tokens_encode_decode.decode_token(access_token, no_exception=True)
        if data and 'exp' in data:
            exp_seconds = tokens_utils.token_dict_expires_in_seconds(data)
            if exp_seconds >= 0:
                data['exp_seconds'] = f'exp {exp_seconds} seconds from now'
            else:
                data['exp_seconds'] = f'exp {-1 * exp_seconds} seconds ago'
        return data

    @classmethod
    def get_current_user(cls) -> Optional[object]:
        """
        If a user is logged in, this will return the user object (dict) for the JWT that is accessing the endpoint.
        If no user is logged in, returns None.

        This method checks g.unset_tokens in case the user was logged out or had their tokens revoked at the beginning
        of the current request
        """

        # `unset_tokens`=True means user auth tokens expired at the beginning of this request
        if hasattr(g, 'unset_tokens') and g.unset_tokens:
            _logger.info('current_user(): got g.unset_tokens, returning no-user')
            return None

        dec_access_token = tokens_utils.get_jwt()
        if dec_access_token is None:
            return None
        return cls.load_user(jwt_header={}, dec_access_token=dec_access_token)

    @classmethod
    def current_user_context_processor(cls) -> Any:
        return {"current_user": cls.get_current_user()}
