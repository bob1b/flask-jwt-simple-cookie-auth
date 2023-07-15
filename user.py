from datetime import timedelta
from flask import g


def login(user, request):
    # create cookies and save in 'g' so they will be applied to the response
    g.new_access_token = user.create_access_token(request=request, fresh=timedelta(minutes=15))
    g.new_refresh_token = user.create_refresh_token()
    # TODO

def logout_user(user, response=None, logout_all_sessions=False):
    method = f'logout_user({user.id}, response={response}, logout_all_sessions={logout_all_sessions})'

    if not logout_all_sessions:  # if we logged out all sessions, then all tokens have already been removed
        tokens = []

        access_cookie_value = get_access_cookie_value()
        if not access_cookie_value:
            _logger.warning(f'{method}: no access_cookie_value for user #{user.id}, cannot invalidate access token')
        else:
            found_tokens = models.AccessToken.query.filter_by(user_id=user.id, token=access_cookie_value).all()
            if not found_tokens:
                _logger.warning(f'{method}: no AccessToken(s) found for cookie value "{access_cookie_value}", ' +
                                f'user #{user.id}')
            else:
                tokens = tokens + found_tokens

        refresh_cookie_value = get_refresh_cookie_value()
        if not refresh_cookie_value:
            _logger.warning(
                f'{method}: no refresh_cookie_value for user #{user.id}, cannot invalidate access token')
        else:
            found_tokens = models.RefreshToken.query.filter_by(
                user_id=user.id, token=refresh_cookie_value).all()
            if not found_tokens:
                _logger.warning(
                    f'{method}: no RefreshToken(s) found for cookie value "{refresh_cookie_value}", ' +
                    f'user #{user.id}')
            else:
                tokens = tokens + found_tokens

        for token in tokens:
            _logger.info(f'{method}: deleting token: {token}')
            db.session.delete(token)
        db.session.commit()

        g.unset_tokens = True

def remove_expired_tokens(user):
    """
        Remove expired tokens for this user. Even though Access Tokens expire relatively quickly compared to
          Refresh Tokens, only consider tokens to be expired if they are older than the Refresh Token expiration.

        Otherwise, we might end up deleting still in-use Access Tokens if the user has multiple sessions of the same
          login across multiple devices
    """
    method = f'remove_expired_tokens(user #{user.id} ({user.email}))'
    removed_access_count = 0
    removed_refresh_count = 0
    user_tokens = models.AccessToken.query.filter_by(user_id=user.id).all() + \
                  models.RefreshToken.query.filter_by(user_id=user.id).all()
    for token in user_tokens:
        expires_in_seconds = token.expires_in_seconds(use_refresh_expiration_delta=True)
        if int(expires_in_seconds) < 0:
            if type(token) == models.AccessToken:
                removed_access_count = removed_access_count + 1
            else: # refresh token
                removed_refresh_count = removed_refresh_count + 1
            db.session.delete(token)
    db.session.commit()
    _logger.info(f'{method}: removed {removed_access_count} expired access tokens and {removed_refresh_count } ' +
                 'refresh tokens')

def create_access_token(self, request=None, fresh=False, expires_delta=timedelta(minutes=15), replace=None):
    method = f"User.create_access_token({self})"

    user_agent = None
    if request:
        user_agent = request.headers.get("User-Agent")

    access_token = jwt2.create_access_token(identity=self.id, fresh=fresh) # set JWT access cookie (includes CSRF)

    _logger.info(f"{method}: Created new access_token = {access_token}")

    if replace and type(replace) == models.AccessToken:
        replace.token = access_token
        replace.user_agent = user_agent
    else:
        access_token_obj = models.AccessToken(token=access_token, user_id=self.id, user_agent=user_agent)
        db.session.add(access_token_obj)
    db.session.commit()
    return access_token

def create_refresh_token(self, expires_delta=timedelta(weeks=2)):
    refresh_token = jwt2.create_refresh_token(identity=self.id)
    refresh_token_obj = models.RefreshToken(token=refresh_token, user_id=self.id)
    db.session.add(refresh_token_obj)
    db.session.commit()
    return refresh_token