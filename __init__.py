__version__ = ".1"

from . import jwt_user
from . import view_decorators

# TODO #####################################

# TODO - refresh window (percent of access expiration) at end of valid term when tokens will start refreshing
# TODO - refresh the access tokens early and leave the access token in the table as an expired token for now
#   TODO - when the token is refreshed, set the expiration to occur soonish
# TODO - ensure that the refresh request has a valid refresh token


# TODO - race condition problem
#   * Two or more requests using the same access token (and refresh token) call an endpoint
#   * The first request is processed first and gets a refreshed access token [cookie] - is the old toke immediately expired??
#   * The second request starts before the token is changed in the db, so this request is also going to get a
#     new access token cookie, and the old token will again immediately expired?
#   * Since currently tokens are replaced when they expire, the next request is using an invalid token,
#     leading to the user getting logged out
#
#  TODO - consider: https://pypi.org/project/safelock/

# TODO - Test case:
#   *  Malicious user steals an access token and can act as a logged-in user until the access token needs to be
#      refreshed.
#   * When then malicious user's access token expires, it can't be refreshed, and the user is logged out. Optionally,
#     we can invalidate all of that user's session's tokens OR all of that user's tokens

#   TODO - remove old expired access token records after after 1 month or whatever
#   TODO - intermittently consolidate access tokens having the same refresh token (or session uuid)
#   TODO - create a session ID at every log in users
#   TODO - use the refresh token as a session uuid
#     TODO - send the new token and set the consolidate tokens to expire soon

#  TODO - add the device "Android phone" in the JWT when it's encoded. Then, token revocation should be easy to do

#  TODO - for cookies, check this:
#         For browsers, use HttpOnly and Secure cookies. cookie. The HttpOnly flag protects the cookies from being
#         accessed by JavaScript and prevents XSS attack. The Secure flag will only allow cookies to be sent to
#         servers over HTTPS connection.

# TODO - don't refresh tokens if the user has been logged out
# TODO - packaging
# TODO - reenable CSRF
# TODO _ figure out why flask.g (and/or the ctx) isn't getting cleared/popped after the request ends
# TODO - unit tests
# TODO - add the default callbacks functionality back in
# TODO #####################################

"""
  Files:
    * config.py - config handling for JWT, mainly @property methods
    * default_callbacks.py - callbacks for things like user_identity_loader and user_lookup_loader
    * jwt_exceptions.py - exception classes, some containing __init__ code
    * jwt_manager.py - 
    * py.typed - empty
    * tokens.py - token methods that don't belong in another file like user.py
    * typing.py - type hints setup
    * jwt_user.py (mine) - user-specific methods: login, logout, remove_expired_tokens, etc
    * utils.py - ...
    * view_decorators.py - jwt_sca()

    What exactly is a claim: an unverified statement of identity?
        It's a potentially unvalidated part of the JWT token, e.g "sub" (user identity)
"""
