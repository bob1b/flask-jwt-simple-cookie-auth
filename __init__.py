__version__ = ".1"

from . import jwt_user
from . import view_decorators

# TODO #####################################

# TODO - optionally refresh at a random time during the ready-to-refresh time (reducing change of race conditions)
# TODO - set old token (found_access_token) to expire in a little while when it is replaced with a new token

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
