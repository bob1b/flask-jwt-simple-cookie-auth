__version__ = ".1"

from . import jwt_user
from . import view_decorators

# TODO - don't refresh tokens if the user has been logged out
# TODO - packaging
# TODO - reenable CSRF
# TODO _ figure out why flask.g (and/or the ctx) isn't getting cleared/popped after the request ends
# TODO - unit tests


"""
  Files:
    * config.py - config handling for JWT, mainly @property methods
    * default_callbacks.py - callbacks for things like user_identity_loader and user_lookup_loader
    * jwt_exceptions.py - exception classes, some containing __init__ code
    * internal_utils.py - small set of utils used by package but supposedly not available outside it
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
