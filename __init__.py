from . import *

__version__ = "b4.5.2"  # modified by bob1b

# TODO - refactor verify_jwt_in_request method -> process_and_handle_tokens

## features ##
# TODO - is a user logged in or not? return user_id or None
# TODO - JWT parsing utils
# TODO - token creation utils
# TODO - log in / log out
# TODO - token expiration config
# .. what else?


"""
  Files:
    * config.py - config handling for JWT, mainly @property methods
    * default_callbacks.py - callbacks for things like user_identity_loader and user_lookup_loader
    * exceptions.py - exception classes, some containing __init__ code
    * internal_utils.py - small set of utils used by package but supposedly not available outside it
    * jwt_manager.py - 
    * py.typed - empty
    * tokens.py - token methods that don't belong in another file like user.py
    * typing.py - type hints setup
    * user.py (mine) - user-specific methods: login, logout, remove_expired_tokens, etc
    * utils.py - ...
    * view_decorators.py - jwt_sca()

    What exactly is a claim: an unverified statement of identity?
        It's a potentially unvalidated part of the JWT token, e.g "sub" (user identity)
"""
