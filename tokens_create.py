import logging
from typing import (Any, Optional)

from . import types
from . import tokens_encode_decode
from .config import config

_logger = logging.getLogger(__name__)


def create_access_token(identity: Any,
                        additional_claims=None,
                        additional_headers=None,
                        fresh: types.Fresh = False,
                        expires_delta: Optional[types.ExpiresDelta] = None):
    """
        :param identity:
            The identity of this token. It can be any data that is json serializable. You can use
            :meth:`~flask_jwt_extended.JWTManager.user_identity_loader` to define a callback function to convert any
            object passed in into a json serializable format.

        :param fresh:
            If this token should be marked as fresh, and can thus access endpoints protected with
            ``@jwt_sca(fresh=True)``. Defaults to ``False``.

            This value can also be a ``datetime.timedelta``, which indicate how long this token will be considered
            fresh.

        :param expires_delta:
            A ``datetime.timedelta`` for how long this token should last before it expires. Set to False in order to
            disable expiration. If this is None, it will use the ``JWT_ACCESS_TOKEN_EXPIRES`` config value (see
            :ref:`Configuration Options`)

        :param additional_claims:
            Optional. A hash of claims to include in the access token.  These claims are merged into the default claims
            (exp, iat, etc.) and claims returned from the
            :meth:`~flask_jwt_extended.JWTManager.additional_claims_loader` callback. On conflict, these claims take
            precedence.

        :param additional_headers:
            Optional. A hash of headers to include in the access token. These headers are merged into the default
            headers (alg, typ) and headers returned from the
            :meth:`~flask_jwt_extended.JWTManager.additional_headers_loader` callback. On conflict, these headers take
            precedence.

        :return:  An encoded access token
    """
    expires_delta = expires_delta or config.access_expires
    return tokens_encode_decode.encode_jwt(claim_overrides=additional_claims, expires_delta=expires_delta, fresh=fresh,
                                           header_overrides=additional_headers, identity=identity, token_type="access")


def create_refresh_token(identity: Any,
                         additional_claims=None,
                         additional_headers=None,
                         expires_delta: Optional[types.ExpiresDelta] = None):
    """
        :param identity:
            The identity of this token. It can be any data that is json serializable. You can use
            :meth:`~flask_jwt_extended.JWTManager.user_identity_loader` to define a callback function to convert any
            object passed in into a json serializable format.

        :param expires_delta:
            A ``datetime.timedelta`` for how long this token should last before it expires. Set to False in order to
            disable expiration. If this is None, it will use the ``JWT_REFRESH_TOKEN_EXPIRES`` config value (see
            :ref:`Configuration Options`)

        :param additional_claims:
            Optional. A hash of claims to include in the refresh token. These claims are merged into the default claims
            (exp, iat, etc.) and claims returned from the :meth:`~flask_jwt_extended.JWTManager.additional_claims_loader`
            callback. On conflict, these claims take precedence.

        :param additional_headers:
            Optional. A hash of headers to include in the refresh token. These headers are merged into the default
            headers (alg, typ) and headers returned from the
            :meth:`~flask_jwt_extended.JWTManager.additional_headers_loader` callback. On conflict, these headers take
            precedence.s

        :return:  An encoded refresh token
    """
    expires_delta = expires_delta or config.refresh_expires
    return tokens_encode_decode.encode_jwt(claim_overrides=additional_claims, expires_delta=expires_delta,
                                           header_overrides=additional_headers, identity=identity, token_type="refresh")
