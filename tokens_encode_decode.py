import jwt
import json
import uuid
import logging
import traceback

from sqlalchemy import and_
from hmac import compare_digest
from jwt import ExpiredSignatureError
from datetime import (datetime, timedelta, timezone)
from flask import (request, g, current_app, make_response)
from typing import (Any, Iterable, Type, Union, Optional, Tuple)


from . import utils
from . import types
from . import tokens
from . import cookies
from . import tokens_refresh
from . import jwt_user
from . import jwt_manager
from .config import config
from . import jwt_exceptions

_logger = logging.getLogger(__name__)


def encode_jwt(nbf: Optional[bool] = None,
               csrf: Optional[bool] = None,
               issuer: Optional[str] = None,
               secret: Optional[str] = None,
               identity: Optional[Any] = None,
               algorithm: Optional[str] = None,
               fresh: Optional[types.Fresh] = None,
               token_type: Optional[str] = 'access',
               claim_overrides: Optional[dict] = None,
               header_overrides: Optional[dict] = None,
               identity_claim_key: Optional[str] = None,
               audience: Union[str, Iterable[str]] = False,
               expires_delta: Optional[types.ExpiresDelta] = None) -> str:
    method = 'encode_jwt()'
    jwt_man = jwt_manager.get_jwt_manager()
    now = datetime.now(timezone.utc)

    if nbf is None:
        nbf = config.encode_nbf

    if csrf is None:
        csrf = config.csrf_protect

    if algorithm is None:
        algorithm = config.algorithm

    if issuer is None:
        issuer = config.encode_issuer

    if audience is None:
        audience = config.encode_audience

    if identity_claim_key is None:
        identity_claim_key = config.identity_claim_key

    if isinstance(fresh, timedelta):
        fresh = datetime.timestamp(now + fresh)

    # TODO - this will need to be rewritten
    if not identity:
        identity = jwt_man.user_identity_callback(identity) # identity data would have to come from somewhere

    if secret is None:
        secret = jwt_man.encode_key_callback(identity)

    token_data = {
        "fresh": fresh,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "type": token_type,
        identity_claim_key: identity,
    }

    if nbf:
        token_data["nbf"] = now

    if issuer:
        token_data["iss"] = issuer

    if audience:
        token_data["aud"] = audience

    if csrf:
        token_data["csrf"] = str(uuid.uuid4())

    if expires_delta is None:
        if token_type == "access":
            expires_delta = config.access_expires
        else:
            expires_delta = config.refresh_expires

    if expires_delta:
        token_data["exp"] = now + expires_delta

    if claim_overrides:
        token_data.update(claim_overrides)

    try:
        token = jwt.encode(token_data, secret, algorithm, headers=header_overrides)
        return token
    except Exception as e:
        err = f'{method}: exception in jwt.encode({json.dumps(token_data)}): {e}'
        _logger.error(err)


def decode_token(encoded_token: str, no_exception=True) -> dict:
    try:
        token_dict = jwt.decode(encoded_token,
                                None,  # secret - None means to use the secret in the app config
                                issuer=config.decode_issuer,
                                audience=config.decode_audience,
                                algorithms=config.decode_algorithms,
                                options={"verify_signature": False})
        # _logger.info(f"decode_token(): {utils.shorten_middle(encoded_token, 30)} -> {json.dumps(token_dict, indent=2)}")
        return token_dict

    except Exception as e:
        err = f'decode_token(): exception in jwt.decode({utils.shorten_middle(encoded_token, 30)}): {e}'
        _logger.error(err)
        if not no_exception:
            raise
