import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'fsnd-mashael.eu.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffee_shop'

## AuthError Exception
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header
def get_token_auth_header():
    # Obtain Access Token from the Authorization Header
    auth = request.headers.get('Authorization', None)

    # Check if Authorization header exists
    if not auth:
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'Authorization header is expected.'
            }, 401)

    # Split the header into two parts => Bearer, Token
    parts = auth.split()

    # Check that the first part is Bearer
    if parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must start with "Bearer".'
            }, 401)

    # Check if Token exists
    elif len(parts) == 1:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Token not found.'
            }, 401)

    # Make sure the Authorization header is a bearer token
    elif len(parts) > 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token.'
            }, 401)

    # Get the second part (token)
    token = parts[1]

    return token


def check_permissions(permission, payload):
    # Check that permissions are included in the payload
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Permissions not included in JWT.'
            }, 400)

    # Check that the passed permission string is included in the payload (authorized)
    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'forbidden',
            'description': 'Access Forbidden.'
            }, 403)

    return true


def verify_decode_jwt(token):
    # Load public key from Auth0
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())

    # Unpack jwt header to verify the kid
    unverified_header = jwt.get_unverified_header(token)

    rsa_key = {}

    # Check that kid exists
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    # Choose our key
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }

    print(rsa_key)

    if rsa_key:
        try:
            # Use rsa_key to validate the JWT
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload
            
        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token Expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)

    raise AuthError({
            'code': 'invalid_header',
            'description': 'Unable to find the appropriate key.'
    }, 400)


def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Get token
            token = get_token_auth_header()

            try:
                # Decode jwt
                payload = verify_decode_jwt(token)
            except:
                raise AuthError({
                    "code": "invalid_payload",
                    "description": "Unable to decode payload."
                }, 400)

            # Validate claims
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator