import json
from flask import request, _request_ctx_stack, abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'kcemenike.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'kcemenike'

# AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


# Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''


def get_token_auth_header():
    auth = request.headers.get('Authorization', None)
    # Return 401 if authorization header does not exist
    if not auth:
        # print("No auth")
        raise AuthError({
            'code': 'no_auth_header',
            'description': 'Authorization header is missing. Kindly include'
        }, 401)
    # print(auth)
    if len(auth.split()) != 2:
        raise AuthError({
            'code': 'invalid_auth',
            'description': 'Authorization invalid, please try again'
        }, 401)
    elif auth.split()[0].lower() != 'bearer':
        raise AuthError({
            'code': 'no_bearer',
            'description': "Authorization header must start with 'Bearer'"
        }, 401)
    # print(auth.split())
    else:
        return auth.split()[1]
    raise AuthError({
        'code': 'invalid_auth',
        'description': 'Authorization invalid'
    })
    # raise Exception('Not Implemented')


'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''


def check_permissions(permission, payload):
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid claim',
            'description': 'please include permissions in token'
        }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'descripton': "payload doesn't contain permission. Please check and try again"
        }, 403)

    return True

    # raise Exception('Not Implemented')


'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''


def verify_decode_jwt(token):
    url = urlopen(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
    jwt_keys = json.loads(url.read())

    unverified_header = jwt.get_unverified_header(token)

    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization invalid'
        }, 401)

    for key in jwt_keys['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {index: value for index, value in key.items() if index in [
                'kid', 'kty', 'use', 'n', 'e']}
            # print(rsa_key)
    # raise Exception('Not Implemented')

    try:
        payload = jwt.decode(token=token, key=rsa_key, algorithms=ALGORITHMS,
                             audience=API_AUDIENCE, issuer=f"https://{AUTH0_DOMAIN}/")
        return payload

    except jwt.JWTClaimsError:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Claims invalid'
        }, 401)

    except jwt.ExpiredSignatureError:
        raise AuthError({
            'code': 'expired_token',
            'description': 'This token has expired, please generate another toekn'
        }, 401)
    except Exception:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Unable to parse token'
        }, 400)

    # final error catch
    raise AuthError({
        'code': 'invalid',
        'description': 'Key not found in token'
    }, 400)


'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''


def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            jwt = get_token_auth_header()
            try:
                payload = verify_decode_jwt(jwt)
            except:
                raise AuthError({
                    'code': 'invalid_token',
                    'description': 'Token invalid, kindly try again with valid token'
                }, 401)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator
