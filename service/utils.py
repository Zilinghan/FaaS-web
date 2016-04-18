from base64 import urlsafe_b64encode
import requests

from service import app


def basic_auth_header():
    """Generate a Globus Auth compatible basic auth header."""
    cid = app.config['GA_CLIENT_ID']
    csecret = app.config['GA_CLIENT_SECRET']

    creds = '{}:{}'.format(cid, csecret)
    basic_auth = urlsafe_b64encode(creds.encode(encoding='UTF-8'))

    return 'Basic ' + basic_auth.decode(encoding='UTF-8')


def token_introspect(token):
    url = app.config['GA_INTROSPECT_URI']

    token_data = requests.post(url,
                               headers=dict(Authorization=basic_auth_header()),
                               data=dict(token=token))

    return token_data.json()


def get_token(header):
    return header.split(' ')[1].strip()


def get_dependent_tokens(token):
    url = app.config['GA_TOKEN_URI']
    data = {
        'grant_type': 'urn:globus:auth:grant_type:dependent_token',
        'token': token
    }

    tokens = requests.post(url,
                           headers=dict(Authorization=basic_auth_header()),
                           data=data)

    return tokens.json()