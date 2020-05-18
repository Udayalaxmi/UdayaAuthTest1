import requests
import base64
import logging,sys
import os

LOG_FILE_PATH = './logs'
LOG_FILE_NAME = os.path.join(LOG_FILE_PATH,'authlogs.log')
LOGGER_NAME = 'oauth2log'

ORG_URL = "https://dev-777014.okta.com"
ISSUER = "https://dev-777014.okta.com/oauth2/default"
CLIENT_ID = "0oacg4297PlnRyDbO4x6"
CLIENT_SECRET = "DN_oQbfvhh02rctHMtcXUxnoKeXjnU3-wdXE9Wl_"
SCOPES = "openid profile email"
REDIRECT_URI = "https://stark-ridge-55239.herokuapp.com/oauth2/callback/"



def call_userinfo_endpoint(issuer, token):
    # Get an instance of a logger
    log = logging.getLogger(LOGGER_NAME)
    print('call_userinfo_endpoint() started')

    # Calls /userinfo endpoint with a valid access_token to fetch user information scoped to the access token
    if issuer is None:
        issuer = ISSUER

    header = {'Authorization': 'Bearer {}'.format(token)}
    r = requests.get("{}/v1/userinfo".format(issuer), headers=header)

    if r.status_code != 401:
        # Success
        return r.json()
    return


def call_introspect(issuer, token, config):
    log = logging.getLogger(LOGGER_NAME)
    print('call_introspect() started')
    # Calls /introspect endpoint to check if accessToken is valid

    header = _build_header(config)
    data = {'token': token}
    r = requests.post("{}/v1/introspect".format(issuer), headers=header, params=data)
    print(r)

    if r.status_code != 401:
        # Success
        return r.json()
    else:
        # Error
        print(r.json())
        return


def call_revocation(issuer, token, config):
    log = logging.getLogger(LOGGER_NAME)
    print('call_revocation() started')
    # Calls /revocation endpoint to revoke current accessToken
    header = _build_header(config)
    data = {'token': token}
    r = requests.post("{}/v1/revoke".format(issuer), headers=header, params=data)
    print(r)
    if r.status_code == 204:
        return
    else:
        return r.status_code


def _build_header(config):
    log = logging.getLogger(LOGGER_NAME)
    print('_build_header() started')
    # Builds the header for sending requests
    if config.client_id is None:
        config.client_id = CLIENT_ID
    if config.client_secret is None:
        config.client_secret = CLIENT_SECRET
    basic = '{}:{}'.format(config.client_id, config.client_secret)
    authorization_header = base64.b64encode(basic.encode())

    header = {
        'Authorization': 'Basic: ' + authorization_header.decode("utf-8"),
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    return header
