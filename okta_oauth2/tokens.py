import time
import jwt as jwt_python
from jose import jwt
from jose import jws
import requests
from .models import DiscoveryDocument
from django.conf import settings
import base64
import logging,sys
import os





ORG_URL = "https://dev-777014.okta.com"
ISSUER = "https://dev-777014.okta.com/oauth2/default"
CLIENT_ID = "0oacg4297PlnRyDbO4x6"
CLIENT_SECRET = "DN_oQbfvhh02rctHMtcXUxnoKeXjnU3-wdXE9Wl_"
SCOPES = "openid profile email"
REDIRECT_URI = "https://stark-ridge-55239.herokuapp.com/oauth2/callback/"


LOG_FILE_PATH = './logs'
LOG_FILE_NAME = os.path.join(LOG_FILE_PATH,'authlogs.log')
LOGGER_NAME = 'oauth2log'

class TokenValidator(object):
    # Get an instance of a logger
    log = logging.getLogger(LOGGER_NAME)
    print('in class TokenValidator() started')
    def __init__(self, config, keys=[]):
        log = logging.getLogger(LOGGER_NAME)
        print('in  TokenValidator init() started')
        print('params....', config)
        print('params.keys...', keys)
        self.config = config
        self.keys = keys

    def call_token_endpoint(self, auth_code):
        """ Call /token endpoint
            Returns accessToken, idToken, or both
        """
        log = logging.getLogger(LOGGER_NAME)
        print('call_token_endpoint() started')
        discovery_doc = DiscoveryDocument(self.config.issuer).getJson()
        token_endpoint = discovery_doc['token_endpoint']
        print('token_endpoint==')
        print(token_endpoint)
        print('SCOPES==')
        print(SCOPES)
        print(CLIENT_ID)
        print(CLIENT_SECRET)
        if self.config.scopes is None:
            print("inn iff")
            self.config.scopes = SCOPES
        if self.config.client_id is None:
            self.config.client_id = CLIENT_ID
        if self.config.client_secret is None:
            self.config.client_secret = CLIENT_SECRET
        if self.config.redirect_uri is  None:
            self.config.redirect_uri = REDIRECT_URI
        if self.config.issuer is None:
            self.config.issuer = ISSUER

        basic_auth_str = '{0}:{1}'.format(self.config.client_id, self.config.client_secret)
        authorization_header = base64.b64encode(basic_auth_str.encode())
        header = {
            'Accept':'application/json',
            'Authorization': 'Basic: ' + authorization_header.decode("utf-8"),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        print('self.config.scopes : ')
        print(self.config.scopes)
        print('self.config.clientId : ')
        print(self.config.client_id)
        #self.config.scopes = "openid profile email"
        data = {
            'grant_type': self.config.grant_type,
            'code': str(auth_code),
            'scope':self.config.scopes,
            #'scope': ' '.join(self.config.scopes),
            'redirect_uri': self.config.redirect_uri
        }

        # Send token request
        print("header==")
        print(header)
        print("param ==")
        print(data)
        print("Sending token endpoint")
        r = requests.post(token_endpoint, headers=header, params=data)
        response = r.json()

        # Return object
        result = {}
        if 'error' not in response:
            if 'access_token' in response:
                result['access_token'] = response['access_token']
            if 'id_token' in response:
                result['id_token'] = response['id_token']

        return result if len(result.keys()) > 0 else None

    def validate_token(self, token, nonce):
        log = logging.getLogger(LOGGER_NAME)
        print('inn validate_token() started')
        """
            Validate token
             (Taken from http://openid.net/specs/openid-connect-core-1_0.html#TokenResponseValidation)
        """

        def _jwks(kid, issuer):
            print("in jwks..")
            """
                Internal:
                    Fetch public key from jwks_uri and caches it until the key rotates
                :param kid: "key Id"
                :param issuer: issuer uri
                :return: key from jwks_uri having the kid key
            """

            for key in self.keys:
                if key["kid"] == kid:
                    print('found key in cache')
                    return key

            # lookup the key from jwks_uri if key is not in cache
            # Get discovery document
            r = requests.get(issuer + "/.well-known/openid-configuration")
            discovery = r.json()
            r = requests.get(discovery["jwks_uri"])
            jwks = r.json()
            for key in jwks['keys']:
                if kid == key['kid']:
                    self.keys.append(key)
                    return key

            return None

        try:
            """	Step 1
                If encrypted, decrypt it using the keys and algorithms specified in the meta_data
                If encryption was negotiated but not provided, REJECT
                
                Skipping Okta has not implemented encrypted JWT
            """

            decoded_token = jwt_python.decode(token, verify=False)

            dirty_alg = jwt.get_unverified_header(token)['alg']
            dirty_kid = jwt.get_unverified_header(token)['kid']

            key = _jwks(dirty_kid, decoded_token['iss'])
            if key:
                # Validate the key using jose-jws
                try:
                    jws.verify(token, key, algorithms=[dirty_alg])
                except Exception as err:
                    raise ValueError("Signature is Invalid. {}".format(err))
            else:
                raise ValueError("Unable to fetch public signing key")

            """ Step 2
                Issuer Identifier for the OpenID Provider (which is typically
                obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim.
                Redundant, since we will validate in Step 3, the "iss" claim matches host we requested the token from
            """

            if decoded_token['iss'] != self.config.issuer:
                """ Step 3    
                    Client MUST validate:
                        aud (audience) contains the same `client_id` registered
                        iss (issuer) identified as the aud (audience)
                        aud (audience) Claim MAY contain an array with more than one element (Currently NOT IMPLEMENTED by Okta)
                    The ID Token MUST be rejected if the ID Token does not list the Client as a valid
                    audience, or if it contains additional audiences not trusted by the Client.
                """
                raise ValueError('Issuer does not match')

            if decoded_token['aud'] != self.config.client_id:
                raise ValueError('Audience does not match client_id')

            """ Step 6 : TLS server validation not implemented by Okta       
                If ID Token is received via direct communication between Client and Token Endpoint,
                TLS server validation may be used to validate the issuer in place of checking token
                signature. MUST validate according to JWS algorithm specialized in JWT alg Header.
                MUST use keys provided.
            """

            """ Step 7
                The alg value SHOULD default to RS256 or sent in id_token_signed_response_alg param during Registration
                
                We don't need to test this. Okta always signs in RS256
            """

            """ Step 8 : Not implemented due to Okta configuration
    
                If JWT alg Header uses MAC based algorithm (HS256, HS384, etc) the octets of UTF-8 of the
                client_secret corresponding to the client_id are contained in the aud (audience) are
                used to validate the signature. For MAC based, if aud is multi-valued or if azp value
                is different than aud value - behavior is unspecified.
            """

            if decoded_token['exp'] < int(time.time()):
                """ Step 9
                    The current time MUST be before the time represented by exp
                """

                raise ValueError('Token has expired')

            if decoded_token['iat'] < (int(time.time()) - 100000):
                """ Step 10 - Defined 'too far away time' : approx 24hrs
                    The iat can be used to reject tokens that were issued too far away from current time,
                    limiting the time that nonces need to be stored to prevent attacks. 
                """

                raise ValueError('iat too far in the past ( > 1 day)')

            if nonce is not None:
                """ Step 11
                    If a nonce value is sent in the Authentication Request, a nonce MUST be present and be
                    the same value as the one sent in the Authentication Request. Client SHOULD check for nonce value
                    to prevent replay attacks.
                """
                if nonce != decoded_token['nonce']:
                    raise ValueError('nonce value does not match Authentication Request nonce')

            """ Step 12:  Not implemented by Okta            
                If acr was requested, check that the asserted Claim Value is appropriate
            """

            """ Step 13
                If auth_time was requested, check claim value and request re-authentication if too much time elapsed
                
                We relax this requirement during jwt validation. The Okta Session should be 
                handled inside Okta - See https://developer.okta.com/docs/api/resources/sessions
            """
            print("Decodedd token=====%s",decoded_token)

            return decoded_token

        except ValueError as err:
            print("inn validation errorr")
            return err
