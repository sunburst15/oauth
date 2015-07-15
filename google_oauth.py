
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import requests
import json
import httplib2

class OAuthError(Exception):
    '''Error class for the google OAuth flow.
    '''
    def __init__(self, cause):
        self.cause = cause

    def __str__(self):
        return '[GoogleOAuthError] cause: ' + repr(self.cause)


def get_client_id(client_secret_file):
    '''01. Get client id from the given secret file.
    '''
    return json.loads(open(client_secret_file,'r').read())['web']['client_id']


def get_credential_from_auth_code(auth_code, client_secret_file, redirect_uri):
    '''02. Convert the authorization code to credentials.
    Inside the credential, there is the access token.
    '''
    try:
        oauth_flow = flow_from_clientsecrets(client_secret_file,scope='')
        oauth_flow.redirect_uri = redirect_uri
        return oauth_flow.step2_exchange(auth_code)
    except FlowExchangeError as e:
        raise OAuthError(e)


def get_access_token_info(access_token):
    '''03. using the given access token, returns the token info as json
    '''
    url = 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
    url = url % access_token
    return json.loads(httplib2.Http().request(url, 'GET')[1])


def get_user_info(access_token):
    '''04. get user info as json
    '''
    url = "https://www.googleapis.com/oauth2/v1/userinfo?access_token=%s&alt=json"
    url = url % access_token
    return json.loads(httplib2.Http().request(url, 'GET')[1])


def revoke_access_token(access_token, revoke_uri):
    '''05. revoke the existing access token
    '''
    if revoke_uri == None:
        revoke_uri = "https://accounts.google.com/o/oauth2/revoke"
    url = revoke_uri + '?token=%s'
    url = url % access_token
    response = httplib2.Http().request(url, 'GET')
    if response[0]['status'] == '200':
        return response[0]
    else:
        result = json.loads(response[1])
        result['status'] = response[0]['status']
        return result


