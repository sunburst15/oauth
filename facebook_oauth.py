
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
        return '[FacebookOAuthError] cause: ' + repr(self.cause)


def get_app_id_and_secret(client_secret_file):
    '''01. Get client id from the given secret file.
    '''
    app = json.loads(open(client_secret_file,'r').read())
    return app['web']['app_id'], app['web']['app_secret']


def get_token_from_auth_code(auth_code, app_id, app_secret):
    '''02. Convert the authorization code to long-term token.
    '''
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, auth_code)

    result = httplib2.Http().request(url, 'GET')[1]
    # remove expire tag from access token
    return result.split("&")[0]


def get_user_info(token):
    '''03. get user info as json
    '''
    # you should list all the fields that you want to retrieve.
    url = "https://graph.facebook.com/v2.2/me?%s&fields=name,email,id" % token
    return json.loads(httplib2.Http().request(url, 'GET')[1])


def get_user_picture(token):
    '''04. get user picture
    '''
    url = "https://graph.facebook.com/v2.2/me/picture?%s&redirect=0&height=200&width=200" % token
    return json.loads(httplib2.Http().request(url, 'GET')[1])['data']['url']


def revoke_access(facebook_id):
    '''05. revoke the existing access token
    '''
    url = 'https://graph.facebook.com/%s/permissions' % facebook_id
    return json.loads(httplib2.Http().request(url, 'DELETE')[1])


