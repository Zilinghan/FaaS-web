from flask import request
from threading import Lock

import globus_sdk

try:
    from urllib.parse import urlparse, urljoin
except ImportError:
    from urlparse import urlparse, urljoin

from portal import app

FL_TAG = '__FLAAS'

def load_portal_client():
    """Create an AuthClient for the portal"""
    return globus_sdk.ConfidentialAppAuthClient(
        app.config['PORTAL_CLIENT_ID'], app.config['PORTAL_CLIENT_SECRET'])

def load_group_client(authorizer):
    """Create a GroupClient for getting group information."""
    return globus_sdk.GroupsClient(authorizer=globus_sdk.AccessTokenAuthorizer(authorizer))

def group_tagging(group_name):
    """Add a tag to the group name is there is no tag before to indicate that this is a group for FL."""
    if group_name[max(0, len(group_name)-len(FL_TAG)):] != FL_TAG:
        group_name += FL_TAG
    return group_name

def get_servers_clients(all_groups):
    servers = []
    clients = []
    for group in all_groups:
        if group['name'][max(0, len(group['name'])-len(FL_TAG)):] == FL_TAG:
            group['name'] = group['name'][:len(group['name'])-len(FL_TAG)]
            is_server = False
            for member in group['my_memberships']:
                if member['role'] in ['admin', 'manager']:
                    is_server = True
                    break
            if is_server:
                servers.append(group)
            # TODO: Check if this is a correct design decision: an APPFL server himself is also an APPFL client
            clients.append(group)
            # else:
            #     clients.append(group)
    return servers, clients

def is_safe_redirect_url(target):
    """https://security.openstack.org/guidelines/dg_avoid-unvalidated-redirects.html"""  # noqa
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))

    return redirect_url.scheme in ('http', 'https') and \
        host_url.netloc == redirect_url.netloc


def get_safe_redirect():
    """https://security.openstack.org/guidelines/dg_avoid-unvalidated-redirects.html"""  # noqa
    url = request.args.get('next')
    if url and is_safe_redirect_url(url):
        return url

    url = request.referrer
    if url and is_safe_redirect_url(url):
        return url

    return '/'


def get_portal_tokens(
        scopes=['openid', 'urn:globus:auth:scope:demo-resource-server:all', 'urn:globus:auth:scope:demo-resource-server:all[https://auth.globus.org/scopes/' + app.config['GRAPH_ENDPOINT_ID'] + '/https]']):
    """
    Uses the client_credentials grant to get access tokens on the
    Portal's "client identity."
    """
    with get_portal_tokens.lock:
        if not get_portal_tokens.access_tokens:
            get_portal_tokens.access_tokens = {}

        scope_string = ' '.join(scopes)

        client = load_portal_client()
        tokens = client.oauth2_client_credentials_tokens(
            requested_scopes=scope_string)

        # walk all resource servers in the token response (includes the
        # top-level server, as found in tokens.resource_server), and store the
        # relevant Access Tokens
        for resource_server, token_info in tokens.by_resource_server.items():
            get_portal_tokens.access_tokens.update({
                resource_server: {
                    'token': token_info['access_token'],
                    'scope': token_info['scope'],
                    'expires_at': token_info['expires_at_seconds']
                }
            })

        return get_portal_tokens.access_tokens


get_portal_tokens.lock = Lock()
get_portal_tokens.access_tokens = None
