import os
import boto3
import globus_sdk
from portal import app
from flask import request
from threading import Lock
from funcx import FuncXClient
from botocore.exceptions import ClientError
from funcx.sdk.web_client import FuncxWebClient
from globus_sdk.scopes import AuthScopes, SearchScopes

try:
    from urllib.parse import urlparse, urljoin
except ImportError:
    from urlparse import urlparse, urljoin

FL_TAG = '__FLAAS'

# For local test purposes, where all the access key are configured using awscli
s3 = boto3.client('s3')
ecs = boto3.client('ecs')
dynamodb = boto3.resource('dynamodb')
dynamodb_table = dynamodb.Table('appfl-tasks')
# Hard code for ECS information
ECS_CLUSTER = 'flaas-anl-test-cluster' 

class FuncXLoginManager:
    """Implements the funcx.sdk.login_manager.protocol.LoginManagerProtocol class."""
    def __init__(self, authorizers):
        self.authorizers = authorizers

    def get_auth_client(self) -> globus_sdk.AuthClient:
        return globus_sdk.AuthClient(
            authorizer=self.authorizers[AuthScopes.openid]
        )

    def get_search_client(self) -> globus_sdk.SearchClient:
        return globus_sdk.SearchClient(
            authorizer=self.authorizers[SearchScopes.all]
        )

    def get_funcx_web_client(self, *, base_url: str) -> FuncxWebClient:
        return FuncxWebClient(
            base_url=base_url,
            authorizer=self.authorizers[FuncXClient.FUNCX_SCOPE],
        )

    def ensure_logged_in(self):
        return True

    def logout(self):
        print("logout cannot be invoked from here!")

def s3_get_download_link(bucket_name, key_name):
    """Obtain a link from AWS for downloading a file in S3 bucket."""
    return s3.generate_presigned_url('get_object', Params={'Bucket': bucket_name, 'Key': key_name})

def s3_download(bucket_name, key_name, file_folder, file_name):
    """
    Download file with `key_name` from S3 bucket `bucket_name`, and store it locally to `file_name`.
    Return true if the file exists and gets downloaded successfully, return false otherwise.
    """
    try:
        if not os.path.exists(file_folder):
            os.makedirs(file_folder)
        s3.download_file(Bucket=bucket_name, Key=key_name, Filename=os.path.join(file_folder, file_name))
        return True
    except Exception as e:
        print(e)
        return False
    
def s3_upload(bucket_name, key_name, file_name, delete_local=True):
    """
    Upload the local file with name `file_name` to the S3 bucket `bucket_name` and save it as `key_name`.
    User can choose whether to delete the uploaded local file by specifying `delete_local`
    """
    try:
        s3.upload_file(Filename=file_name, Bucket=bucket_name, Key=key_name)
        if delete_local:
            os.remove(file_name)
        return True
    except Exception as e:
        print(e)
        return False
    
def get_funcx_client(tokens):
    """Obtain a funcx client for the authenticated user using the returned login token."""
    # Obtain tokens from the input tokens
    openid_token = tokens['auth.globus.org']['access_token']
    search_token = tokens['search.api.globus.org']['access_token']
    funcx_token = tokens['funcx_service']['access_token']

    # Create authorizers from existing tokens
    funcx_auth = globus_sdk.AccessTokenAuthorizer(funcx_token)
    search_auth = globus_sdk.AccessTokenAuthorizer(search_token)
    openid_auth = globus_sdk.AccessTokenAuthorizer(openid_token)

    # Create a new login manager and use it to create a client
    funcx_login_manager = FuncXLoginManager(
        authorizers={FuncXClient.FUNCX_SCOPE: funcx_auth,
                    SearchScopes.all: search_auth,
                    AuthScopes.openid: openid_auth}
    )

    fxc = FuncXClient(login_manager=funcx_login_manager)
    return fxc

def ecs_run_task(cmd):
    response = ecs.run_task(
        cluster='flaas-anl-test-cluster',
        taskDefinition='pytest2-task-def-3',
        count=1,
        launchType='FARGATE',
        networkConfiguration={
            'awsvpcConfiguration': {
                'subnets': ['subnet-0ae916ead3118ec21', 'subnet-0c88864adf8950099', 'subnet-023d1cdc4f0bc871a', 'subnet-0285ff6457e1fbe35', 'subnet-06d99e5eaad06ad79', 'subnet-06ac227a962b9bfde'],
                
                'assignPublicIp': 'ENABLED'
            }
        },
        overrides = {
            'containerOverrides': [{
                'name': 'pytest2',
                'command': cmd,
            }]
        }
    )
    return response['tasks'][0]['taskArn']

def ecs_task_status(task_arn):
    """Return the status, """
    response = ecs.describe_tasks(cluster=ECS_CLUSTER, tasks=[task_arn])
    try:
        task = response['tasks'][0]
        status = task['containers'][0]['lastStatus']
    except:
        status = 'FINISHED'
        starttime = ""
        endtime = ""
        return status, starttime, endtime
    if status == 'PENDING':
        starttime = ""
        endtime = ""
    elif status == 'RUNNING':
        try:
            starttime = task['createdAt'].strftime("%Y-%m-%d %H:%M:%S")
        except:
            starttime = ""
        endtime = ""
    else:
        try:
            starttime = task['createdAt'].strftime("%Y-%m-%d %H:%M:%S")
        except:
            starttime = ""
        try:
            endtime = task['executionStoppedAt'].strftime("%Y-%m-%d %H:%M:%S")
        except:
            endtime = ""
    return status, starttime, endtime

def ecs_arn2id(task_arn):
    """Convert the ARN of ECS task into ID"""
    return task_arn.split('/')[-1]

def dynamodb_get_tasks(group_id):
    """Return all the task ids for the certain group"""
    try:
        response = dynamodb_table.get_item(Key={'group-id': group_id})
    except ClientError as err:
        print(
            "Couldn't get tasks for group %s from table %s. Here's why: %s: %s" %(\
            group_id, dynamodb_table.name, \
            err.response['Error']['Code'], err.response['Error']['Message']))
        raise
    else:
        if not 'Item' in response:
            print('Tasks not found for group %s' %(group_id))
            return None
        return response['Item']['task-ids']

def dynamodb_append_task(group_id, task_id):
    """Add one task to a certain group"""
    try:
        dynamodb_table.update_item(
            Key={'group-id': group_id},
            UpdateExpression='set #t = list_append(#t, :val)',
            ExpressionAttributeNames={'#t': 'task-ids'},
            ExpressionAttributeValues={":val": [task_id]}
        )
        return True
    except ClientError as err:
        try: 
            dynamodb_table.put_item(Item={'group-id': group_id, 'task-ids': [task_id]})
            return True
        except ClientError as err:
            print(
                "Couldn't get tasks for group %s from table %s. Here's why: %s: %s" %(\
                group_id, dynamodb_table.name, \
                err.response['Error']['Code'], err.response['Error']['Message']))
            return False

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
