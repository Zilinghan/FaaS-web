import os
import boto3
import globus_sdk
from portal import app
from threading import Lock
from funcx import FuncXClient
from datetime import datetime, timedelta
from flask import request, render_template, redirect, flash
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
log = boto3.client('logs')
dynamodb = boto3.resource('dynamodb')
dynamodb_table = dynamodb.Table('appflx-tasks')
# Hard code for ECS information
ECS_CLUSTER = 'appflx-cluster' 
ECS_TASK_DEF = 'appflx-fl-server'
ECS_IMAGE_NAME = 'flserver'
S3_BUCKET_NAME = 'appflx-bucket' 

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

def training_data_preprocessing(data):
    """
    Preprocess the yaml training metrics to desired format.
    TODO: see what can be changed later...
    """
    def remove_decimal(dt_string):
        return dt_string.split('.')[0]
    data_processed = []
    for item in data:
        processed_item = item.copy()
        processed_item['start_at'] = remove_decimal(item['start_at'])
        processed_item['end_at'] = remove_decimal(item['end_at'])
        start_time = datetime.strptime(item['start_at'], '%Y-%m-%d %H:%M:%S.%f')
        end_time = datetime.strptime(item['end_at'], '%Y-%m-%d %H:%M:%S.%f')
        processed_item['duration'] = f'{(end_time-start_time).total_seconds():.2f}'
        processed_item['timing'] = {}
        for event, event_value in item['timing'].items():
            if isinstance(event_value, dict):
                for event_child, event_child_value in event_value.items():
                    processed_item['timing'][f'{event}-{event_child}'] = event_child_value
            else:
                processed_item['timing'][event] = event_value
        data_processed.append(processed_item)
    return data_processed

def val_test_data_preprocessing(data):
    """
    Preprocess the json validation and test data to desired format
    TODO: see what can be changed later...
    """
    client_validation = []
    server_validation = []
    client_test = []
    server_test = []
    for endpoint_info in data['val']['clients']:
        for endpoint_name in endpoint_info:
            client_validation.append({
                'endpoint': endpoint_name,
                'step': endpoint_info[endpoint_name]['step'],
                'loss': f"{endpoint_info[endpoint_name]['val_loss']:.4f}",
                'accuracy': f"{endpoint_info[endpoint_name]['val_acc']:.3f}"
            })
    for server_info in data['val']['server']:
        if server_info['acc'] == 0.0 and server_info['loss'] == 0.0:
            server_validation= []
            break
        else:
            server_validation.append({
                'step': server_info['step'],
                'loss': f"{server_info['loss']:.4f}",
                'accuracy': f"{server_info['acc']:.3f}"
            })
    # TODO: how to deal with the test data: currently I don't have sample data 
    return client_validation, server_validation, client_test, server_test

def hp_data_preprocessing(data):
    """
    Preprocess the hyperparameter data to desired format
    TODO: see what can be changed later...
    """
    hp_data = {}
    # TODO: Change this if more algorithms are integrated
    fed_alg_dict = {
        'ServerFedAvg': 'Federated Average',
        'ServerFedAvgMomentum': 'Federated Average Momentum',
        'ServerFedAdagrad': 'Federated Adagrad',
        'ServerFedAdam': 'Federated Adam',
        'ServerFedYogi': 'Federated Yogi',
        'ServerFedAsynchronous': 'Federated Asynchronous'
    }
    fed_alg = data['algorithm']['servername']
    hp_data['fed_alg'] = fed_alg_dict[fed_alg]
    hp_data['exp_name'] = data['dataset']['name']
    hp_data['server_epoch'] = data['training']['num_epochs']
    hp_data['client_epoch'] = data['algorithm']['args']['num_local_epochs']
    hp_data['privacy_budget'] = data['algorithm']['args']['epsilon']
    hp_data['clip_value'] = data['algorithm']['args']['clip_value']
    hp_data['clip_norm'] = data['algorithm']['args']['clip_norm']
    if fed_alg == 'ServerFedAvgMomentum':
        hp_data['server_mom'] = data['algorithm']['args']['server_momentum_param_1']
    elif fed_alg == 'ServerFedAdagrad':
        hp_data['server_mom']   = data['algorithm']['args']['server_momentum_param_1']
        hp_data['server_lr']    = data['algorithm']['args']['server_learning_rate']
        hp_data['server_adapt'] = data['algorithm']['args']['server_adapt_param']
    elif fed_alg == 'ServerFedAdam' or fed_alg == 'ServerFedYogi':
        hp_data['server_mom']     = data['algorithm']['args']['server_momentum_param_1']
        hp_data['server_lr']      = data['algorithm']['args']['server_learning_rate']
        hp_data['server_adapt']   = data['algorithm']['args']['server_adapt_param']
        hp_data['server_var_mom'] = data['algorithm']['args']['server_momentum_param_2']
    elif fed_alg == 'ServerFedAsynchronous':
        hp_data['server_mix_param'] = data['algorithm']['args']['alpha']
        hp_data['reg_strength'] = data['algorithm']['args']['rho']
        sta_func = data['algorithm']['args']['staness_func']['name']
        hp_data['staleness_func'] = sta_func
        if sta_func == 'polynomial':
            hp_data['parameter_a'] = data['algorithm']['args']['staness_func']['args']['a']
        elif sta_func == 'hinge':
            hp_data['parameter_a'] = data['algorithm']['args']['staness_func']['args']['a']
            hp_data['parameter_b'] = data['algorithm']['args']['staness_func']['args']['b']
    hp_data['optimizer'] = data['algorithm']['args']['optim']
    hp_data['lr'] = data['algorithm']['args']['optim_args']['lr']
    hp_data['lr_decay'] = data['algorithm']['args']['server_lr_decay_exp_gamma']
    hp_data['client_weights'] = data['algorithm']['args']['client_weights']
    if 'model_type' in data:
        hp_data['model_type'] = data['model_type']
        hp_data['model_params'] = data['model']
    else:
        # TODO: Generate a download link for the custom model file
        pass
    return hp_data

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

def s3_get_download_link(bucket_name, key_name):
    """Obtain a link from AWS for downloading a file in S3 bucket."""
    return s3.generate_presigned_url('get_object', Params={'Bucket': bucket_name, 'Key': key_name})

def s3_download(bucket_name, key_name, file_folder, file_name):
    """
    Download file with `key_name` from S3 bucket `bucket_name`, and store it locally to `file_folder/file_name`.
    Return true if the file exists and gets downloaded successfully, return false otherwise.
    """
    try:
        if not os.path.exists(file_folder):
            os.makedirs(file_folder)
        s3.download_file(Bucket=bucket_name, Key=key_name, Filename=os.path.join(file_folder, file_name))
        return True
    except Exception as e:
        print(f'S3 Download Error: {e}')
        return False

def s3_download_folder(bucket_name, key_folder, file_folder):
    """
    Download all the files in the S3 folder `key_folder` from S3_bucker `bucket_name` and store it locally to `file_folder`.
    Return true if the `key_folder` exists, return false otherwise.
    """
    try:
        if not os.path.exists(file_folder):
            os.makedirs(file_folder)
        objects = s3.list_objects_v2(Bucket=bucket_name, Prefix=key_folder)
        if not 'Contents' in objects:
            return False
        if len(objects['Contents']) == 0:
            return False
        for obj in objects['Contents']:
            # Check if the object is a file (i.e., not a subfolder)
            if not obj['Key'].endswith('/'):
                # Download the file to the file folder
                file_name = os.path.basename(obj['Key'])
                s3.download_file(Bucket=bucket_name, Key=obj['Key'], Filename=os.path.join(file_folder, file_name))
        return True
    except Exception as e:
        print(e)
        return False

def s3_delete_folder(bucket_name, key_folder):
    """Delete every file in the `key_folder` of S3 bucket with name `bucket_name`."""
    try:
        objects = s3.list_objects_v2(Bucket=bucket_name, Prefix=key_folder)
        if 'Contents' not in objects: return
        if len(objects['Contents']) == 0: return
        objects = objects['Contents']
        delete_objects = [{'Key': obj['Key']} for obj in objects]
        if delete_objects:
            s3.delete_objects(Bucket=bucket_name, Delete={'Objects': delete_objects})
            print('Objects deleted successfully on S3.')
        # Delete the folder itself (optional)
        s3.delete_object(Bucket=bucket_name, Key=key_folder.rstrip('/') + '/')
    except Exception as e:
        print(f"Error occurs in deleting S3 bucket {bucket_name} folder {key_folder}: {e}")

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
        print(f'S3 Upload Error: {e}')
        return False

def ecs_run_task(cmd):
    response = ecs.run_task(
        cluster=ECS_CLUSTER,
        taskDefinition=ECS_TASK_DEF,
        count=1,
        launchType='FARGATE',
        networkConfiguration={
            'awsvpcConfiguration': {
                'subnets': ['subnet-0bfec7d4ab40ce975', 
                            'subnet-045cc8ea2cd9ba216', 
                            'subnet-07396ea53e7cdb3e0', 
                            'subnet-0c531ab49624e9bb3', 
                            'subnet-0c4b4157fefd0b45d', 
                            'subnet-0c54d032c74a7986a'],
                
                'assignPublicIp': 'ENABLED'
            }
        },
        overrides = {
            'containerOverrides': [{
                'name': ECS_IMAGE_NAME,
                'command': cmd,
            }]
        }
    )
    return response['tasks'][0]['taskArn']

def ecs_task_status(task_arn):
    """
    Return the status of an ECS Task.
    TODO: maybe we can check if the process fails or not.
    """
    response = ecs.describe_tasks(cluster=ECS_CLUSTER, tasks=[task_arn])
    try:
        task = response['tasks'][0]
        status = task['containers'][0]['lastStatus']
        if status == 'STOPPED':
            status = 'DONE'
    except:
        status = 'DONE'
    return status

def ecs_arn2id(task_arn):
    """Convert the ARN of ECS task into ID"""
    return task_arn.split('/')[-1]

def ecs_parse_taskinfo(task_info):
    """Parse a list of task information into task ARN and task/experiment name"""
    task_arns, task_names = [], []
    for info in task_info:
        info_pc = info.split('<EXP_NAME>')
        task_arn = info_pc[0]
        task_name = ""
        for i in range(1, len(info_pc)):
            if i != 1:
                task_name += '<EXP_NAME>'
            task_name += info_pc[i]
        task_arns.append(task_arn)
        task_names.append(task_name)
    return task_arns, task_names

def ecs_task_stop(task_arn):
    """Stop a running ECS task using the task ARN."""
    try:
        ecs.stop_task(cluster=ECS_CLUSTER, task=task_arn)
        print('Task stopped successfully.')
    except Exception as e:
        print(f"Failed to stop the task with error: {e}")

def ecs_task_delete(task_arn, task_group, group_server_id):
    """
    Given task ARN, do the following steps to clean everything related to the task:
        (1) Stop the task if it is not finished 
        (2) Delete the task from the task table in DynamoDB
        (3) Delete everything output files related to this task
    TODO: If we use more task status in the future, remember to update here
    """
    task_status = ecs_task_status(task_arn)
    if task_status != 'DONE':
        ecs_task_stop(task_arn)
    dynamodb_delete_task(task_arn, task_group)
    task_id = ecs_arn2id(task_arn)
    s3_folder = f'{task_group}/{group_server_id}/{task_id}'
    s3_delete_folder(S3_BUCKET_NAME, s3_folder)
    print(f"Everything for task {task_id} is cleaned successfully")
    
def dynamodb_delete_task(task_arn, group_id):
    """Delete the task arn from the group in the DynamoDB task table."""
    try:
        task_arns = dynamodb_get_tasks(group_id)
        updated_task_arns = [arn for arn in task_arns if not str(arn).startswith(task_arn)]
        dynamodb_table.update_item(
            Key={'group-id': group_id},
            UpdateExpression='set #t = :updated_list',
            ExpressionAttributeNames={'#t': 'task-ids'},
            ExpressionAttributeValues={':updated_list': updated_task_arns}
        )
        print(f"Task deleted succesfully in DynamoDB table")
    except Exception as e:
        print(f"Error in deleting task in DynamoDB: {e}")

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
            return []
        return response['Item']['task-ids']

def dynamodb_append_task(group_id, task_id, exp_name):
    """Add one task to a certain group"""
    try:
        dynamodb_table.update_item(
            Key={'group-id': group_id},
            UpdateExpression='set #t = list_append(#t, :val)',
            ExpressionAttributeNames={'#t': 'task-ids'},
            ExpressionAttributeValues={":val": [f'{task_id}<EXP_NAME>{exp_name}']}
        )
        return True
    except ClientError as err:
        try: 
            dynamodb_table.put_item(Item={'group-id': group_id, 'task-ids': [f'{task_id}<EXP_NAME>{exp_name}']})
            return True
        except ClientError as err:
            print(
                "Couldn't get tasks for group %s from table %s. Here's why: %s: %s" %(\
                group_id, dynamodb_table.name, \
                err.response['Error']['Code'], err.response['Error']['Message']))
            return False
        
def _s3_get_log(group_id, user_id, task_id):
    # If nothing in the log contents, obtain the log from S3 bucker
    log_key    = f'{group_id}/{user_id}/{task_id}/log_server.log'
    log_folder = os.path.join(app.config['UPLOAD_FOLDER'], group_id, user_id)
    log_name   = 'log_server.log'
    if s3_download(S3_BUCKET_NAME, log_key, log_folder, log_name):
        log_file = os.path.join(log_folder, log_name)
        print(log_file)
        if os.path.isfile(log_file):
            with open(log_file) as f:
                log_contents = [line for line in f]
    else:
        log_contents = []
        print("Nothing from S3....")
    return log_contents

def aws_get_log(task_id, user_id, group_id, referrer):
    """Return the log file for certain task either from AWS clouldwatch or S3 stored log file"""
    log_group_name  = f'/ecs/{ECS_TASK_DEF}'
    log_stream_name = f'ecs/{ECS_IMAGE_NAME}/{task_id}'
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=100.0) # TODO: now we only supports log 100 days ago
    resp = log.get_log_events(
        logGroupName=log_group_name,
        logStreamName=log_stream_name,
        startTime=int(start_time.timestamp() * 1000),
        endTime=int(end_time.timestamp() * 1000)
    )
    s3_downloaded = False
    try:
        log_contents = [event['message'] for event in resp['events']]
    except:
        print("Nothing from cloud watch....")
        log_contents = _s3_get_log(group_id, user_id, task_id)
        s3_downloaded = True
    if not s3_downloaded and len(log_contents) == 0:
        log_contents = _s3_get_log(group_id, user_id, task_id)
    if len(log_contents) == 0:
        flash("There is currently no log for this federation!")
        return redirect(referrer)
    
    return render_template('log.jinja2', log_contents=log_contents)

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
