import os
import yaml
import time
import funcx
import requests
import globus_sdk
import importlib.util
import multiprocessing
from enum import Enum
from datetime import datetime
from funcx import FuncXClient
from tensorboard import program
from portal import app, database, datasets
from portal.decorators import authenticated
from flask import (abort, flash, redirect, render_template, request, session, url_for)
from globus_sdk import (RefreshTokenAuthorizer, TransferAPIError, TransferClient, TransferData)
from portal.utils import (get_portal_tokens, get_safe_redirect, group_tagging, get_servers_clients, \
                          load_portal_client, load_group_client, \
                          s3_download, s3_upload, s3_get_download_link, \
                          ecs_run_task, ecs_task_status, ecs_arn2id, \
                          dynamodb_get_tasks, dynamodb_append_task, get_funcx_client)
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

S3_BUCKET_NAME = 'flaas-anl-test' 
STATUS_CHECK_TIMES = 5

@app.route('/', methods=['GET'])
def home():
    """Home page"""
    return render_template('home.jinja2')


@app.route('/signup', methods=['GET'])
def signup():
    """Send the user to Globus Auth with signup=1."""
    return redirect(url_for('authcallback', signup=1))


@app.route('/login', methods=['GET'])
def login():
    """Send the user to Globus Auth."""
    return redirect(url_for('authcallback'))


@app.route('/logout', methods=['GET'])
@authenticated
def logout():
    """
    - Revoke the tokens with Globus Auth.
    - Destroy the session state.
    - Redirect the user to the Globus Auth logout page.
    """
    client = load_portal_client()

    # Revoke the tokens with Globus Auth
    for token, token_type in (
            (token_info[ty], ty)
            # get all of the token info dicts
            for token_info in session['tokens'].values()
            # cross product with the set of token types
            for ty in ('access_token', 'refresh_token')
            # only where the relevant token is actually present
            if token_info[ty] is not None):
        client.oauth2_revoke_token(
            token, body_params={'token_type_hint': token_type})

    # Destroy the session state
    session.clear()

    redirect_uri = url_for('home', _external=True)

    ga_logout_url = []
    ga_logout_url.append(app.config['GLOBUS_AUTH_LOGOUT_URI'])
    ga_logout_url.append('?client={}'.format(app.config['PORTAL_CLIENT_ID']))
    ga_logout_url.append('&redirect_uri={}'.format(redirect_uri))
    ga_logout_url.append('&redirect_name=Globus Sample Data Portal')

    # Redirect the user to the Globus Auth logout page
    return redirect(''.join(ga_logout_url))


@app.route('/profile', methods=['GET', 'POST'])
@authenticated
def profile():
    """User profile information. Assocated with a Globus Auth identity."""
    if request.method == 'GET':
        identity_id = session.get('primary_identity')
        profile = database.load_profile(identity_id)

        if profile:
            name, email, institution = profile

            session['name'] = name
            session['email'] = email
            session['institution'] = institution
        else:
            flash(
                'Please complete any missing profile fields and press Save.')

        if request.args.get('next'):
            session['next'] = get_safe_redirect()

        return render_template('profile.jinja2')
    elif request.method == 'POST':
        name = session['name'] = request.form['name']
        email = session['email'] = request.form['email']
        institution = session['institution'] = request.form['institution']

        database.save_profile(identity_id=session['primary_identity'],
                              name=name,
                              email=email,
                              institution=institution)

        flash('Thank you! Your profile has been successfully updated.')

        if 'next' in session:
            redirect_to = session['next']
            session.pop('next')
        else:
            redirect_to = url_for('profile')

        return redirect(redirect_to)


@app.route('/authcallback', methods=['GET'])
def authcallback():
    """Handles the interaction with Globus Auth."""
    # If we're coming back from Globus Auth in an error state, the error
    # will be in the "error" query string parameter.
    if 'error' in request.args:
        flash("You could not be logged into the portal: " +
              request.args.get('error_description', request.args['error']))
        return redirect(url_for('home'))

    # Set up our Globus Auth/OAuth2 state
    redirect_uri = url_for('authcallback', _external=True)

    client = load_portal_client()
    client.oauth2_start_flow(
        redirect_uri,
        refresh_tokens=True,
        requested_scopes=app.config['USER_SCOPES']
    )

    # If there's no "code" query string parameter, we're in this route
    # starting a Globus Auth login flow.
    print(request.args)
    if 'code' not in request.args:
        additional_authorize_params = (
            {'signup': 1} if request.args.get('signup') else {})

        auth_uri = client.oauth2_get_authorize_url(
            query_params=additional_authorize_params)
        return redirect(auth_uri)
    else:
        # If we do have a "code" param, we're coming back from Globus Auth
        # and can start the process of exchanging an auth code for a token.
        code = request.args.get('code')
        tokens = client.oauth2_exchange_code_for_tokens(code)
        id_token = tokens.decode_id_token()
        session.update(
            tokens=tokens.by_resource_server,
            is_authenticated=True,
            name=id_token.get('name'),
            email=id_token.get('email'),
            institution=id_token.get('organization'),
            primary_username=id_token.get('preferred_username'),
            primary_identity=id_token.get('sub'),
        )
        print(session['tokens'])

        profile = database.load_profile(session['primary_identity'])

        if profile:
            name, email, institution = profile

            session['name'] = name
            session['email'] = email
            session['institution'] = institution
        else:
            return redirect(url_for('profile',
                            next=url_for('dashboard')))

        return redirect(url_for('dashboard'))


def get_endpoint_information(members, group_id):
    """
    Check if the APPFL clients in the group have uploaded their endpoint information
    Inputs:
        - members: list of group membership information
        - group_id: Globus group id
    Outputs:
        - user_names: list of names of group members
        - user_emails: list of emails of group emails
        - user_endpoint: list of funcx endpoints provided by group members
    """
    user_names, user_emails, user_orgs, user_endpoints = [], [], [], []
    for member in members:
        user_id = member['identity_id']
        # TODO: Check if this is a correct design decision: an APPFL server himself is also an APPFL client
        # if user_id == session.get('primary_identity'): continue

        # Obtain user names and emails
        if member['status'] != 'active': continue
        try:
            user_names.append(member['membership_fields']['name'])
        except:
            if user_id == session.get('primary_identity'):
                user_names.append(f"{session.get('name')} (You)")
            else:
                user_names.append(member['username'])
        try:
            user_emails.append(member['membership_fields']['email'])
        except:
            if user_id == session.get('primary_identity'):
                user_emails.append(session.get('email'))
            else:
                user_emails.append("NONE") # TODO: how to deal with a user without any valid email?
        try:
            user_orgs.append(member['membership_fields']['organization'])
        except:
            if user_id == session.get('primary_identity'):
                user_orgs.append(f"{session.get('institution')}")
            else:
                user_orgs.append("")
        # Obtain user endpoints
        client_config_folder = os.path.join(app.config['UPLOAD_FOLDER'], group_id, user_id)
        client_config_key    = f'{group_id}/{user_id}/client.yaml'
        if s3_download(S3_BUCKET_NAME, client_config_key, client_config_folder, 'client.yaml'):
            with open(os.path.join(client_config_folder, 'client.yaml')) as f:
                data = yaml.safe_load(f)
            user_endpoints.append(data['client']['endpoint_id'])
            # TODO: Do we need to destroy the file?? 
            # -- Probably...especially if we want to do load balancing, we want it to be stateless
            os.remove(os.path.join(client_config_folder, 'client.yaml'))
        else:
            user_endpoints.append('0')
        # if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], group_id, user_id, 'client.yaml')):
        #     with open(os.path.join(app.config['UPLOAD_FOLDER'], group_id, user_id, 'client.yaml')) as f:
        #         data = yaml.safe_load(f)
        #     user_endpoints.append(data['client']['endpoint_id'])
        # else:
        #     print(os.path.join(app.config['UPLOAD_FOLDER'], group_id, user_id, 'client.yaml'))
        #     print(member)
        #     user_endpoints.append('0')
    print(user_endpoints)
    return user_names, user_emails, user_orgs, user_endpoints


@app.route('/browse/server/<server_group_id>', methods=['GET'])
@app.route('/browse/client/<client_group_id>', methods=['GET'])
@authenticated
def browse_config(server_group_id=None, client_group_id=None):
    """
    Load the APPFL server/client configuration page
    Inputs:
        - server_group_id: Globus group ID for the APPFL server 
        - client_group_id: Globus group ID for the APPFL client 
        Note: two inputs are mutually exclusive
    """
    gc = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
    if server_group_id is not None:
        server_group = gc.get_group(server_group_id, include=["memberships"])
        client_names, client_emails, client_orgs, client_endpoints = get_endpoint_information(server_group['memberships'], server_group_id)
        return render_template('server.jinja2', \
                               server_group_id=server_group_id, \
                               client_names=client_names, \
                               client_endpoints=client_endpoints, \
                               client_emails=client_emails, \
                               client_orgs=client_orgs)
    if client_group_id is not None:
        client_group = gc.get_group(client_group_id)
        return render_template('client.jinja2', client_group=client_group, client_group_id=client_group_id)
    return render_template('dashboard.jinja2')

@app.route('/browse/server-info/<server_group_id>', methods=['GET'])
@app.route('/browse/client-info/<client_group_id>', methods=['GET'])
def browse_info(server_group_id=None, client_group_id=None):
    """
    Load the APPFL server/client information page
    Inputs:
        - server_group_id: Globus group ID for the APPFL server 
        - client_group_id: Globus group ID for the APPFL client 
        Note: two inputs are mutually exclusive
    """
    gc = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
    if server_group_id is not None:
        task_arns = dynamodb_get_tasks(server_group_id)
        task_ids = [ecs_arn2id(task_arn) for task_arn in task_arns]
        print(task_arns)
        print(task_ids)
        server_group = gc.get_group(server_group_id, include=["memberships"])
        client_names, client_emails, client_orgs, client_endpoints = get_endpoint_information(server_group['memberships'], server_group_id)
        return render_template('server_info.jinja2', \
                                server_group_id=server_group_id, \
                                client_names=client_names, \
                                client_endpoints=client_endpoints, \
                                client_emails=client_emails, \
                                client_orgs=client_orgs, \
                                task_ids=task_ids,
                                task_arns=task_arns)
    if client_group_id is not None:
        return render_template('client_info.jinja2', client_group_id=client_group_id)

@app.route('/download/<file_type>/<client_group_id>', methods=['GET'])
def download_file(file_type="", client_group_id=None):
    if file_type == "dataloader" and client_group_id is not None:
        return redirect(s3_get_download_link(S3_BUCKET_NAME, f'{client_group_id}/{session["primary_identity"]}/dataloader.py'))
    pass

@app.route('/get-client-info', methods=['GET'])
def get_client_info():
    client_info = {}
    client_group_id = request.args['client_group_id']
    client_info_key    = f'{client_group_id}/{session["primary_identity"]}/client.yaml'
    client_info_folder = os.path.join(app.config['UPLOAD_FOLDER'], client_group_id, session.get('primary_identity'))
    client_info_name   = 'client.yaml'
    if s3_download(S3_BUCKET_NAME, client_info_key, client_info_folder, client_info_name):
        with open(os.path.join(client_info_folder, client_info_name)) as f:
            data = yaml.safe_load(f)
            client_info = data['client']
        os.remove(os.path.join(client_info_folder, client_info_name))
        return client_info
    else:
        abort(404, 'User has not uploaded any configuration.')


@app.route('/dashboard', methods=['GET'])
@authenticated
def dashboard():    
    """Load the dashboard page"""
    try:
        # TODO: An error: when we restart the application and go to the dashboard page after some time, 
        # the group access token may become invalid/expired. Think of some better solution to this.
        gc = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
        all_groups = gc.get_my_groups()
        all_server_groups, all_client_groups = get_servers_clients(all_groups)
        return render_template('dashboard.jinja2', all_server_groups=all_server_groups, all_client_groups=all_client_groups)
    except globus_sdk.services.groups.errors.GroupsAPIError as e:
        # TODO: Check if this error-handling is valid when the error occurs next
        session.update(is_authenticated=False)
        return redirect(url_for('home', next=request.url))


@app.route('/create_server', methods=['GET', 'POST'])
@authenticated
def create_server():    
    """Load the web page for creating a new APPFL server."""
    if request.method == 'GET':
        return render_template('create_server.jinja2')
    if request.method == 'POST':
        if not request.form.get('new-server-group-id'):
            flash('Please enter a group ID.')
            return redirect(url_for('create_server'))
        new_server_group_id = request.form.get('new-server-group-id')
        gc = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
        try:
            new_server_group = gc.get_group(new_server_group_id)
            server_group_name = new_server_group["name"]
            server_group_name_tagged = group_tagging(server_group_name)
            gc.update_group(new_server_group_id, data={'name': server_group_name_tagged})
            flash('The group server %s is successfully created!' % (server_group_name, ))
            return redirect(url_for('create_server'))
        except:
            flash('Error: Please enter a valid group ID.')
            return redirect(url_for('create_server'))

def endpoint_test():
    """Endpoint health status test function."""
    import torch
    return torch.cuda.is_available()

# This function should be deprecated: we need to use container to run APPFL
def run_appfl(group_members, server_id, server_group_id, upload_folder, tokens):
    """
    Start running the APPFL algorithm. 
    TODO: Ideally, we want this function to run in an isolated container with its own file system, etc.
    
    Inputs: 
        - group_members: List of globus ids of members in the APPFL group
        - server_id: Globus id of APPFL server member
        - server_group_id: Globus id of the APPFL group
        - upload_folder: Base folder for storing the user uploaded files
    """
    # Load APPFL module
    spec = importlib.util.spec_from_file_location('funcx-run', 'funcx_server/funcx_sync.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Create funcX client for testing endpoint status
    # fxc = FuncXClient()
    fxc = get_funcx_client(tokens)
    func_id = fxc.register_function(endpoint_test)

    # Load APPFL configurations
    client_configs, dataloaders, server_config = [], [], None
    for user_id in group_members:
        # Download the server configuration from AWS S3
        if user_id == server_id:
            server_config_folder = os.path.join(upload_folder, server_group_id, user_id)
            server_config_key    = f'{server_group_id}/{user_id}/appfl_config.yaml'
            if not s3_download(S3_BUCKET_NAME, server_config_key, server_config_folder, 'appfl_config.yaml'):
                print("Error: Cannot downlaod the APPFL server configuration file from S3 Bucket!")
                return
            server_config = os.path.join(server_config_folder, 'appfl_config.yaml')

            # If user upload a model file, download it
            with open(server_config) as f:
                data = yaml.safe_load(f)
            if 'model_file' in data:
                if not s3_download(S3_BUCKET_NAME, data['model_file'], server_config_folder, 'model.py'):
                    print("Error: Cannot downlaod the custom model file from S3 Bucket!")
                    return
                data['model_file'] = os.path.join(server_config_folder, 'model.py')
        
        #TODO: Check if this is a correct design decision: an APPFL server himself is also an APPFL client
        # Download the client configurations and dataloaders from AWS S3
        client_folder     = os.path.join(upload_folder, server_group_id, user_id)
        client_config_key = f'{server_group_id}/{user_id}/client.yaml'
        dataloader_key    = f'{server_group_id}/{user_id}/dataloader.py'
        if s3_download(S3_BUCKET_NAME, client_config_key, client_folder, 'client.yaml') and s3_download(S3_BUCKET_NAME, dataloader_key, client_folder, 'dataloader.py'):
            # Check endpoint health status
            with open(os.path.join(client_folder, 'client.yaml')) as f:
                data = yaml.safe_load(f)
            endpoint_id = data['client']['endpoint_id']
            for _ in range(STATUS_CHECK_TIMES): # Wait for at most STATUS_CHECK_TIMES seconds
                try:
                    task_id = fxc.run(endpoint_id=endpoint_id, function_id=func_id)
                    time.sleep(1)
                    fxc.get_result(task_id)
                    client_configs.append(os.path.join(client_folder, 'client.yaml'))
                    dataloaders.append(os.path.join(client_folder, 'dataloader.py'))
                    break
                except funcx.errors.error_types.TaskPending: continue
                except: break

        # data_dir = os.path.join(upload_folder, server_group_id, user_id)
        # # Check if the folder exists or not
        # if os.path.exists(data_dir):
        #     # Check the availability/validity of the resources
        #     with open(os.path.join(data_dir, 'client.yaml')) as f:
        #         data = yaml.safe_load(f)
        #     endpoint_id = data['client']['endpoint_id']
        #     for _ in range(5): # Wait for at most 5 seconds
        #         try:
        #             task_id = fxc.run(endpoint_id=endpoint_id, function_id=func_id)
        #             time.sleep(1)
        #             fxc.get_result(task_id)
        #             client_configs.append(os.path.join(data_dir, 'client.yaml'))
        #             dataloaders.append(os.path.join(data_dir, 'dataloader.py'))
        #             break
        #         except funcx.errors.error_types.TaskPending: continue
        #         except: break
    if len(client_configs) == 0:
        print("Error: No active client available, APPFL run is stopped!")
        return
    # Start running the APPFL
    module.main(server_config, client_configs, dataloaders)
    # TODO: Integrate the attack model
    # TODO: Generate a report


@app.route('/upload_client_config/<client_group_id>', methods=['POST'])
@authenticated
def upload_client_config(client_group_id):
    """
    Upload client configurations to AWS S3
    Input:
        - client_group_id: Globus group id for the client
    """
    upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], client_group_id, session.get('primary_identity'))
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

    # TODO: If we change the configurations, please change here on how we read those user inputs
    # Save the client configuration into a YAML file
    client_config = {'client': {}}
    for param in request.form:
        client_config['client'][param] = request.form[param]
    with open(os.path.join(upload_folder, 'client.yaml'), 'w') as f:
        yaml.dump(client_config, f, default_flow_style=False)

    # Save the dataloader
    loader_file = request.files['client-dataloader']
    loader_file.save(os.path.join(upload_folder, 'dataloader.py'))

    # Upload the files to AWS S3
    error_count = 0
    client_config_fp  = os.path.join(upload_folder, 'client.yaml')
    client_config_key = f'{client_group_id}/{session.get("primary_identity")}/client.yaml'
    loader_file_fp    = os.path.join(upload_folder, 'dataloader.py')
    loader_file_key   = f'{client_group_id}/{session.get("primary_identity")}/dataloader.py'
    if not s3_upload(S3_BUCKET_NAME, client_config_key, client_config_fp, delete_local=True): 
        flash("Error: Client configure is NOT uploaded successfully!")
        print("Error: Client configure is NOT uploaded successfully!")
        error_count += 1
    if not s3_upload(S3_BUCKET_NAME, loader_file_key, loader_file_fp, delete_local=True): 
        flash("Error: Client dataloader is NOT uploaded successfully!")
        print("Error: Client dataloader is NOT uploaded successfully!")
        error_count += 1
    if error_count == 0:
        flash("Configurations are saved successfully!")
    
    return redirect(url_for('dashboard'))


def load_server_config(form, server_group_id):
    """
    Given the input server configuration form, load the configuration into files and upload to AWS S3.
    Inputs:
        - form: Input server configuration form, a dictionary copy of request.form
        - server_group_id: Globus group ID for the APPFL group.
    """
    # TODO: Make sure that the sanity checks are correct (value ranges), such as the privacy budget
    # Input data sanity check
    error_count = 0
    form['server-training-epoch'] = int(form['server-training-epoch'])
    if form['server-training-epoch'] <= 0:
        error_count += 1
        flash(f"Error {error_count}: Server training epoch cannot be less than or equal to 0!")
    form['client-training-epoch'] = int(form['client-training-epoch'])
    if form['client-training-epoch'] <= 0:
        error_count += 1
        flash(f"Error {error_count}: Client training epoch cannot be less than or equal to 0!")
    form['privacy-budget'] = float(form['privacy-budget'])
    if form['privacy-budget'] < 0 or form['privacy-budget'] > 1:
        error_count += 1
        flash(f"Error {error_count}: Privacy budget must lie in range [0, 1]!")
    if form['privacy-budget'] == 0:
        form['privacy-budget'] = False
    form['clip-value'] = float(form['clip-value'])
    if form['clip-value'] < 0:
        error_count += 1
        flash(f"Error {error_count}: Clip value cannot be negative!")
    if form['clip-value'] ==  0:
        form['clip-value'] = False
    form['clip-norm'] = float(form['clip-norm'])
    if form['clip-norm'] < 0:
        error_count += 1
        flash(f"Error {error_count}: Clip norm cannot be negative!")
    form['server-lr'] = float(form['server-lr'])
    if form['server-lr'] < 0:
        error_count += 1
        flash(f"Error {error_count}: Server learning rate cannot be negative!")
    form['server-adapt-param'] = float(form['server-adapt-param'])
    if form['server-adapt-param'] < 0:
        error_count += 1
        flash(f"Error {error_count}: Server Adaptive Param cannot be negative!")
    form['server-momentum'] = float(form['server-momentum'])
    if form['server-momentum'] < 0:
        error_count += 1
        flash(f"Error {error_count}: Server Momentum cannot be negative!")
    form['server-var-momentum'] = float(form['server-var-momentum'])
    if form['server-var-momentum'] < 0:
        error_count += 1
        flash(f"Error {error_count}: Server Variance Momentum cannot be negative!")
    form['client-lr'] = float(form['client-lr'])
    if form['client-lr'] < 0:
        error_count += 1
        flash(f"Error {error_count}: Client learning rate cannot be negative!")
    form['client-lr-decay'] = float(form['client-lr-decay'])
    if form['client-lr-decay'] <= 0 or form['client-lr-decay'] > 1:
        error_count += 1
        flash(f"Error {error_count}: Client learning rate decay should be in range (0, 1]!")

    # If user chooses to use the template model
    if form['model-type'] == 'template':
        form['model-num-channels'] = int(form['model-num-channels'])
        if form['model-num-channels'] <= 0:
            error_count += 1
            flash(f"Error {error_count}: Number of input channels must be positive!")
        form['model-num-classes'] = int(form['model-num-classes'])
        if form['model-num-classes'] <= 0:
            error_count += 1
            flash(f"Error {error_count}: Number of output classes must be positive!")
        form['model-input-width'] = int(form['model-input-width'])
        if form['model-input-width'] <= 0:
            error_count += 1
            flash(f"Error {error_count}: Input width must be positive!")
        form['model-input-height'] = int(form['model-input-height'])
        if form['model-input-height'] <= 0:
            error_count += 1
            flash(f"Error {error_count}: Input height must be positive!")
    # If user uploads a custom model
    else:
        upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], server_group_id, session.get('primary_identity'))
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        model_file = request.files['custom-model-file']
        model_file_fp = os.path.join(upload_folder, 'model.py')
        model_file.save(model_file_fp)
        model_key = f'{server_group_id}/{session.get("primary_identity")}/model.py'
        
        # Upload the model file to AWS S3
        if not s3_upload(S3_BUCKET_NAME, model_key, model_file_fp, delete_local=True):
            flash("Error: The model file is not uploaded successfully to S3!")
            print("Error: The model file is not uploaded successfully to S3!")
            error_count += 1

    if error_count > 0:
        return error_count, None

    # TODO: How to deal with this log file if we move things to cloud (data to S3, and probably the running in a container)
    server_log_dir = os.path.join(app.config['UPLOAD_FOLDER'], server_group_id, session.get('primary_identity'), 'logs')
    # server_log_dir = os.path.join(app.config['UPLOAD_FOLDER'], server_group_id, session.get('primary_identity'))

    appfl_config = {
        'algorithm': {},
        'training': {},
        'dataset': {},
        'server': {'data_dir': server_log_dir, 'output_dir': server_log_dir}
    }
    appfl_config['algorithm']['servername'] = form['fed-alg-select']
    appfl_config['algorithm']['clientname'] = 'FuncxClientOptim'
    #TODO: I think server_lr_decay_exp_gamma is not a suitable name
    appfl_config['algorithm']['args'] = {
        'server_learning_rate': form['server-lr'],
        'server_adapt_param': form['server-adapt-param'],
        'server_momentum_param_1': form['server-momentum'],
        'server_momentum_param_2': form['server-var-momentum'],
        'optim': form['client-optimizer'],
        'num_local_epochs': form['client-training-epoch'],
        'optim_args': {'lr': form['client-lr']},
        'epsilon': form['privacy-budget'],
        'server_lr_decay_exp_gamma': form['client-lr-decay'],
        'client_weights': form['client-weights'],
        'clip_value': form['clip-value'],
        'clip_norm': form['clip-norm']
    }
    appfl_config['training'] = {
        'num_epochs': form['server-training-epoch'],
        'save_model_filename': f"{form['federation-name']}_{form['training-model']}",
        'save_model_dirname': "./save_models"
    }
    appfl_config['dataset']['name'] = form['federation-name']
    if form['model-type'] == 'template':
        appfl_config['model_type'] = form['training-model']
        appfl_config['model'] = {
            'num_channel': form['model-num-channels'],
            'num_classes': form['model-num-classes'],
            'width': form['model-input-width'],
            'height': form['model-input-height']
        }
    else:
        appfl_config['model_file'] = f'{server_group_id}/{session.get("primary_identity")}/model.py'
    return error_count, appfl_config


@app.route('/upload_server_config/<server_group_id>/<run>', methods=['POST'])
@authenticated
def upload_server_config(server_group_id, run='True'):
    """
    Upload the server input configurations to AWS S3.
    Inputs:
        - server_group_id: Globus group ID for the APPFL group.
        - run: Whether to start the APPFL running or simply save the configuration
    """
    # TODO:
    # (1) Test if I can pass the parameter run correctly
    # (2) Load default values based on previously saved parameters, and the default values will be passed as request.form after submission
    upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], server_group_id, session.get('primary_identity'))
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

    # Save the appfl and model configuration
    form = dict(request.form)
    error_count, appfl_config = load_server_config(form, server_group_id)
    if error_count > 0:
        return redirect(request.referrer)
    with open(os.path.join(upload_folder, 'appfl_config.yaml'), 'w') as f:
        yaml.dump(appfl_config, f, default_flow_style=False)
    
    # Upload the configuration file to AWS S3
    appfl_config_key = f'{server_group_id}/{session.get("primary_identity")}/appfl_config.yaml'
    appfl_config_fp  = os.path.join(upload_folder, 'appfl_config.yaml')
    if not s3_upload(S3_BUCKET_NAME, appfl_config_key, appfl_config_fp, delete_local=True):
        flash("Error: The configuration file is not uploaded successfully!")
        return redirect(request.referrer)
    
    # Start the APPFL training
    if run == 'True':
        gc = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
        server_group = gc.get_group(server_group_id, include=["memberships"])
        group_members = [server_group["memberships"][i]["identity_id"] for i in range(len(server_group["memberships"]))]
        group_members_str = ""
        for member in group_members:
            group_members_str += member
            group_members_str += ','
        group_members_str = group_members_str[:-1]
        print(f'Group members: {group_members_str}')
        print(f'Server ID: {session.get("primary_identity")}')
        print(f'Group ID: {server_group_id}')
        print(f'Upload folder: {app.config["UPLOAD_FOLDER"]}')
        print(f"Funcx  token: {session['tokens']['funcx_service']['access_token']}")
        print(f"Search token: {session['tokens']['search.api.globus.org']['access_token']}")
        print(f"Openid token: {session['tokens']['auth.globus.org']['access_token']}")
        # Those parameters should be passed to the container
        task_arn = ecs_run_task([group_members_str, 
                            session.get("primary_identity"), 
                            server_group_id, 
                            app.config["UPLOAD_FOLDER"],
                            session['tokens']['funcx_service']['access_token'],
                            session['tokens']['search.api.globus.org']['access_token'],
                            session['tokens']['auth.globus.org']['access_token']
        ])
        if not dynamodb_append_task(server_group_id, task_arn):
            flash("An error occurs when adding the task!")
        flash("The federation is started!")
        # appfl_process = multiprocessing.Process(target=run_appfl, args=(group_members, session.get('primary_identity'), server_group_id, app.config['UPLOAD_FOLDER']))
        # appfl_process.start()
        # flash("The federation is started!")
    else:
        flash("Configurations are saved successfully!")
    return redirect(url_for('dashboard'))


class EndpointStatus(Enum):
    UNSET = -2              # User does not specify an endpoint
    INVALID = -1            # User give an invalid endpoint
    INACTIVE = 0            # Endpoint is not active (not started)
    ACTIVE_CPU = 1          # Endpoint does not have GPU
    ACTIVE_GPU = 2          # Endpoint has GPU available

@app.route('/task-status', methods=['GET'])
@authenticated
def task_status():
    task_status = {}
    for key in request.args:
        task_arn = request.args[key]
        task_id = ecs_arn2id(task_arn)
        task_status[task_id] = {}
        status, starttime, endtime = ecs_task_status(task_arn)
        task_status[task_id]['status'] = status
        task_status[task_id]['start-time'] = starttime
        task_status[task_id]['end-time'] = endtime
    return task_status



@app.route('/status-check', methods=['GET'])
@authenticated
def status_check():
    """Check the health status of the provided funcx endpoints."""
    endpoint_status = {}
    for key in request.args:
        endpoint_status[request.args[key]] = EndpointStatus.UNSET.value
    # fxc = FuncXClient()
    fxc = get_funcx_client(session['tokens'])
    func_id = fxc.register_function(endpoint_test)
    for endpoint_id in endpoint_status:
        if endpoint_id == '0': continue
        endpoint_status[endpoint_id] = EndpointStatus.INACTIVE.value
        for _ in range(STATUS_CHECK_TIMES): # Wait for at most STATUS_CHECK_TIMES seconds
            try:
                task_id = fxc.run(endpoint_id=endpoint_id, function_id=func_id)
                time.sleep(1)
                if (fxc.get_result(task_id)):
                    endpoint_status[endpoint_id] = EndpointStatus.ACTIVE_GPU.value
                    break
                else:
                    endpoint_status[endpoint_id] = EndpointStatus.ACTIVE_CPU.value
                    break
            except funcx.errors.error_types.TaskPending: continue
            except:
                endpoint_status[endpoint_id] = EndpointStatus.INVALID.value
                break
    return endpoint_status
    

@app.route('/appfl-log/<server_group_id>', methods=['GET'])
@authenticated
def appfl_log_page(server_group_id):
    """Return the log page for the appfl run of group `server_group_id`"""
    log_file = os.path.join(app.config['UPLOAD_FOLDER'], server_group_id, session.get('primary_identity'), 'logs', 'log_server.log')
    if os.path.isfile(log_file):
        with open(log_file) as f:
            log_contents = [line for line in f]
        return render_template('log.jinja2', log_contents=log_contents)
    else:
        flash("Error: There is not log file for this server now!")
        return redirect(request.referrer)


@app.route('/tensorboard-log/<server_group_id>', methods=['GET'])
@authenticated
def tensorboard_log_page(server_group_id):
    """
    Return the tensorboard log page for the appfl run of group `server_group_id`
    """
    #TODO: Include a 404 page if there is no log file available
    #TODO: currently the tensorboard is launched using http, later we should launch it using https
    #TODO: This implementation still launches a new TensorBoard server every time 
    #      the /info route is visited, so you may want to modify the code to launch 
    #      the server only once and keep it running in the background, or use a 
    #      different method of embedding the TensorBoard page (such as using 
    #      JavaScript to load the page dynamically).
    logdir = os.path.join(app.config['UPLOAD_FOLDER'], server_group_id, session.get('primary_identity'), 'logs', 'tensorboard')
    if os.path.isdir(logdir):
        tb = program.TensorBoard()  
        tb.configure(argv=[None, '--logdir', logdir, '--host', '0.0.0.0'])
        url = tb.launch()
        port = url.split(':')[-1]
        url = f'http://{app.config["SESSION_COOKIE_DOMAIN"]}:{port}'
        return redirect(url)
        return render_template('tensorboard_log.jinja2', url=url)
    else:
        flash("Error: There is not log file for this server!")
        return redirect(request.referrer)


@app.errorhandler(413)
def error413(e):
    """Error handler for uploading file exceeding the maximum size."""
    flash(f'Error: File is larger than the maximum file size: {float(app.config["MAX_CONTENT_LENGTH"]/(1024*1024)):2f}MB!')
    return redirect(request.referrer)


# =====================================DEPRECATED BELOW===============================================

@app.route('/browse/dataset/<dataset_id>', methods=['GET'])
@app.route('/browse/endpoint/<endpoint_id>/<path:endpoint_path>',
           methods=['GET'])
@authenticated
def browse(dataset_id=None, endpoint_id=None, endpoint_path=None):
    """
    - Get list of files for the selected dataset or endpoint ID/path
    - Return a list of files to a browse view

    The target template (browse.jinja2) expects an `endpoint_uri` (if
    available for the endpoint), `target` (either `"dataset"`
    or `"endpoint"`), and 'file_list' (list of dictionaries) containing
    the following information about each file in the result:

    {'name': 'file name', 'size': 'file size', 'id': 'file uri/path'}

    If you want to display additional information about each file, you
    must add those keys to the dictionary and modify the browse.jinja2
    template accordingly.
    """

    assert bool(dataset_id) != bool(endpoint_id and endpoint_path)

    if dataset_id:
        try:
            dataset = next(ds for ds in datasets if ds['id'] == dataset_id)
        except StopIteration:
            abort(404)

        endpoint_id = app.config['DATASET_ENDPOINT_ID']
        endpoint_path = app.config['DATASET_ENDPOINT_BASE'] + dataset['path']

    else:
        endpoint_path = '/' + endpoint_path

    transfer_tokens = session['tokens']['transfer.api.globus.org']

    authorizer = RefreshTokenAuthorizer(
        transfer_tokens['refresh_token'],
        load_portal_client(),
        access_token=transfer_tokens['access_token'],
        expires_at=transfer_tokens['expires_at_seconds'])

    transfer = TransferClient(authorizer=authorizer)

    try:
        transfer.endpoint_autoactivate(endpoint_id)
        listing = transfer.operation_ls(endpoint_id, path=endpoint_path)
    except TransferAPIError as err:
        flash('Error [{}]: {}'.format(err.code, err.message))
        return redirect(url_for('transfer'))

    file_list = [e for e in listing if e['type'] == 'file']

    ep = transfer.get_endpoint(endpoint_id)

    https_server = ep['https_server']
    endpoint_uri = https_server + endpoint_path if https_server else None
    webapp_xfer = 'https://app.globus.org/file-manager?' + \
        urlencode(dict(origin_id=endpoint_id, origin_path=endpoint_path))

    return render_template('browse.jinja2', endpoint_uri=endpoint_uri,
                           target="dataset" if dataset_id else "endpoint",
                           description=(dataset['name'] if dataset_id
                                        else ep['display_name']),
                           file_list=file_list, webapp_xfer=webapp_xfer)


@app.route('/transfer', methods=['GET', 'POST'])
@authenticated
def transfer():
    """
    - Save the submitted form to the session.
    - Send to Globus to select a destination endpoint using the
      Browse Endpoint helper page.
    """
    if request.method == 'GET':
        return render_template('transfer.jinja2', datasets=datasets)

    if request.method == 'POST':
        if not request.form.get('dataset'):
            flash('Please select at least one dataset.')
            return redirect(url_for('transfer'))

        params = {
            'method': 'POST',
            'action': url_for('submit_transfer', _external=True,
                              _scheme='https'),
            'filelimit': 0,
            'folderlimit': 1
        }

        browse_endpoint = 'https://app.globus.org/file-manager?{}' \
            .format(urlencode(params))

        session['form'] = {
            'datasets': request.form.getlist('dataset')
        }

        return redirect(browse_endpoint)


@app.route('/submit-transfer', methods=['POST'])
@authenticated
def submit_transfer():
    """
    - Take the data returned by the Browse Endpoint helper page
      and make a Globus transfer request.
    - Send the user to the transfer status page with the task id
      from the transfer.
    """
    browse_endpoint_form = request.form

    selected = session['form']['datasets']
    filtered_datasets = [ds for ds in datasets if ds['id'] in selected]

    transfer_tokens = session['tokens']['transfer.api.globus.org']

    authorizer = RefreshTokenAuthorizer(
        transfer_tokens['refresh_token'],
        load_portal_client(),
        access_token=transfer_tokens['access_token'],
        expires_at=transfer_tokens['expires_at_seconds'])

    transfer = TransferClient(authorizer=authorizer)

    source_endpoint_id = app.config['DATASET_ENDPOINT_ID']
    source_endpoint_base = app.config['DATASET_ENDPOINT_BASE']
    destination_endpoint_id = browse_endpoint_form['endpoint_id']
    destination_folder = browse_endpoint_form.get('folder[0]')

    transfer_data = TransferData(transfer_client=transfer,
                                 source_endpoint=source_endpoint_id,
                                 destination_endpoint=destination_endpoint_id,
                                 label=browse_endpoint_form.get('label'))

    for ds in filtered_datasets:
        source_path = source_endpoint_base + ds['path']
        dest_path = browse_endpoint_form['path']

        if destination_folder:
            dest_path += destination_folder + '/'

        dest_path += ds['name'] + '/'

        transfer_data.add_item(source_path=source_path,
                               destination_path=dest_path,
                               recursive=True)

    transfer.endpoint_autoactivate(source_endpoint_id)
    transfer.endpoint_autoactivate(destination_endpoint_id)
    task_id = transfer.submit_transfer(transfer_data)['task_id']

    flash('Transfer request submitted successfully. Task ID: ' + task_id)

    return(redirect(url_for('transfer_status', task_id=task_id)))


@app.route('/status/<task_id>', methods=['GET'])
@authenticated
def transfer_status(task_id):
    """
    Call Globus to get status/details of transfer with
    task_id.

    The target template (tranfer_status.jinja2) expects a Transfer API
    'task' object.

    'task_id' is passed to the route in the URL as 'task_id'.
    """
    transfer_tokens = session['tokens']['transfer.api.globus.org']

    authorizer = RefreshTokenAuthorizer(
        transfer_tokens['refresh_token'],
        load_portal_client(),
        access_token=transfer_tokens['access_token'],
        expires_at=transfer_tokens['expires_at_seconds'])

    transfer = TransferClient(authorizer=authorizer)
    task = transfer.get_task(task_id)

    return render_template('transfer_status.jinja2', task=task)


@app.route('/graph', methods=['GET', 'POST'])
@authenticated
def graph():
    """
    Make a request to the "resource server" (service app) API to
    do the graph processing.
    """
    if request.method == 'GET':
        return render_template('graph.jinja2', datasets=datasets)

    selected_ids = request.form.getlist('dataset')
    selected_year = request.form.get('year')

    if not (selected_ids and selected_year):
        flash("Please select at least one dataset and a year to graph.")
        return redirect(url_for('graph'))

    tokens = get_portal_tokens()
    service_token = tokens.get('GlobusWorld Resource Server')['token']

    service_url = '{}/{}'.format(app.config['SERVICE_URL_BASE'], 'api/doit')
    req_headers = dict(Authorization='Bearer {}'.format(service_token))

    req_data = dict(datasets=selected_ids,
                    year=selected_year,
                    user_identity_id=session.get('primary_identity'),
                    user_identity_name=session.get('primary_username'))

    resp = requests.post(service_url, headers=req_headers, data=req_data,
                         verify=False)

    resp.raise_for_status()

    resp_data = resp.json()
    dest_ep = resp_data.get('dest_ep')
    dest_path = resp_data.get('dest_path')
    dest_name = resp_data.get('dest_name')
    graph_count = resp_data.get('graph_count')

    flash("%d-file SVG upload to %s on %s completed!" %
          (graph_count, dest_path, dest_name))

    return redirect(url_for('browse', endpoint_id=dest_ep,
                            endpoint_path=dest_path.lstrip('/')))


@app.route('/graph/clean-up', methods=['POST'])
@authenticated
def graph_cleanup():
    """Make a request to the service app API to do the graph processing."""
    tokens = get_portal_tokens()
    service_token = tokens.get('GlobusWorld Resource Server')['token']

    service_url = '{}/{}'.format(app.config['SERVICE_URL_BASE'], 'api/cleanup')
    req_headers = dict(Authorization='Bearer {}'.format(service_token))

    resp = requests.post(service_url,
                         headers=req_headers,
                         data=dict(
                             user_identity_name=session['primary_username']
                         ),
                         verify=False)

    resp.raise_for_status()

    task_id = resp.json()['task_id']

    msg = '{} ({}).'.format('Your existing processed graphs have been removed',
                            task_id)
    flash(msg)
    return redirect(url_for('graph'))
