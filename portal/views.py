import os
import json
import yaml
import time
import funcx
import base64
import requests
import globus_sdk
from enum import Enum
from portal import app
from tensorboard import program
from portal.decorators import authenticated
from portal.github_integration import github_bp
from flask import (abort, flash, redirect, render_template, request, session, url_for, jsonify)
from portal.utils import (EXP_DIR, FL_TAG, S3_BUCKET_NAME, \
                          get_safe_redirect, group_tagging, get_servers_clients, \
                          load_portal_client, load_group_client, \
                          s3_download, s3_upload, s3_get_download_link, s3_download_folder, \
                          ecs_run_task, ecs_task_status, ecs_arn2id, ecs_parse_taskinfo, ecs_task_delete, \
                          dynamodb_get_tasks, dynamodb_append_task, get_funcx_client, aws_get_log, \
                          dynamodb_get_profile, dynamodb_add_profile, \
                          training_data_preprocessing, val_test_data_preprocessing, hp_data_preprocessing)

app.register_blueprint(github_bp, url_prefix='/github_integration')

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

    unrevoked_tokens = ['auth.globus.org', 'funcx_service', 'search.api.globus.org']

    # Revode the tokens with Globus Auth
    for key, token_info in session['tokens'].items():
        if key not in unrevoked_tokens:
            for token_type in ('access_token', 'refresh_token'):
                token = token_info[token_type]
                client.oauth2_revoke_token(token, body_params={'token_type_hint': token_type})

    # Destroy the session state
    session.clear()

    redirect_uri = url_for('home', _external=True)

    ga_logout_url = []
    ga_logout_url.append(app.config['GLOBUS_AUTH_LOGOUT_URI'])
    ga_logout_url.append('?client={}'.format(app.config['PORTAL_CLIENT_ID']))
    ga_logout_url.append('&redirect_uri={}'.format(redirect_uri))
    ga_logout_url.append('&redirect_name=Privacy Preservering Federated Learning as a Service')

    # Redirect the user to the Globus Auth logout page
    return redirect(''.join(ga_logout_url))

@app.route('/profile', methods=['GET', 'POST'])
@authenticated
def profile():
    """
    Get:
        Obtain the user profile from the DynamoDB profile table. If no record exists, 
        redirect the user to the profile page.
    Post:
        Post the user profile to the DynamoDB profile table.
    """
    if request.method == 'GET':
        user_id = session.get('primary_identity')
        profile = dynamodb_get_profile(user_id)
        if profile is not None:
            name, email, institution = profile
            session['name'] = name
            session['email'] = email
            session['institution'] = institution
        else:
            flash('Please complete any missing profile fields and press Save.')
        if request.args.get('next'):
            session['next'] = get_safe_redirect()
        return render_template('profile.jinja2')
    elif request.method == 'POST':
        name = session['name'] = request.form['name']
        email = session['email'] = request.form['email']
        institution = session['institution'] = request.form['institution']
        all_identities = session['all_identities']
        for user_id in all_identities:
            dynamodb_add_profile(user_id, name, email, institution)
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
    # If we come back from Globus Auth in an error state, the error will be in the "error" query string parameter.
    if 'error' in request.args:
        flash("You could not be logged into the portal: " + request.args.get('error_description', request.args['error']))
        return redirect(url_for('home'))

    # Set up our Globus Auth/OAuth2 state
    redirect_uri = url_for('authcallback', _external=True)

    client = load_portal_client()
    client.oauth2_start_flow(
        redirect_uri,
        refresh_tokens=True,
        requested_scopes=app.config['USER_SCOPES']
    )

    # Start a Globus Auth login flow.
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
        all_identities = [identity['sub'] for identity in id_token['identity_set']]
        session.update(
            tokens=tokens.by_resource_server,
            is_authenticated=True,
            name=id_token.get('name'),
            email=id_token.get('email'),
            institution=id_token.get('organization'),
            primary_username=id_token.get('preferred_username'),
            primary_identity=id_token.get('sub'),
            all_identities=all_identities
        )
        profile = dynamodb_get_profile(session['primary_identity'])
        if profile:
            name, email, institution = profile
            session['name'] = name
            session['email'] = email
            session['institution'] = institution
        else:
            return redirect(url_for('profile', next=url_for('dashboard')))
        return redirect(url_for('dashboard'))

def get_clients_information(members, group_id):
    """
    Check if the APPFL clients in the group have uploaded their endpoint information

    Inputs:
        - `members`: list of group membership information
        - `group_id`: Globus group id

    Outputs:
        - `user_names`: list of names of group members
        - `user_emails`: list of emails of group members
        - `user_orgs`: list of organizations of group members
        - `user_endpoint`: list of funcx endpoints provided by group members
    """
    user_names, user_emails, user_orgs, user_endpoints = [], [], [], []
    for member in members:
        if member['status'] != 'active': continue
        # Obtain user information
        user_id = member['identity_id']
        profile = dynamodb_get_profile(user_id)
        if profile:
            name, email, institution = profile
        else:
            if 'name' in member['membership_fields']: 
                name = member['membership_fields']['name']
            elif 'username' in member:
                name = member['username']
            else:
                name = 'unknown'
            if 'email' in member['membership_fields']:
                email = member['membership_fields']['email']
            elif 'invite_email_address' in member:
                email = member['invite_email_address']
            else:
                email = 'unknown'
            if 'organization' in member['membership_fields']:
                institution = member['membership_fields']['organization']
            else:
                institution = 'unknown'
        user_names.append(name)
        user_emails.append(email)
        user_orgs.append(institution)
        # Obtain user endpoints
        client_config_folder = os.path.join(app.config['UPLOAD_FOLDER'], group_id, user_id)
        client_config_key    = f'{group_id}/{user_id}/client.yaml'
        if s3_download(S3_BUCKET_NAME, client_config_key, client_config_folder, 'client.yaml'):
            with open(os.path.join(client_config_folder, 'client.yaml')) as f:
                data = yaml.safe_load(f)
            user_endpoints.append(data['client']['endpoint_id'])
            os.remove(os.path.join(client_config_folder, 'client.yaml'))
        else:
            user_endpoints.append('0')
    return user_names, user_emails, user_orgs, user_endpoints

@app.route('/browse/server/<server_group_id>', methods=['GET'])
@app.route('/browse/client/<client_group_id>', methods=['GET'])
@authenticated
def browse_config(server_group_id=None, client_group_id=None):
    """
    Load the APPFL server/client configuration page

    Inputs (Note: two inputs are mutually exclusive):
        - `server_group_id`: Globus group ID for the APPFL server 
        - `client_group_id`: Globus group ID for the APPFL client 
    """
    gc = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
    client_id = app.config['GITHUB_CLIENT_ID']
    redirect_uri =app.config['GITHUB_REDIRECT_URI']
    auth_url = f"https://github.com/login/oauth/authorize?client_id={client_id}&scope=repo&redirect_uri={redirect_uri}"
    
    if server_group_id is not None:
        server_group = gc.get_group(server_group_id, include=["memberships"])
        client_names, client_emails, client_orgs, client_endpoints = get_clients_information(server_group['memberships'], server_group_id)
        return render_template('server.jinja2', \
                               server_group_id=server_group_id, \
                               client_names=client_names, \
                               client_endpoints=client_endpoints, \
                               client_emails=client_emails, \
                               client_orgs=client_orgs, \
                               auth_url=auth_url)
    if client_group_id is not None:
        client_group = gc.get_group(client_group_id)
        return render_template('client.jinja2', \
                               client_group=client_group, \
                               client_group_id=client_group_id, \
                               auth_url=auth_url)
    return render_template('dashboard.jinja2')

@app.route('/browse/server-info/<server_group_id>', methods=['GET'])
@app.route('/browse/client-info/<client_group_id>', methods=['GET'])
@authenticated
def browse_info(server_group_id=None, client_group_id=None):
    """
    Load the APPFL server/client information page

    Inputs (Note: two inputs are mutually exclusive):
        - `server_group_id`: Globus group ID for the APPFL server 
        - `client_group_id`: Globus group ID for the APPFL client 
    """
    gc = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
    if server_group_id is not None:
        task_info = dynamodb_get_tasks(server_group_id)
        task_arns, task_names = ecs_parse_taskinfo(task_info)
        task_ids = [ecs_arn2id(task_arn) for task_arn in task_arns]
        server_group = gc.get_group(server_group_id, include=["memberships"])
        client_names, client_emails, client_orgs, client_endpoints = get_clients_information(server_group['memberships'], server_group_id)
        return render_template('server_info.jinja2', \
                                server_group_id=server_group_id, \
                                client_names=client_names, \
                                client_endpoints=client_endpoints, \
                                client_emails=client_emails, \
                                client_orgs=client_orgs, \
                                task_ids=task_ids, \
                                task_arns=task_arns, \
                                task_names=task_names)
    if client_group_id is not None:
        return render_template('client_info.jinja2', client_group_id=client_group_id)

def download_comp_report(group_id, task_ids, referrer):
    """Download comparison report for experiments in a group."""
    # task_ids is a string of comma-separated ids, split it into a list
    task_ids = task_ids.split(',')
    gc = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
    my_info = gc.get_group(group_id, include=['my_memberships'])['my_memberships'][0]
    group_name_raw = gc.get_group(group_id)["name"]
    group_name = group_name_raw[:-len(FL_TAG)]
    user_id = my_info['identity_id']
    if group_id is not None:
        training_data_list = []
        client_validation_list = []
        server_validation_list = []
        client_test_list = []
        server_test_list = []
        hp_data_list = []
        for task_id in task_ids:
            config_key      = f'{group_id}/{EXP_DIR}/{task_id}/appfl_config.yaml'
            train_key       = f'{group_id}/{EXP_DIR}/{task_id}/log_funcx.yaml'
            eval_key        = f'{group_id}/{EXP_DIR}/{task_id}/log_eval.json'
            download_folder = os.path.join(app.config['UPLOAD_FOLDER'], group_id, user_id, task_id)
            if s3_download(S3_BUCKET_NAME, config_key, download_folder, 'appfl_config.yaml') and \
               s3_download(S3_BUCKET_NAME, train_key, download_folder, 'log_funcx.yaml') and \
               s3_download(S3_BUCKET_NAME, eval_key, download_folder, 'log_eval.json'):
                # Load the training metrics
                with open(os.path.join(download_folder, 'log_funcx.yaml')) as f:
                    training_data = yaml.safe_load(f)
                training_data = training_data_preprocessing(training_data)

                # Load the validation and test results
                with open(os.path.join(download_folder, 'log_eval.json')) as f:
                    val_test_data = json.load(f)
                client_validation, server_validation, client_test, server_test = val_test_data_preprocessing(val_test_data)

                # Load the training hyperparameters
                with open(os.path.join(download_folder, 'appfl_config.yaml')) as f:
                    hp_data = yaml.safe_load(f)
                hp_data = hp_data_preprocessing(hp_data)

                hp_data["group_name"] = group_name

                # Add to the list
                training_data_list.append(training_data)
                client_validation_list.append(client_validation)
                server_validation_list.append(server_validation)
                client_test_list.append(client_test)
                server_test_list.append(server_test)
                hp_data_list.append(hp_data)

                # Clean the downloaded files
                os.remove(os.path.join(download_folder, 'log_funcx.yaml'))
                os.remove(os.path.join(download_folder, 'log_eval.json'))
                os.remove(os.path.join(download_folder, 'appfl_config.yaml'))
                
            else:
                flash("There is no report for at least one of the experiments!")
                return redirect(referrer)
            
        return render_template('comp-report/comp_report.jinja2', 
                                tab_title='Federation Comparison Report',
                                report_title='Federation Comparison Report',
                                training_data_list=json.dumps(training_data_list), 
                                client_validation_list=json.dumps(client_validation_list), 
                                server_validation_list=json.dumps(server_validation_list),
                                client_test_list=json.dumps(client_test_list),
                                server_test_list=json.dumps(server_test_list),
                                hp_data_list=hp_data_list,
                                hp_data_list_json=json.dumps(hp_data_list))
    else:
        flash("Sorry, you do not select experiments in a right way!")
        return redirect(referrer)    

@app.route('/download/<file_type>/<group_id>', methods=['GET'])
@app.route('/download/<file_type>/<group_id>/<task_id>', methods=['GET'])
@authenticated
def download_file(file_type="", group_id=None, task_id=None):
    """
    Download (or load) different types of files such as client dataloader,
    experiment configuration, experiment log, experiment report.
    #TODO: Combine the comparison report to this function as well.

    Inputs:
        - `file_type`: Type of the file to be loaded.
        - `group_id`: Corresponding group ID of the required file.
        - `task_id` (optional): Corresponding task ID of the required file. 
    """
    gc      = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
    my_info = gc.get_group(group_id, include=['my_memberships'])['my_memberships'][0]
    user_id = my_info['identity_id']
    if file_type == "dataloader" and group_id is not None:
        return redirect(s3_get_download_link(S3_BUCKET_NAME, f'{group_id}/{user_id}/dataloader.py'))
    elif file_type == 'configuration' and group_id is not None and task_id is not None:
        config_key    = f'{group_id}/{EXP_DIR}/{task_id}/appfl_config.yaml'
        config_folder = os.path.join(app.config['UPLOAD_FOLDER'], group_id, user_id, task_id)
        config_name   = 'appfl_config.yaml'
        if s3_download(S3_BUCKET_NAME, config_key, config_folder, config_name):
            with open(os.path.join(config_folder, config_name)) as f:
                hp_data = yaml.safe_load(f)
            hp_data = hp_data_preprocessing(hp_data)
            # Load the group name
            group_name_raw = gc.get_group(group_id)["name"]
            group_name = group_name_raw[:-len(FL_TAG)]
            hp_data["group_name"] = group_name
            os.remove(os.path.join(config_folder, config_name))
            return render_template('report.jinja2',
                                   tab_title='Federation Configuration',
                                   report_title='Federation Configuration',
                                   hp_data=hp_data)
        else:   
            flash("There is no configuration for this federation!")
            return redirect(request.referrer)
    elif file_type == 'log' and task_id is not None and group_id is not None:
        return aws_get_log(task_id, user_id, group_id, request.referrer)
    elif file_type == 'report' and task_id is not None and group_id is not None:
        config_key      = f'{group_id}/{EXP_DIR}/{task_id}/appfl_config.yaml'
        train_key       = f'{group_id}/{EXP_DIR}/{task_id}/log_funcx.yaml'
        eval_key        = f'{group_id}/{EXP_DIR}/{task_id}/log_eval.json'
        download_folder = os.path.join(app.config['UPLOAD_FOLDER'], group_id, user_id, task_id)
        if s3_download(S3_BUCKET_NAME, config_key, download_folder, 'appfl_config.yaml') and \
           s3_download(S3_BUCKET_NAME, train_key, download_folder, 'log_funcx.yaml') and \
           s3_download(S3_BUCKET_NAME, eval_key, download_folder, 'log_eval.json'):
            # Load the training metrics
            with open(os.path.join(download_folder, 'log_funcx.yaml')) as f:
                training_data = yaml.safe_load(f)
            training_data = training_data_preprocessing(training_data)

            # Load the validation and test results
            with open(os.path.join(download_folder, 'log_eval.json')) as f:
                val_test_data = json.load(f)
            client_validation, server_validation, client_test, server_test = val_test_data_preprocessing(val_test_data)

            # Load the training hyperparameters
            with open(os.path.join(download_folder, 'appfl_config.yaml')) as f:
                hp_data = yaml.safe_load(f)
            hp_data = hp_data_preprocessing(hp_data)

            # Load the group name
            gc = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
            group_name_raw = gc.get_group(group_id)["name"]
            group_name = group_name_raw[:-len(FL_TAG)]
            hp_data["group_name"] = group_name

            # Clean the downloaded files
            os.remove(os.path.join(download_folder, 'log_funcx.yaml'))
            os.remove(os.path.join(download_folder, 'log_eval.json'))
            os.remove(os.path.join(download_folder, 'appfl_config.yaml'))
            return render_template('report.jinja2', 
                           tab_title='Federation Report',
                           report_title='Federation Report',
                           training_data=training_data, 
                           client_validation=client_validation, 
                           server_validation=server_validation,
                           client_test=client_test,
                           server_test=server_test,
                           hp_data=hp_data)
        else:
            flash("There is no report for this federation!")
            return redirect(request.referrer)
    elif file_type == 'comp_report' and group_id is not None:
        task_ids = request.args.get('task_ids')
        return download_comp_report(group_id, task_ids, request.referrer)
    else:
        flash("Sorry, this function is still not implemented!")
        return redirect(request.referrer)

@app.route('/get-client-info', methods=['GET'])
@authenticated
def get_client_info():
    """Return the client information to the client information page."""
    client_info = {}
    client_group_id = request.args['client_group_id']
    gc = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
    client_info = gc.get_group(client_group_id, include=['my_memberships'])['my_memberships'][0]
    client_id = client_info['identity_id']
    client_info_key = f'{client_group_id}/{client_id}/client.yaml'
    client_info_folder = os.path.join(app.config['UPLOAD_FOLDER'], client_group_id, client_id)
    client_info_name = 'client.yaml'
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

@app.route('/upload_client_config/<client_group_id>', methods=['POST'])
@authenticated
def upload_client_config(client_group_id):
    """
    Upload client configurations to AWS S3。

    Input:
        - client_group_id: Globus group id for the client
    """
    form = request.form
    gc = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
    client_info = gc.get_group(client_group_id, include=['my_memberships'])['my_memberships'][0]
    client_id = client_info['identity_id']
    upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], client_group_id, client_id)
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

    # TODO: If we change the configurations, please change here on how we read those user inputs
    # Save the client configuration into a YAML file
    client_config = {'client': {}}
    client_config['client']['device'] = request.form['device']
    client_config['client']['endpoint_id'] = request.form['endpoint_id']
    client_config['client']['output_dir'] = 'output' # the default name for output is output

    with open(os.path.join(upload_folder, 'client.yaml'), 'w') as f:
        yaml.dump(client_config, f, default_flow_style=False)

    # Save the dataloader
    if form['loader-type'] == 'custom':
        loader_file = request.files['client-dataloader']
        loader_file_fp = os.path.join(upload_folder, 'dataloader.py')
        loader_file.save(loader_file_fp)
    elif form['loader-type'] == 'github':
        # Handle GitHub file selection here
        access_token = session.get('access_token')
        repo_name = form.get('github-repo-name') 
        branch = form.get('github-branch') 
        file_path = form.get('github-file-path') 

        # Make a request to the GitHub API to get the file's contents
        file_response = requests.get(
            f"https://api.github.com/repos/{session.get('username')}/{repo_name}/contents/{file_path}?ref={branch}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github.v3+json"
            }
        )

        if file_response.status_code == 200:
            # Extract the file data from the response
            file_data = file_response.json()

            # Decode the base64 content without decoding it to a string
            file_content = base64.b64decode(file_data['content'])

            # Open the file in binary mode to write
            loader_file_fp = os.path.join(upload_folder, 'dataloader.py')
            with open(loader_file_fp, "wb") as f:
                f.write(file_content)
            print("==================upload from github success!====================")
        else:
            # Handle errors
            print("====================upload from github error====================")
            return "Error occurred."

    # Upload the files to AWS S3
    error_count = 0
    client_config_fp  = os.path.join(upload_folder, 'client.yaml')
    client_config_key = f'{client_group_id}/{client_id}/client.yaml'
    loader_file_fp    = os.path.join(upload_folder, 'dataloader.py')
    loader_file_key   = f'{client_group_id}/{client_id}/dataloader.py'
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
    Check the validity of input configuration form and load the configuration into dictionary.

    Inputs:
        - form: Input server configuration form, a dictionary copy of request.form
        - server_group_id: Globus group ID for the APPFL group.

    Outputs:
        - error_count: number of errors in the configuration form
        - appfl_config: configuration dictionary
        - fed_name: name of the FL experiment
        - model_file_fp: file path of the custom model file (None if not applicable)
    """
    # TODO: Make sure that the sanity checks are correct (value ranges), such as the privacy budget
    # Input data sanity check
    gc          = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
    server_info = gc.get_group(server_group_id, include=['my_memberships'])['my_memberships'][0]
    server_id   = server_info['identity_id']

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
    form['server-mix-param'] = float(form['server-mix-param'])
    if form['server-mix-param'] <= 0 or form['server-mix-param'] > 1:
        error_count += 1
        flash(f"Error {error_count}: Mixing parameter should be in range(0, 1]!")
    form['server-reg-strength'] = float(form['server-reg-strength'])
    if form['server-reg-strength'] < 0:
        error_count += 1
        flash(f"Error {error_count}: Regularization strength cannot be negative!")
    form['server-sta-func-param-a'] = float(form['server-sta-func-param-a'])
    if form['server-sta-func-param-a'] <= 0:
        error_count += 1
        flash(f"Error {error_count}: Parameter a must be positive!")
    form['server-sta-func-param-b'] = float(form['server-sta-func-param-b'])
    if form['server-sta-func-param-a'] < 0:
        error_count += 1
        flash(f"Error {error_count}: Parameter b cannot be negative!")
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
        model_file_fp = None
    # If user uploads a custom model
    else:
        if form['model-type'] == 'custom':
            upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], server_group_id, server_id)
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            model_file = request.files['custom-model-file']
            model_file_fp = os.path.join(upload_folder, 'model.py')
            model_file.save(model_file_fp)
        elif form['model-type'] == 'github':
            # Handle GitHub file selection here
            upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], server_group_id, server_id)
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            access_token = session.get('access_token')
            repo_name = form.get('github-repo-name') 
            branch = form.get('github-branch') 
            file_path = form.get('github-file-path') 

            # Make a request to the GitHub API to get the file's contents
            file_response = requests.get(
                f"https://api.github.com/repos/{session.get('username')}/{repo_name}/contents/{file_path}?ref={branch}",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )

            if file_response.status_code == 200:
                # Extract the file data from the response
                file_data = file_response.json()

                # Decode the base64 content without decoding it to a string
                file_content = base64.b64decode(file_data['content'])

                # Open the file in binary mode to write
                model_file_fp = os.path.join(upload_folder, 'model.py')
                with open(model_file_fp, "wb") as f:
                    f.write(file_content)
                print("==================upload from github success!====================")
            else:
                # Handle errors
                print("====================upload from github error====================")
                return "Error occurred."

    if error_count > 0:
        return error_count, None, None, None

    server_log_dir = os.path.join(app.config['UPLOAD_FOLDER'], server_group_id, EXP_DIR, 'logs')
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
        'alpha': form['server-mix-param'],
        'rho': form['server-reg-strength'],
        'staness_func': {
            'name': form['server-sta-func'], 
            'args': {
                'a': form['server-sta-func-param-a'],
                'b': form['server-sta-func-param-b']
            }
        },
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
        'clip_norm': form['clip-norm'],
        'benchmarking_set': form['benchmark-set']
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
        #TODO: Check what is model_file should be filled after changes
        appfl_config['model_file'] = f'TBF'
    return error_count, appfl_config, form['federation-name'], model_file_fp

@app.route('/upload_server_config/<server_group_id>', methods=['POST'])
@authenticated
def upload_server_config(server_group_id):
    """
    Upload the server input configurations to AWS S3 and start the experiment.

    Inputs:
        - server_group_id: Globus group ID for the APPFL group.
        - run: Whether to start the APPFL running or simply save the configuration
    """
    # TODO:
    # (1) Test if I can pass the parameter run correctly
    # (2) Load default values based on previously saved parameters, and the default values will be passed as request.form after submission
    gc          = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
    server_info = gc.get_group(server_group_id, include=['my_memberships'])['my_memberships'][0]
    server_id   = server_info['identity_id']

    upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], server_group_id, server_id)
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

    # Save the appfl and model configuration
    form = dict(request.form)
    error_count, appfl_config, exp_name, model_fp = load_server_config(form, server_group_id)
    if error_count > 0:
        return redirect(request.referrer)
    with open(os.path.join(upload_folder, 'appfl_config.yaml'), 'w') as f:
        yaml.dump(appfl_config, f, default_flow_style=False)
    
    # Obtain necessary parameters for launching experiments
    gc = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
    server_group = gc.get_group(server_group_id, include=["memberships"])
    group_members = [server_group["memberships"][i]["identity_id"] for i in range(len(server_group["memberships"]))]
    group_members_str = ""
    for member in group_members:
        group_members_str += member
        group_members_str += ','
    group_members_str = group_members_str[:-1]

    # # Test Code Updated
    # parameter_dict = {}
    # parameter_dict['group_members'] = group_members_str
    # parameter_dict['server_id'] = server_id
    # parameter_dict['group_id'] = server_group_id
    # parameter_dict['upload_folder'] = app.config["UPLOAD_FOLDER"]
    # parameter_dict['funcx_token'] = session['tokens']['funcx_service']['access_token']
    # parameter_dict['search_token'] = session['tokens']['search.api.globus.org']['access_token']
    # parameter_dict['openid_token'] = session['tokens']['auth.globus.org']['access_token']
    # with open(os.path.join(upload_folder, 'parameter.yaml'), 'w') as f:
    #     yaml.dump(parameter_dict, f, default_flow_style=False)

    # task_id = 'randomid'
    # model_key        = f'{server_group_id}/{EXP_DIR}/{task_id}/model.py'
    # parameter_fp     = os.path.join(upload_folder, 'parameter.yaml')
    # parameter_key    = f'{server_group_id}/{EXP_DIR}/{task_id}/parameter.yaml'
    # appfl_config_fp  = os.path.join(upload_folder, 'appfl_config.yaml')    
    # appfl_config_key = f'{server_group_id}/{EXP_DIR}/{task_id}/appfl_config.yaml'

    # if model_fp is not None:
    #     if not s3_upload(S3_BUCKET_NAME, model_key, model_fp, delete_local=True):
    #         flash("Error: The custom model file is not uploaded successfully!")
    #         return redirect(request.referrer)
    # if not s3_upload(S3_BUCKET_NAME, appfl_config_key, appfl_config_fp, delete_local=True):
    #     flash("Error: The configuration file is not uploaded successfully!")
    #     return redirect(request.referrer)
    # if not s3_upload(S3_BUCKET_NAME, parameter_key, parameter_fp, delete_local=True):
    #     flash("Error: The parameter file is not uploaded successfully!")
    #     return redirect(request.referrer)
    # print(f'The key of the S3 parameter object file is {server_group_id}/{EXP_DIR}')
    # return redirect(url_for('dashboard'))

    # Prepare a parameter file for running the server
    parameter_dict = {}
    parameter_dict['group_members'] = group_members_str
    parameter_dict['server_id'] = server_id
    parameter_dict['group_id'] = server_group_id
    parameter_dict['upload_folder'] = app.config["UPLOAD_FOLDER"]
    parameter_dict['funcx_token'] = session['tokens']['funcx_service']['access_token']
    parameter_dict['search_token'] = session['tokens']['search.api.globus.org']['access_token']
    parameter_dict['openid_token'] = session['tokens']['auth.globus.org']['access_token']
    with open(os.path.join(upload_folder, 'parameter.yaml'), 'w') as f:
        yaml.dump(parameter_dict, f, default_flow_style=False)
    base_folder = f'{server_group_id}/{EXP_DIR}'

    # Start the server
    task_arn = ecs_run_task([base_folder])

    # Upload the configuration file to AWS S3
    task_id = ecs_arn2id(task_arn)
    model_key        = f'{server_group_id}/{EXP_DIR}/{task_id}/model.py'
    parameter_fp     = os.path.join(upload_folder, 'parameter.yaml')
    parameter_key    = f'{server_group_id}/{EXP_DIR}/{task_id}/parameter.yaml'
    appfl_config_fp  = os.path.join(upload_folder, 'appfl_config.yaml')    
    appfl_config_key = f'{server_group_id}/{EXP_DIR}/{task_id}/appfl_config.yaml'

    if not dynamodb_append_task(server_group_id, task_arn, exp_name):
        flash("An error occurs when adding the task!")
        return redirect(request.referrer)
    if model_fp is not None:
        if not s3_upload(S3_BUCKET_NAME, model_key, model_fp, delete_local=True):
            flash("Error: The custom model file is not uploaded successfully!")
            return redirect(request.referrer)
    if not s3_upload(S3_BUCKET_NAME, appfl_config_key, appfl_config_fp, delete_local=True):
        flash("Error: The configuration file is not uploaded successfully!")
        return redirect(request.referrer)
    if not s3_upload(S3_BUCKET_NAME, parameter_key, parameter_fp, delete_local=True):
        flash("Error: The parameter file is not uploaded successfully!")
        return redirect(request.referrer)

    flash("The federation is started!")
    return redirect(url_for('dashboard'))

@app.route('/task-delete', methods=['POST'])
@authenticated
def task_delete():
    """Delete selected tasks in a certain group."""
    group_id = request.form['task_group']
    for key in request.form:
        if key != 'task_group':
            task_arn = request.form[key]
            ecs_task_delete(task_arn, group_id)
    return redirect(request.referrer)

@app.route('/task-status', methods=['GET'])
@authenticated
def task_status():
    """Check the status of given tasks."""
    task_status = {}
    for key in request.args:
        task_arn = request.args[key]
        task_id = ecs_arn2id(task_arn)
        task_status[task_id] = {}
        status = ecs_task_status(task_arn)
        task_status[task_id]['status'] = status
    return task_status

class EndpointStatus(Enum):
    UNSET = -2              # User does not specify an endpoint
    INVALID = -1            # User give an invalid endpoint
    INACTIVE = 0            # Endpoint is not active (not started)
    ACTIVE_CPU = 1          # Endpoint does not have GPU
    ACTIVE_GPU = 2          # Endpoint has GPU available

def endpoint_test():
    """Endpoint health status test function."""
    import torch
    return torch.cuda.is_available()

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

@app.route('/tensorboard-log/<server_group_id>/<task_id>', methods=['GET'])
@authenticated
def tensorboard_log_page(server_group_id, task_id):
    """
    Return the tensorboard log page for the appfl run of group `server_group_id`
    TODO: Include a 404 page if there is no log file available
    TODO: This implementation still launches a new TensorBoard server every time 
        the /info route is visited, so you may want to modify the code to launch 
        the server only once and keep it running in the background, or use a 
        different method of embedding the TensorBoard page (such as using 
        JavaScript to load the page dynamically).
    """
    # Download the tensorboard output from S3
    gc          = load_group_client(session['tokens']['groups.api.globus.org']['access_token'])
    server_info = gc.get_group(server_group_id, include=['my_memberships'])['my_memberships'][0]
    server_id   = server_info['identity_id']
    key_folder  = f'{server_group_id}/{EXP_DIR}/{task_id}/tensorboard'
    log_dir = os.path.join(app.config['UPLOAD_FOLDER'], server_group_id, server_id, task_id, 'logs', 'tensorboard')
    if not s3_download_folder(S3_BUCKET_NAME, key_folder, log_dir):
        flash("The tensorboard page is not available for this experiment yet!")
        return redirect(request.referrer)
    
    # Launch the tensorboard on an available port
    if os.path.isdir(log_dir):
        # tb_process = subprocess.Popen(['tensorboard', f'--logdir={log_dir}', f'--host=0.0.0.0', f'--port={port}'])
        # url = f'http://localhost:{port}'
        # tb_pid = tb_process.pid
        tb = program.TensorBoard()  
        tb.configure(argv=[None, '--logdir', log_dir, '--host', '0.0.0.0', '--port', f'0'])
        url = tb.launch()
        port = url.split(':')[-1]
        if app.config["SESSION_COOKIE_DOMAIN"]:
            # Use reverse proxy for the tensorboard server
            url = f'https://{app.config["SESSION_COOKIE_DOMAIN"]}/tb/{port}'
        else:
            # For local test
            url = f'http://localhost:{port}'
        return render_template('tensorboard_log.jinja2', url=f'{url}')
    else:
        flash("Error: There is not log file for this server!")
        return redirect(request.referrer)

def get_system_stats():
    """Get system and network utilization statistics."""
    """Ensure necessary dependencies are installed."""
    import subprocess
    import pkg_resources

    DEPENDENCIES = [
        'psutil',
        'pynvml'
    ]

    installed_packages = pkg_resources.working_set
    installed_packages_list = sorted(["%s==%s" % (i.key, i.version)
        for i in installed_packages])

    for dependency in DEPENDENCIES:
        if dependency not in installed_packages_list:
            subprocess.check_call(["python3", "-m", "pip", "install", dependency])

    import psutil
    try:
        import pynvml

        pynvml.nvmlInit()
        handle = pynvml.nvmlDeviceGetHandleByIndex(0) # Assuming one GPU.

        # Get GPU utilization
        gpu_utilization = pynvml.nvmlDeviceGetUtilizationRates(handle).gpu

        # Don't forget to shut down the NVML library.
        pynvml.nvmlShutdown()

    except Exception as e:
        gpu_utilization = "N/A"
        print(f"Error: {e}. GPU utilization will not be available.")

    # Get CPU, memory, and network stats.
    cpu_utilization = psutil.cpu_percent()
    memory_utilization = psutil.virtual_memory().percent
    bytes_sent = psutil.net_io_counters().bytes_sent
    bytes_received = psutil.net_io_counters().bytes_recv

    return {
        "CPU utilization": cpu_utilization,
        "Memory utilization": memory_utilization,
        "GPU utilization": gpu_utilization,
        "Bytes Sent": bytes_sent,
        "Bytes Received": bytes_received
    }


@app.route('/resources_monitor_data', methods=['GET', 'POST'])
@authenticated
def resources_monitor_data():
    # Retrieve the parameters and parse the JSON
    client_endpoints = request.get_json().get('client_endpoints', [])
    if client_endpoints is None:
        client_endpoints = []
    endpoint_resources_data = {}
    endpoint_status = {}
    for endpoint_id in client_endpoints:
        endpoint_status[endpoint_id] = EndpointStatus.UNSET.value
    fxc = get_funcx_client(session['tokens'])
    func_id = fxc.register_function(endpoint_test)
    monitor_func_id = fxc.register_function(get_system_stats)
    for endpoint_id in endpoint_status:
        if endpoint_id == '0': continue
        try:
            task_id = fxc.run(endpoint_id=endpoint_id, function_id=monitor_func_id)
            for _ in range(6):
                try:
                    result = fxc.get_result(task_id)
                    if result is not None:
                        endpoint_resources_data[endpoint_id] = result
                        break
                    time.sleep(1)
                except funcx.errors.error_types.TaskPending:
                    time.sleep(1)
                    continue
                except:
                    endpoint_resources_data[endpoint_id] = {'error': 'Failed to get result'}
                    break
        except:
            endpoint_resources_data[endpoint_id] = {'error': 'Failed to run monitoring function'}
            break

    return jsonify(endpoint_resources_data)

@app.route('/resources_monitor')
def resources_monitor():
    client_endpoints = request.args.get('client_endpoints')
    client_names = request.args.get('client_names')

    # Because we passed the data as JSON, we need to parse it back into a Python list
    import json
    client_endpoints = json.loads(client_endpoints)
    client_names = json.loads(client_names)

    return render_template('resources_monitor.jinja2', 
                       client_endpoints=client_endpoints, 
                       client_names=client_names)

@app.errorhandler(413)
def error413(e):
    """Error handler for uploading file exceeding the maximum size."""
    flash(f'Error: File is larger than the maximum file size: {float(app.config["MAX_CONTENT_LENGTH"]/(1024*1024)):2f}MB!')
    return redirect(request.referrer)
