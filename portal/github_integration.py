from flask import Blueprint, session, request, render_template, jsonify
import requests
from portal import app

''' 
    Integrated the functionality to upload file from github
    To use this, 
    set GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET in portal.conf according to the Oauth app
    and set GITHUB_REDIRECT_URI in portal.conf and Oauth app to the route <root_page>/github_integration/github_callback
'''


github_bp = Blueprint('github_integration', __name__)

# Your GitHub OAuth app's client_id and client_secret
client_id = app.config['GITHUB_CLIENT_ID']
client_secret = app.config['GITHUB_CLIENT_SECRET']

# The callback URL you set in your GitHub OAuth app
redirect_uri =app.config['GITHUB_REDIRECT_URI']

def get_repos(access_token):
    # Use the access token to fetch user's repositories
    repos_response = requests.get(
        "https://api.github.com/user/repos",
        headers={
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }
    )
    
    if repos_response.status_code == 200:
        # Get the repository data from the response
        return repos_response.json()
    
    return None

@github_bp.route("/github_callback")
def github_callback():
    # Check if the access_token is already in the session
    if 'access_token' in session and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        repos = get_repos(session['access_token'])
        if repos:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify(repos)  # Return the repositories data as JSON
            else:
                return render_template("github-selection/authorized.jinja2")
        else:
            return "Error occurred when fetching repos."

    # Retrieve the code query parameter from the request
    code = request.args.get('code')
    
    # Prepare the data for the POST request to exchange code for an access token
    data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'redirect_uri': redirect_uri
    }

    # Make the POST request
    response = requests.post('https://github.com/login/oauth/access_token', data=data, headers={'Accept': 'application/json'})

    # Check the response status
    if response.status_code == 200:
        response_json = response.json()
        if 'access_token' in response_json:
            # Get the access token from the response
            access_token = response.json()['access_token']
            
            # Save the access token (e.g., in the session, a user object in a database, etc.)
            # In this example, we'll just use Flask's session
            session['access_token'] = access_token

            # Get the user's data
            user_response = requests.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"token {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )

            if user_response.status_code == 200:
                # Get the user's login (username) from the response and save it in the session
                session['username'] = user_response.json()['login']

            # Use the access token to fetch user's repositories
            repos = get_repos(access_token)
            if repos:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify(repos)  # Return the repositories data as JSON
                else:
                    return render_template("github-selection/authorized.jinja2")
        else:
            # Log the response from GitHub
            print(f"Unexpected response from GitHub: {response_json}")
            return "Error occurred."

    # Handle the error
    return "Error occurred."


@github_bp.route("/selected_repo/<repo_owner>/<repo_name>/branches")
def selected_repo(repo_owner, repo_name):
    access_token = session.get('access_token')

    branches_response = requests.get(
        f"https://api.github.com/repos/{repo_owner}/{repo_name}/branches",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }
    )

    if branches_response.status_code == 200:
        # Extract the files data from the response
        branches_data = branches_response.json()

        return jsonify(branches_data)  # Return the files data as JSON

    else:
        print(f"Unexpected response from GitHub: {branches_response}")
        # Handle errors
        return "Error occurred."

@github_bp.route("/selected_repo/<repo_owner>/<repo_name>/<branch_name>/", defaults={'path': ''})
@github_bp.route("/selected_repo/<repo_owner>/<repo_name>/<branch_name>/<path:path>")
def selected_branch(repo_owner, repo_name, branch_name, path):
    # Make sure the access_token is available (you might need to handle cases where it is not)
    access_token = session.get('access_token')

    # Make a request to the GitHub API to get the repository's contents
    files_response = requests.get(
        f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{path}?ref={branch_name}",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }
    )

    if files_response.status_code == 200:
        # Extract the files data from the response
        files_data = files_response.json()

        return jsonify(files_data)  # Return the files data as JSON

    else:
        # Handle errors
        print("=================", files_response)
        return "Error occurred."


@github_bp.route("/selected_file/<repo_name>/<path:file_path>")
def selected_file(repo_name, file_path):
    return jsonify(file_path)  # Return the file path as JSON

