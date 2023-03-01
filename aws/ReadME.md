# Deploy the Web App to AWS EC2 Instance
This is how to create an EC2 instance. Please allocate some amount of disk memory (>16GB) for running this application. [**Start AWS EC2 Instance**](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html)


1. Connect to your EC2 instance using ssh
    ```
    ssh -i your-pem.pem ec2-user@your-ec2-instance-ipv4dns
    ```

2. Install `git` in your EC2 instance
    ```
    sudo yum update -y
    sudo yum install git -y
    ```

3. Generate `ssh-key` for your EC2 instance, then copy the key to Github to create an ssh-key for accessing github inside the EC2 instance.
    ```
    ssh-keygen -t rsa -b 4096 -C "your-email@illinois.edu"
    cat ~/.ssh/id_rsa.pub
    ```

4. Allocate more memory from disk using swapfile. Run the following command to create a swap file with a size of 8 GB (you can adjust the size as needed):
    ```
    sudo fallocate -l 8G /swapfile
    ```
    Set the correct permissions for the swap file by running the following command:
    ```
    sudo chmod 600 /swapfile
    ```
    Set up the swap space on the file by running the following command:
    ```
    sudo mkswap /swapfile
    ```
    Enable the swap file by running the following command:
    ```
    sudo swapon /swapfile
    ```
    To make the swap file permanent across reboots, add an entry for the swap file to the `/etc/fstab` file. Open the `/etc/fstab` file in a text editor and add the following line at the end of the file:
    ```
    /swapfile swap swap defaults 0 0
    ```
5. Install `conda`
    ```
    mkdir conda
    cd conda
    wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
    bash Miniconda3-latest-Linux-x86_64.sh
    source ~/.bashrc
    ```

6. Clone the repository for APPFL and checkout to the funcx branch
    ```
    cd ~
    git clone git@github.com:Zilinghan/FL-as-a-Service.git FaaS
    cd FaaS
    git checkout funcx
    ```

7. Configure the environment
    ```
    conda create -n appfl python=3.8
    conda activate appfl
    pip install -r requirements.txt
    pip install -e .
    ```

8. Clone the repository for the web application: Federated Learning as a Service.
    ```
    cd ~
    git clone git@github.com:Zilinghan/FaaS-web.git
    ```

9. Set the web application configurations: Go to the AWS EC2 console to get your EC2 instance **Public** IPv4 address, and replace `YOUR_IP` below to that IP address. 

    [**Important Note**: If the flask app is running on port 8000, please make sure that you add an inbound rule to allow traffic on that port. (Add rule: select "Custom TCP Rule", enter 8000 for "Port Range", and enter "0.0.0.0/0" for "Source")]
    ```
    cd FaaS-web
    sed -i 's/localhost/0.0.0.0/' run_portal.py
    sed -i '4,//s/localhost/YOUR_IP/' portal/portal.conf
    echo "SESSION_COOKIE_DOMAIN = 'YOUR_IP'" >> portal/portal.conf
    ```

10. Create your own App registration for use in the portal.
* Visit the [Globus Developer Pages](https://developers.globus.org) to register an App.
* If this is your first time visiting the Developer Pages you'll be asked to create a Project. A Project is a way to group Apps together.
* When registering the App you'll be asked for some information, including the redirect URL and any scopes you will be requesting.
    * Redirect URL: `https://YOUR_IP:8000/authcallback` (note: replace YOUR_IP with your EC2 instance public IPv4 address).

* After creating your App the client id and secret can be copied into this project in the following two places:
    * `portal/portal.conf` in the `PORTAL_CLIENT_ID` and `PORTAL_CLIENT_SECRET` properties.
    * `service/service.conf` where the `PORTAL_CLIENT_ID` is used to validate the access token that the Portal sends to the Service.

11. Start running the portal program, and then point your browser to `https://YOUR_IP:8000/`
    ```
    ./run_portal.py
    ```

12. To run the portal server on the background, we use Systemd boot manager for restart the server if the EC2 restarts or reboots for some reason. We create a `<projectname>.service` file in `/etc/systemd/system` folder and specify what would happen when the system reboots. 

    First create the file:
    ```
    sudo vim /etc/systemd/system/web.service
    ```
    Then copy the following contents into this file. **Note**: you need to replace the value for the `WorkingDirectory` to the directory of your app (containing `run_portal.py`). For the first argument of `ExecStart`, it should be the **absolute** path of your python, which can be obtained by running `which python`.
    ```
    [Unit]
    Description=Web App Deployment
    After=network.target
    [Service]
    User=ec2-user
    WorkingDirectory=/home/ec2-user/FaaS-web
    ExecStart=/home/ec2-user/miniconda3/bin/python run_portal.py
    Restart=always
    [Install]
    WantedBy=multi-user.target
    ``` 
    Then enable the service
    ```
    sudo systemctl daemon-reload
    sudo systemctl start web
    sudo systemctl enable web
    ```