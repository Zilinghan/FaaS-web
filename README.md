# Deploy the Web App to AWS EC2 Instance with DNS

1. Create an EC2 instance [here](https://console.aws.amazon.com/ec2/) by referring to this [guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html).

    **NOTE:** Please select **Amazon Linux 2 AMI (HVM) - Kernel 5.10, SSD Volumn Type** as your OS images. Now I select **t2.micro** as the instance type, which is very cheap for the deployment stage. For the security group, we should allow HTTP, HTTPS inbound traffic from all sources (0.0.0.0/0), and ssh from your own IP address for development. Allocate **more than 20GB** of General Purpose SSD (gp2).

2. Allocate one Elastic IP address in the AWS EC2 console, and associate it with the created EC2 instance.

3. Connect to your EC2 instance using ssh. `your-pem.pem` is a key you create in this [guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html).
    ```
    $ ssh -i your-pem.pem ec2-user@your-ec2-instance-ipv4dns
    ```

4. Install `git` in your EC2 instance.
    ```
    $ sudo yum update -y
    $ sudo yum install git -y
    ```

5. Generate `ssh-key` for your EC2 instance, then copy the key to Github to create an ssh-key for accessing github inside the EC2 instance.
    ```
    $ ssh-keygen -t rsa -b 4096 -C "your-email@illinois.edu"
    $ cat ~/.ssh/id_rsa.pub
    ```

6. Allocate more memory from SSD using swapfile. Run the following command to create a swap file with a size of 8 GB (you can adjust the size as needed).
    ```
    $ sudo fallocate -l 8G /swapfile
    ```
    Set the correct permissions for the swap file by running the following command:
    ```
    $ sudo chmod 600 /swapfile
    ```
    Set up the swap space on the file by running the following command:
    ```
    $ sudo mkswap /swapfile
    ```
    Enable the swap file by running the following command:
    ```
    $ sudo swapon /swapfile
    ```
    To make the swap file permanent across reboots, add an entry for the swap file to the `/etc/fstab` file. Open the `/etc/fstab` file in a text editor and add the following line at the end of the file:
    ```
    /swapfile swap swap defaults 0 0
    ```

7. Install `conda`.
    ```
    $ mkdir conda
    $ cd conda
    $ wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
    $ bash Miniconda3-latest-Linux-x86_64.sh
    $ source ~/.bashrc
    ```

8. Clone this repository.
    ```
    $ cd ~
    $ git clone git@github.com:Zilinghan/FaaS-web.git
    $ cd FaaS-web
    ```

9. Creat virtual environment and install dependencies.
    ```
    $ conda create -n flaas python=3.8
    $ conda activate flaas
    $ pip install -r requirements.txt
    ```

10. Go to the [console of AWS IAM](https://console.aws.amazon.com/iam/), and create a user with the following policies: <span style="color:red">[TODO: We can narrow the access policy set later depending on the specific functionality usage.]</span>
* AmazonDynamoDBFullAccess
* AmazonECS_FullAccess	
* AmazonS3FullAccess
* CloudWatchFullAccess

11. Then go the the **Security credentials** and create an access key. Keep the access key and secret access key in a secure place.

12. Run `aws configure` in the EC2 command line, and then enter the information for the created IAM user (access key, secret access key, region name)

13. Generate SSL certicate and private key for running the Flask application on HTTPS <span style="color:red">[TODO: maybe generate one for everyone to use.]</span> To do this, first install `openssl` on your EC2.
    ```
    $ sudo yum install openssl
    ```
    Then generate a self-signed SSL certificate and private key in the `ssl` folder. The following command generate a self-signed SSL certificate valid for 365 days.
    ```
    $ cd ssl
    $ openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
    $ cd ..
    ```

14. Associate the domain name purchased from AWS Route 53 (e.g. appflx.link) with the EC2 instance.
* Go to [Route 53 console](https://console.aws.amazon.com/route53/) and create a public hosted zone using your domain name (`appflx.link`) if it does not exist.
* Add two records `appflx.link` and `www.appflx.link` with **Type A** to the record table, and set the Value/Route traffic to the Elastic IP address of your EC2 instance.


15. Create your own globus app registration.
* Visit the [Globus Developer Page](https://developers.globus.org) and click 'Register your app with Globus'.
* If this is your first time visiting the developer page, you'll be asked to add a project. A project is a way to group apps together.
* After creating the project, you can 'add new app', where you'll be asked for some information, including the app name and redirect URL.
    * Redirect URL: `https://YOUR_DOMAIN_NAME/authcallback` (e.g. https://appflx.link/authcallback)
* Copy the 'Client ID' and create a 'Client Secret' for later use.

16. Modify the configuration file using `sudo vim portal/portal.conf`, and make the following changes.
* For `SEVER_NAME`, replace `localhost:8000` by your own domain name such as `appflx.link`.
* For `DEBUG`, change it to `False`.
* For `PORTAL_CLIENT_ID`, change it to the Client ID you obtain from the Globus Developer Page.
* For `PORTAL_CLIENT_SECRET`, change it to the Client Secret you obtain from the Globus Developer Page.
* Add `SESSION_COOKIE_DOMAIN = 'YOUR_DOMAIN_NAME'` at the end of the file, and replace `YOUR_DOMAIN_NAME` with your own domain name such as `appflx.link`.

17. Install `gunicorn` for running the Flask app.
    ```
    $ pip install gunicorn
    ```

18. Run Gunicorn with your generated ssl certificate and key with 16 workers (few workers will be very slow).
    ```
    $ gunicorn run_portal:app --bind 0.0.0.0:8000 --certfile ssl/cert.pem --keyfile ssl/key.pem --workers 16
    ```

19. Now let's use systemd to manage Gunicorn. Systemd is a boot manager for Linux, which can be used to restart gunicorn if the EC2 restarts or reboots for some reason. 
* First create a `<projectname>.service` file in `/etc/systemd/system` folder and specify what would happen when the system reboots. 
    ```
    $ sudo vim /etc/systemd/system/web.service
    ```
* Copy the following contents into the file. **Note**: you need to replace the value for the `WorkingDirectory` to the directory of your app (containing `run_portal.py`). For the first argument of `ExecStart`, it should be the **absolute** path of your `gunicorn`, which can be obtained by running `which gunicorn`.
    ```
    [Unit]
    Description=Web App Deployment
    After=network.target
    [Service]
    User=ec2-user
    WorkingDirectory=/home/ec2-user/FaaS-web
    ExecStart=/home/ec2-user/miniconda3/envs/faas/bin/gunicorn run_portal:app --bind 0.0.0.0:8000 --certfile ssl/cert.pem --keyfile ssl/key.pem --workers 16
    Restart=always
    [Install]
    WantedBy=multi-user.target
    ```
* Finally enable the service
    ```
    $ sudo systemctl daemon-reload
    $ sudo systemctl start web
    $ sudo systemctl enable web
    ```

20. Now, we run Nginx reverse proxy to accept and route HTTP and HTTPS requests to Gunicorn.
* Install Nginx <span style="color:red">Note: this may not work, but it will prompt you how to install it if fails</span>
    ```
    $ sudo yum install nginx
    ```
* Start the Nginx service.
    ```
    $ sudo systemctl start nginx
    $ sudo systemctl enable nginx
    ```
* Check if you have `/etc/nginx/sites-available` directory, if not, following the steps below. If you have this, skip this point and go to next point.
    ```
    $ sudo mkdir /etc/nginx/sites-available
    $ sudo mkdir /etc/nginx/sites-enabled
    $ include /etc/nginx/sites-enabled/*;
    $ cd /etc/nginx/sites-available
    $ sudo touch default
    $ sudo ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
    ```

21. Install an SSL certificate using Certbot. But let's first install Certbot.
    ```
    $ sudo yum install -y epel-release
    $ sudo yum install -y certbot python2-certbot-nginx
    ```
    If you are using Amazon Linux 2, you might need to enable the 'extras' repository for the certbot package:
    ```
    $ sudo amazon-linux-extras enable epel
    $ sudo yum clean metadata
    $ sudo yum install -y certbot python2-certbot-nginx
    ```

22. Run Certbot to obtain and install the SSL certificate: Replace `appflx.link` and `www.appflx.link` with your domain name and desired subdomain. Certbot will automatically configure Nginx to use the SSL certificate and redirect HTTP traffic to HTTPS.
    ```
    $ sudo certbot --nginx -d appflx.link -d www.appflx.link
    ```

23. Now, it's time to change the content of `/etc/nginx/sites-available/default` to the following. Replace `YOUR_DOMAIN_NAME` to your own domain name such as `appflx.link`. (This file is available [here](portal/default))
    ```
    server {
        server_name YOUR_DOMAIN_NAME;

        location / {
            proxy_pass https://127.0.0.1:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        listen [::]:443 ssl ipv6only=on; # managed by Certbot
        listen 443 ssl; # managed by Certbot
        ssl_certificate /etc/letsencrypt/live/YOUR_DOMAIN_NAME/fullchain.pem; # managed by Certbot
        ssl_certificate_key /etc/letsencrypt/live/YOUR_DOMAIN_NAME/privkey.pem; # managed by Certbot
        include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
        ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
    }

    server {
        if ($host = YOUR_DOMAIN_NAME) {
            return 301 https://$host$request_uri;
        } # managed by Certbot
        listen 80;
        listen [::]:80;
        server_name YOUR_DOMAIN_NAME;
        return 404; # managed by Certbot
    }
    ```

24. Restart Nginx after updating the default configuration.
    ```
    $ sudo systemctl restart nginx
    ```

25. By default, the certificate are valid for 90 days. To automatically renew the certificates before they expire, you can set up a cron job or a systemd timer.
* Open the crontab for editing:
    ```
    $ sudo crontab -e
    ```
* Add the following line to attempt renewal twice a day and restart your Flask app upon success:
    ```
    0 */12 * * * certbot renew --quiet --post-hook "systemctl reload nginx"
    ```

26. Now, the Flask application should be accessible via your domain (e.g., https://appflx.link) with a valid SSL certificate. The configuration above also ensures that any HTTP requests are redirected to HTTPS.


