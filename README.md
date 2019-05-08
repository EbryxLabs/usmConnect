# Introduction
Alerts on slack about disconnection of USM (AlientVault) sensors by scraping the USM console via selenium. Remote selenium server is used for browser automation while code can run anywhere that can access the endpoint of selenium remote server host.  
Confguration file in `.json` format is given in encrypted form and program decrypts it using AES keys provided in environment. For more information on encryption / decryption, look at [**opencrypt**](https://pypi.org/project/opencrypt/) library of python.

## Pre-Requisites
You can deploy the project using cloudformation but it assumes the following architecture.
- A deployment package archive placed on S3 bucket.
- AESIV & AESKEY used for encrypting the config file.
- Accessible URI to encrypted config file.
- Private subnets to deploy lambda on a AWS VPC having a NAT Gateway for outgoing internet access.
- Security Group to attach lambda with allowing traffic to EC2 machine hosting selenium server and allowing all outgoing traffic.

Private subnets and security groups are needed to be mentioned in cloudformation as parameters and if you have not setup the architect, you'd have to make one before using cloudformation template for deployment.

### Lambda & EC2 connection
AWS Lambda will need an internal connection with a EC2 machine that will be hosting the selenium server. Using the internal IP of EC2 machine, lambda will make remote connection to make browser work since using it directly on Lambda is not natively supported and is prone to deployment package size limitations.  
To make lambda access EC2 internally, they both need to be in same VPC while lambda needs to be hosted on private subnet(s) inside that VPC. Lastly, the targeted VPC must have a NAT Gateway allowing traffic to outside network since lambda would need that to fetch config file from the normal internat.  
> Using EC2 internal connection is strongly recommended since it prevents security concerns related to connection between lambda and EC2 over plain HTTP protocol.  

See more information about accessing internal resources from lambda [here.](https://docs.aws.amazon.com/lambda/latest/dg/vpc.html)


## AWS Lambda Deployment
- Create a deployment package, place it to S3 so you can specify it in your cloudformation process. You need make an archive containing all the required libraries as mentioned in `requirements.txt` file and python scripts containing the code.
    ```
    cd /path/to/env/lib/pythonx.x/site-packages/
    zip -r9 <archive-name> ./
    ```
    From root directory of the project, add python scripts to the same archive you created above:
    ```
    zip -g <archive-name> script.py
    ```
- Or just execute following command to create lambda deployment package named `lambda_code-YYYY-mm-ddTHH-MM-SSZ.zip` command
  ```
  /bin/bash lambda_package_creator.sh /path/to/env/lib/pythonx.x/site-packages/
  ```

## Configuration
A sample configuration file is shown below:
```
{
  "usm_host_url": "<usm-console-url>",
  "usm_username": "<usm-username>",
  "usm_password": "<usm-password>",
  "selenium_host": "<selenium-remote-server>",
  "whitelist": ["Sensor-1", ...],
  "slack_hooks": ["<hook-1-url>", ...]
}
```
**`usm_host_url`**, **`usm_username`** and **`usm_password`** are the url of USM console, username and password to authenticate respectively. **`selenium_host`** is the endpoint of selenium server that it expects the connections to be made at. For example, if your code and server at running locally, the default endpoint exposed by selenium server is `http://127.0.0.1:4444/wd/hub`  
Depending upon the internal IP of EC2 machine and the port you exposed while starting the selenium server, your endpoint should be: `http://<EC2-internal-IP>:<PORT>/wd/hub`  
**`whitelist`** is a list of sensor names or IP to whitelist them from program. You won't get any alert for whitelisted sensors. Lastly, **`slack_hooks`** are a list of URI endpoints for alerting on slack.
> Use credentials of a read-only separate account of USM for this program to minimize its scope. Program just needs to read the sensors and hence least-privilege should be respected in this aspect.

## Slack Alerts
Program will notify on slack when:
- A sensor is down on USM.
- Automation of USM console couldn't work as expected.
- Connection to Selenium server couldn't be established.
