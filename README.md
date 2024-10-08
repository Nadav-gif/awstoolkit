# awstoolkit

AWS Toolkit (`awstoolkit`) is a Python utility designed to help interacting with AWS, and particularly to help with activities that can be time-consuming in the Identity and Access Management (IAM) service.
When AWS verify if an identity has permissions to run a certain action, there are several factors that can be used to grant or remove permissions. Those factors need to be concidered during the verification process.
The flow of the process (and its components), as explained by AWS is:

![image](https://github.com/user-attachments/assets/432b0f5b-f233-429c-8774-75244325a2ae)

`awstoolkit` takes into consideration the Deny evaluation, Organizaions SCPs, Identity-based policies and IAM permissions boundaries factors.

## Features

1. **`who-can`**: 
   - Provides a list of AWS identities (users / roles) that are authorized to perform a given AWS action.
   - It also shows on which resources the action can be performed, and which are denied.
   - The output format will be CSV by default, it can be changed to JSON using the `--output_format` parameter
   - This feature can help you answer the questions such as: "Which identities in my account can terminate EC2 instances?", "Which identies can execute queries on my RDS instances" etc.

2. **`can-do`**: 
   - Checks if a specific AWS identity can perform a particular AWS action.
   - The output format will be JSON.
   - The feature will answer questions such as: "Is the user 'staging-user' can execute Lambda functions?".
   
3. **`policy-diff`**: 
   - Compares two AWS IAM policies and display differences. It can help to quickly spot changes and sared properties between policies.
   - The output format will be CSV by default, it can be changed to JSON using the `--output_format` parameter

## Installation

To install `awstoolkit`, clone the repository and install the required dependencies:

```bash
git clone https://github.com/Nadav-gif/awstoolkit.git
cd awstoolkit
pip install -r requirements.txt

To use the project as a pyton module
python setup.py install
```

## Usage
There are two ways to usage this project - by running a python script, and also programmatically by importing it as module.
To run the features in this project, there are several "list" and "get" actions in the IAM service that are required. Make sure that the identity which is used to run the feature is attached with `iam:List*` and `iam:Get*` permissions.

To include the organization's SCPs in the process, make sure to have the `organizations:ListParents`, `organizations:DescribePolicy` and `organizations:ListPoliciesForTarget` permissions. In addition, since SCPs can be read only from the management account, you need to use the authentication parameters of an identity in the management account (with the said permissions) and then use the `role_arn` parameter to assume a role in a different account. 

### Command Line Usage
      Get all identities in the account that can run ec2:StartInstances and on which resources. Authenticate by using AWS profile "default".
         python awstoolkit.py who-can -p default -a ec2:startinstances
      Get all identities in the account that can run lambda:UpdateFunctionCode and on which resources. Authenticate by using AWS IAM user access keys. Also, take under consideration the organization's SCPs.
         python awstoolkit.py who-can --access-key AKIA... --secret-key SECRET... --action  lambda:UpdateFunctionCode -of json --include_scp

      Get the differences between policy_a and policy_b. Authenticate by using AWS profile and then assuming the role "MonitorRole". The output will be printed to the directory C:\users\<username>\Desktop\new_dir
         python awstoolkit.py policy-diff -p default -r arn:aws:iam::<account-id>:role/MonitorRole -p1 arn:aws:iam::<account-id>:policy/policy_a -p2 arn:aws:iam::<account-id>:policy/policy_b -o C:\users\<username>\Desktop\new_dir
      
### Usage as a Python module
      Get all identities in the account that can run ec2:StartInstances and on which resources. Authenticate by using the AWS profile "default". 
         from awstoolkit import who_can
         response = who_can(action="ec2:startinstances", profile="default")

      Return if the user "prod-user" has permission to run "ec2:StartInstances". If the user can't run this command the result will be False.
         from awstoolkit import can_do
         response = can_do(action="ec2:startinstances", access_key="AKIA...", secret_key="SECRET...", identity="arn:aws:iam::<account-id>:user/prod-user")
         
      Get the differences between policy_a and policy_b. Authenticate by using AWS profile and then assuming the role "MonitorRole". The output format is JSON.
         from awstoolkit import policy_diff
         response = policy_diff(profile="default", role_arn="arn:aws:iam::<account-id>:role/MonitorRole", p1="arn:aws:iam::<account-id>:policy/policy_a", p2="arn:aws:iam::<account-id>:policy/policy_b")
      
