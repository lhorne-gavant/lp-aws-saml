# lp-aws-saml

This repository contains the LastPass AWS SAML login tool. Compatible with Python3.

If you are using LastPass Enterprise SAML with AWS, then please raise a ticket asking LastPass to merge my changes with their master branch.  

It retrieves a SAML assertion from LastPass and then converts it into credentials for use with ```aws```.

## Requirements

You will need python with the Amazon boto3 module and the AWS CLI tool.
The latter may be installed with pip:
```
    # pip3 install boto3 awscli requests lastpass-python
```
On recent Mac platforms, you may need to pass --ignore-installed:

```
    # pip3 install boto3 awscli requests lastpass-python  --ignore-installed
```

You will also need to have integrated AWS with LastPass SAML through the
AWS and LastPass management consoles.  See the SAML setup instructions on the
LastPass AWS configuration page for more information.

## Usage

First you will need to look up the LastPass SAML configuration ID for the AWS
instance you wish to control.  This can be obtained from the generated
Launch URL: if the launch URL is ```https://lastpass.com/saml/launch/cfg/25```
then the configuration ID is ```25```.

Then launch the tool to login to lastpass.  You will be prompted for
password and optionally the AWS role to assume:

```
$ ./lp-aws-saml.py user@example.com 25
Password:
A new AWS CLI profile 'user@example.com' has been added.
You may now invoke the aws CLI tool as follows:

    aws --profile user@example.com [...]

This token expires in 8 hours or less.
```

The duration is dependent on the configuration of the role, if you set a duration of less than 8 hours, it will be less. If you're feeling helpful, maybe you could update this to query the max duration, use the max duration and then change the message appropriately.

Once completed, the ```aws``` tool may be used to execute commands as that
user by specifying the appropriate profile.

