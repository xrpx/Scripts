#!/usr/bin/env bash

# Author:		xrpx
# Description:		Script to generate AWS MFA token and execute a set of commands
# Last Modified:	August 18, 2014

function aws_mfa {
    if [[ -z "$AWS_ACCESS_KEY" ]] ; then
        echo "Please set AWS_ACCESS_KEY and AWS_SECRET_KEY"
        return 1
    fi
 
    if [[ -z "REAL_AWS_ACCESS_KEY" ]] ; then
        REAL_AWS_ACCESS_KEY=$AWS_ACCESS_KEY
        REAL_AWS_SECRET_KEY=$AWS_SECRET_KEY
    fi
 
    if [[ ! -r ~/.aws_mfa_id ]] ; then
        echo "Please put your MFA ID into ~/.aws_mfa_id, can be found in IAM User Info"
        return 1
    fi
 
    read junk AWS_ACCESS_KEY AWS_SESSION_TOKEN_EXPIRATION AWS_SECRET_KEY AWS_SECURITY_TOKEN < <(
        unset AWS_SECURITY_TOKEN
        AWS_ACCESS_KEY=$REAL_AWS_ACCESS_KEY
        AWS_SECRET_KEY=$REAL_AWS_SECRET_KEY
        aws sts get-session-token \
            --output text \
            --serial-number $(<~/.aws_mfa_id) \
            --token-code $(
                if [[ "$DISPLAY" ]] ; then
                    ssh-askpass Enter MFA Code
                else
                    read -p "Enter MFA Code: "
                    echo $REPLY
                fi
            )
    )
    if [[ $? == 0 ]] ; then
        export AWS_SECURITY_TOKEN AWS_ACCESS_KEY=$AWS_ACCESS_KEY AWS_SECRET_KEY=$AWS_SECRET_KEY AWS_DELEGATION_TOKEN=$AWS_SECURITY_TOKEN
        echo Your temporary AWS credentials are valid till $(date -d $AWS_SESSION_TOKEN_EXPIRATION)
    else
        return 1
    fi

# Do what you need in here
  ec2-describe-instances i-00000000

}

aws_mfa
