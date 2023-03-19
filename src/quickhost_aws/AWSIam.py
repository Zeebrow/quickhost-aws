# Copyright (C) 2022 zeebrow
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import json
import logging
from configparser import ConfigParser
from pathlib import Path

from botocore.exceptions import ClientError
import boto3

from quickhost import scrub_datetime

from .utilities import QuickhostUnauthorized, Arn
from .constants import AWSConstants
from .AWSResource import AWSResourceBase

logger = logging.getLogger(__name__)


class Iam(AWSResourceBase):
    """
    Manage AWS IAM (account-global) quickhost resources' lifecycle during
    `main.py aws init` and future `main.py aws uninstall` actions.
    """
    def __init__(self, profile, region):
        self.caller_info = self.get_caller_info(profile=profile, region=region)
        self.iam_user = AWSConstants.DEFAULT_IAM_USER
        self.iam_group = AWSConstants.DEFAULT_IAM_GROUP
        session = self._get_session(profile=profile, region=region)
        self.client = session.client('iam')
        self.iam = session.resource('iam')

    def create(self):
        """
        Create required IAM resources for quickhost-aws to be able to operate.
        Actions:
        - Create IAM user with credentials
            - Save AWS credentials to ~/.aws/credentials
        - Create IAM group and add user
        - Create IAM policies for CRUD and attach group
        """
        rtn = {
            "iam_user_arn": None,
            "iam_group_arn": None,
        }
        # @@@ unreachable ???
        if self.caller_info['username'] == AWSConstants.DEFAULT_IAM_USER:
            logger.warning("The default quickhost user is not allowed to 'init'!")
            raise QuickhostUnauthorized("The default quickhost user is not allowed to 'init'!", operation='app init')
        rtn = {
            **self.create_iam_user_and_group()
        }
        self._create_user_config()
        self._create_user_credentials()
        self.create_policies()
        self.attach_policies_and_group()
        return rtn

    def describe(self):
        """
        Return info describing the IAM configuration for quickhost-aws.
        """
        logger.debug("AWSIam.describe")
        return {
            'credentials': self._describe_user_credentials(),
            'iam-user': self._describe_iam_user(),
            'iam-group': self._describe_iam_group(),
            'iam-policies': self._describe_iam_policies(),
        }

    def destroy(self):
        """
        Delete all quickhost-aws IAM resources.
        - Detatch IAM user from group and delete
        - Remove IAM user credentials from ~/.aws/credentials
        - Delete IAM group
        """
        iam = self.iam
        policy_arns = self.qh_policy_arns()
        user = iam.User(self.iam_user)
        group = iam.Group(self.iam_group)
        try:
            group.remove_user(UserName=self.iam_user)
            logger.info(f"Removed user '{self.iam_user}' from group '{self.iam_group}'")
        except ClientError as e:
            code = e.__dict__['response']['Error']['Code']
            if code == 'NoSuchEntity':
                logger.info(f"User '{self.iam_user}' was removed from Group '{self.iam_group}'")
            else:
                logger.error(f"Unknown error caught while deleting group: {e}")
        for action, arn in policy_arns.items():
            if arn is None:
                logger.info(f"Policy for '{action}' not found.")
                continue
            p = iam.Policy(arn)
            if p.attachment_count == 0:
                logger.info(f"Policy '{p.arn}' is not attached.")
            else:
                p.detach_group(GroupName=group.name)
                logger.info(f"Detatched policy {arn} from {group.name}... ")
            p.delete()
            logger.info(f"Deleted policy {p.arn}... ")
        try:
            group.delete()
            logger.info(f"Deleted group {group.arn}... ")
        except ClientError as e:
            code = e.__dict__['response']['Error']['Code']
            if code == 'NoSuchEntity':
                logger.info(f"Group '{self.iam_group}' doesn't exist")
            else:
                logger.error(f"Unknown error caught while deleting group: {e}")
        try:
            self._delete_user_config()
            self._delete_user_credentials()
            user.delete()
            logger.info(f"Deleted user {user.arn}... ")
        except ClientError as e:
            code = e.__dict__['response']['Error']['Code']
            if code == 'NoSuchEntity':
                logger.info(f"User '{self.iam_user}' doesn't exist")
            else:
                logger.error(f"Unknown error caught while deleting user: {e}")

    def create_policies(self):
        policy_arns = self.qh_policy_arns()
        for action, _ in policy_arns.items():
            self._create_qh_policy(action)

    def attach_policies_and_group(self) -> bool:
        rtn = False
        iam = self.iam  # @@@???
        group = iam.Group(self.iam_group)
        policy_arns = self.qh_policy_arns()
        for action, arn in policy_arns.items():
            _arn = Arn(arn)
            if _arn.is_arn(arn):
                group.attach_policy(PolicyArn=policy_arns[action])
                logger.info(f"Policy '{policy_arns[action]}' is attached to group '{group.name}'")
            else:
                logger.warning(f"Not attaching a policy for action '{action}': {_arn.error}")
                rtn = False
        try:
            group.add_user(UserName=self.iam_user)
            rtn = True
            logger.info(f"User '{self.iam_user}' is attached to group '{group.name}'")
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'UnauthorizedOperation' or code == 'AccessDenied':
                return rtn
        return rtn

    def create_iam_user_and_group(self):
        rtn = {
            "iam_user_arn": None,
            "iam_group_arn": None,
        }
        iam = self.iam
        user = iam.User(self.iam_user)
        group = iam.Group(self.iam_group)
        try:
            user = user.create(
                Path='/quickhost/',
                Tags=[ { 'Key': 'quickhost', 'Value': 'aws' }, ]
            )
            rtn['iam_user_arn'] = user.arn
            logger.info(f"Created user '{self.iam_user}'")
        except ClientError as e:
            code = e.__dict__['response']['Error']['Code']
            if code == 'EntityAlreadyExists':
                rtn['iam_user_arn'] = self.client.get_user(UserName=self.iam_user)['User']['Arn']
                logger.info(f"User '{self.iam_user}' already exists.")
                logger.info(f"User '{user}' already exists.")
        try:
            group.create(
                Path='/quickhost/',
                GroupName=self.iam_group,
                # Tags=[ { 'Key': 'quickhost', 'Value': 'aws' }, ]
            )
            rtn['iam_group_arn'] = group.arn
            logger.info(f"Created group '{self.iam_group}'")
        except ClientError as e:
            code = e.__dict__['response']['Error']['Code']
            if code == 'EntityAlreadyExists':
                rtn['iam_group_arn'] = self.client.get_group(GroupName=self.iam_group)['Group']['Arn']
                logger.info(f"Group '{self.iam_group}' already exists.")
        return rtn

    def qh_policy_arns(self):
        rtn = {
            'create': None,
            'describe': None,
            'update': None,
            'destroy': None,
        }
        qh_policies = scrub_datetime(self.client.list_policies(
            PathPrefix='/quickhost/',
        ))['Policies']

        for policy in qh_policies:
            if policy['PolicyName'] == 'quickhost-create':
                rtn['create'] = policy['Arn']
            elif policy['PolicyName'] == 'quickhost-describe':
                rtn['describe'] = policy['Arn']
            elif policy['PolicyName'] == 'quickhost-update':
                rtn['update'] = policy['Arn']
            elif policy['PolicyName'] == 'quickhost-destroy':
                rtn['destroy'] = policy['Arn']
            else:
                logger.warning(f"Found unknown quickhost policy {policy['PolicyName']}")
                continue
        return rtn

    def _create_qh_policy(self, action: str) -> str:
        existing_policies = self.qh_policy_arns()
        arn = None
        try:
            new_policy = self.client.create_policy(
                PolicyName=f"quickhost-{action}",
                Path='/quickhost/',
                PolicyDocument=json.dumps(PolicyData(self.caller_info['Account'])[action]),
                Description=f"Allow quickhost-users to {action} apps",
                Tags=[ { 'Key': 'quickhost', 'Value': 'aws' }, ]
            )
            arn = new_policy['Policy']['Arn']
            logger.info(f"created '{action}' policy '{arn}'")
        except ClientError as e:
            code = e.__dict__['response']['Error']['Code']
            if code == 'EntityAlreadyExists':
                logger.warning(f"Policy '{action}' already exists.")
                arn = existing_policies[action]
        return arn

    def _delete_user_config(self):
        current_credentials = self.describe()
        if current_credentials['credentials']['default-region'] is None:
            raise Exception("Unable to determine if config exists.")

        if current_credentials['credentials']['default-region'] != '':
            aws_config_dir = Path.home() / ".aws"
            aws_config_file = aws_config_dir / "config"
            config_parser = ConfigParser()
            config_parser.read(aws_config_file)
            cfg_deleted = config_parser.remove_section(f"profile {self.iam_user}")
            if cfg_deleted:
                with aws_config_file.open('w') as aws_cfg:
                    config_parser.write(aws_cfg)
                logger.info(f"deleted {self.iam_user} from aws config file.")
            else:
                logger.error(f"Can't delete profile for {self.iam_user}: does not exist.")
        else:
            logger.warning(f"Can't delete profile for {self.iam_user}: does not exist.")
        return False

    def _delete_user_credentials(self):
        current_credentials = self.describe()
        if current_credentials['credentials']['credentials-exist'] is None:
            logger.error("Unable to determine if credentials exist.")
            raise Exception("Unable to determine if credentials exist.")

        if current_credentials['credentials']['credentials-exist'] is True:
            aws_config_dir = Path.home() / ".aws"
            aws_credentials_file = aws_config_dir / "credentials"

            credentials_parser = ConfigParser()
            credentials_parser.read(aws_credentials_file)
            creds_deleted = credentials_parser.remove_section(self.iam_user)
            if creds_deleted:
                with aws_credentials_file.open('w') as aws_creds:
                    credentials_parser.write(aws_creds)
                logger.info(f"deleted {self.iam_user} from aws credentials file.")
            else:
                logger.error(f"No credentials for '{self.iam_user}' found to remove.")
        else:
            logger.warning(f"No credentials for '{self.iam_user}' found to remove.")
        iam = self.iam
        user = iam.User(self.iam_user)
        keys = user.access_keys.all()
        for k in keys:
            logger.info(f"Deleting access key: {k.id}...")
            k.delete()
        return

    #@@@ default region
    def _create_user_config(self, region='us-east-1', output='json'):
        current_credentials = self.describe()
        if current_credentials['credentials']['default-region'] is None:
            logger.error("Unable to determine if config exists.")
            raise Exception("Unable to determine if config exists.")

        if not current_credentials['credentials']['default-region']:
            aws_config_dir = Path.home() / ".aws"
            aws_config_file = aws_config_dir / "config"
            config_parser = ConfigParser()
            config_parser.read(aws_config_file)

            # @@@ handle aws cli setup?
            if not aws_config_dir.exists():
                logger.info(f"Creating new directory for aws credentials: {aws_config_dir.absolute()}")
                logger.warning("(not really)")
            # @@@ testme
            if self.iam_user not in config_parser:
                config_parser[f"profile {self.iam_user}"] = {
                    'region': region,
                    'output': output,
                }
                with aws_config_file.open('w') as aws_cfg:
                    config_parser.write(aws_cfg)
                logger.info(f"Added {self.iam_user} profile to {aws_config_file.absolute()}.")
                return True
            else:  # should never reach here
                logger.error(f"Profile for {self.iam_user} already exists.")
        else:
            logger.warning(f"Profile for {self.iam_user} already exists.")
        return False

    def _create_user_credentials(self):
        current_credentials = self.describe()
        if current_credentials['credentials']['credentials-exist'] is None:
            logger.error("Unable to determine if credentials exist.")
            raise Exception("Unable to determine if credentials exist.")

        if not current_credentials['credentials']['credentials-exist']:
            iam = self.iam
            aws_config_dir = Path.home() / ".aws"
            aws_credentials_file = aws_config_dir / "credentials"
            credentials_parser = ConfigParser()
            credentials_parser.read(aws_credentials_file)
            # @@@ handle aws cli setup?
            if not aws_config_dir.exists():
                logger.info(f"Creating new directory for aws credentials: {aws_config_dir.absolute()}")
                logger.warning("(not really)")
            user = iam.User(self.iam_user)
            access_key_pair = user.create_access_key_pair()
            if self.iam_user not in credentials_parser:  # shoultn't be necessary
                credentials_parser[self.iam_user] = {
                    'aws_access_key_id': access_key_pair.id,
                    'aws_secret_access_key': access_key_pair.secret,
                }
                with aws_credentials_file.open('w') as aws_creds:
                    credentials_parser.write(aws_creds)
                aws_credentials_file.chmod(0o0600)
                logger.info(f"Added {self.iam_user} credentials to {aws_credentials_file.absolute()}.")
            else:
                logger.debug(f"Credentials for {self.iam_user} already exists.")

    def _describe_iam_policies(self):
        rtn = {
            'create': None,
            'describe': None,
            'update': None,
            'destroy': None,
        }
        policies = self.qh_policy_arns()  # exceptions handled here
        for k, v in policies.items():
            if v is not None:
                rtn[k] = v
            else:
                rtn[k] = ''
        return rtn  # should never have a None field

    def _describe_iam_group(self):
        rtn = {
            'arn': '',
            'attached-policies': [],
        }
        try:
            group = self.iam.Group(self.iam_group)
            rtn['arn'] = group.arn
        except ClientError as e:
            code = e.__dict__['response']['Error']['Code']
            if code == 'NoSuchEntity':
                logger.debug(f"Group '{self.iam_group}' does not exist.")
            else:
                logger.error(f"Unknown error caught: {e}")
                return f"ERROR ({code})"
            return rtn  # return before trying to get nogroup's policies.
        for attached_policy in group.attached_policies.all():
            rtn['attached-policies'].append(attached_policy.arn)
        return rtn

    def _describe_iam_user(self):
        rtn = {
            'name': '',
            'arn': '',
            'access-keys': [],
        }
        iam = self.iam
        try:
            user = iam.User(self.iam_user)
            rtn['arn'] = user.arn
        except ClientError as e:
            code = e.__dict__['response']['Error']['Code']
            if code == 'NoSuchEntity':
                logger.info(f"User '{self.iam_user}' was removed from Group '{self.iam_group}'")
            else:
                logger.error(f"Unknown error caught while deleting group: {e}")
            return rtn
        for key in user.access_keys.all():
            rtn['access-keys'].append(f"{key.access_key_id} ({key.status})")
        return rtn

    def _describe_user_credentials(self):
        rtn = {
            'default-region': None,
            'credentials-exist': None,
        }
        aws_config_dir = Path.home() / '.aws'
        aws_config_file = aws_config_dir / "config"
        aws_credentials_file = aws_config_dir / "credentials"
        config_parser = ConfigParser()
        config_parser.read(aws_config_file)
        profile_name = f"profile {self.iam_user}"
        try:
            if config_parser[profile_name]:
                rtn['default-region'] = config_parser[profile_name].get('region')
        except KeyError:
            logger.debug(f"No config for profile '{profile_name}' found at '{aws_config_file.absolute()}'")
            rtn['default-region'] = ''

        credentials_parser = ConfigParser()
        try:
            credentials_parser.read(aws_credentials_file)
            if credentials_parser[self.iam_user]:
                rtn['credentials-exist'] = True
            else:
                rtn['credentials-exist'] = False
        except KeyError:
            logger.debug(f"No credentials found at '{aws_credentials_file.absolute()}'")
            rtn['credentials-exist'] = False
        finally:
            return rtn


def PolicyData(QUICKHOST_ACCOUNT):
    return {
        'create': {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "quickhostCreate",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateKeyPair",
                        "ec2:CreateTags",
                        "ec2:RunInstances",
                        "ec2:AuthorizeSecurityGroupIngress",
                        "ec2:CreateSecurityGroup"
                    ],
                    "Resource": "*"
                }
            ]
        },
        'describe': {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "quickhostDescribeUserActions",
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetUser",
                        "iam:GetGroup",
                        "iam:ListUsers",
                        "iam:ListAccessKeys",
                        "iam:ListAttachedGroupPolicies",
                    ],
                    "Resource": [
                        f"arn:aws:iam::{QUICKHOST_ACCOUNT}:user/quickhost/*",
                        f"arn:aws:iam::{QUICKHOST_ACCOUNT}:group/quickhost/*"
                    ]
                },
                {
                    "Sid": "quickhostDescribePolicies",
                    "Effect": "Allow",
                    "Action": [
                        "iam:ListPolicies",
                    ],
                    "Resource": f"arn:aws:iam::{QUICKHOST_ACCOUNT}:policy/quickhost/*"
                },
                {
                    "Sid": "quickhostDescribe",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeInstances",
                        "ec2:DescribeVpcs",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeInternetGateways",
                        "ec2:DescribeRouteTables",
                        "ec2:DescribeImages",
                        "ec2:GetPasswordData"
                    ],
                    "Resource": "*"
                }
            ]
        },
        'update': {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "quickhostUpdate",
                    "Effect": "Allow",
                    "Action": [],
                    "Resource": "*"
                }
            ]
        },
        'destroy': {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "quickhostDelete",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeSecurityGroups",
                        "ec2:DeleteSecurityGroup",
                        "ec2:DeleteKeyPair",
                        "ec2:DescribeKeyPairs",
                        "ec2:TerminateInstances"
                    ],
                    "Resource": "*"
                }
            ]
        }
    }
