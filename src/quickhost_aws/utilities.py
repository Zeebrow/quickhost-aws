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

import logging
import os
import sys

import boto3
from botocore.exceptions import ClientError

from quickhost.constants import APP_CONST as QH_C

from .constants import AWSConstants


logger = logging.getLogger(__name__)

DefaultFilter = { 'Name': 'tag:Name', 'Values': [ QH_C.DEFAULT_APP_NAME ] }
DefaultTag = { 'Value': QH_C.DEFAULT_APP_NAME, 'Key': 'Name' }


def QH_Tag(app_name):
    return { 'Key': 'quickhost', 'Value': app_name }


def TagSpec(resource):
    return { 'ResourceType': resource, 'Tags': [ { 'Value': QH_C.DEFAULT_APP_NAME, 'Key': 'Name' } ] }


def get_single_result_id(resource_type, resource, plural=True):
    """
    get the aws resource id for a specified aws resource from a list, when we are expecting the list to contain only 1 item.
    example "InternetGateways" (plural is not implied) resource:
{'InternetGateways': [{'Attachments': [{'State': 'available', 'VpcId': 'vpc-0658d36368c863e33'}], 'InternetGatewayId': 'igw-02f85f5e5c6400320', 'OwnerId': '188154480716', 'Tags': []}, {'Attachments': [], 'InternetGatewayId': 'igw-0850d03a5ab4fbed4', 'OwnerId': '188154480716', 'Tags': [{'Key': 'Name', 'Value': 'quickhost'}]}, {'Attachments': [{'State': 'available', 'VpcId': 'vpc-7c31a606'}], 'InternetGatewayId': 'igw-c10bf1ba', 'OwnerId': '188154480716', 'Tags': []}], 'ResponseMetadata': {'RequestId': 'abe5dbdf-02bf-48db-83cc-ef4f523f8103', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': 'abe5dbdf-02bf-48db-83cc-ef4f523f8103', 'cache-control': 'no-cache, no-store', 'strict-transport-security': 'max-age=31536000; includeSubDomains', 'content-type': 'text/xml;charset=UTF-8', 'content-length': '1355', 'date': 'Mon, 27 Jun 2022 16:09:04 GMT', 'server': 'AmazonEC2'}, 'RetryAttempts': 0}}
    """
    if plural:
        _l = resource["{}s".format(resource_type)]
    else:
        return resource[resource_type]["{}Id".format(resource_type)]

    if len(_l) == 1:
        logger.debug("Found 1 %s.", resource_type)
        return _l[0]["{}Id".format(resource_type)]
    if len(_l) < 1:
        logger.info("No %ss were found.", resource_type)
        return None
    if len(_l) > 1:
        logger.warning("%s %ss were found with the name '%s'", len(resource_type[resource]), resource_type, QH_C.DEFAULT_APP_NAME)
        return None
    logger.error("something went wrong getting resource id")
    return None


def check_running_as_user(tgt_user_name=AWSConstants.DEFAULT_IAM_USER):
    sts = boto3.client('sts')
    caller_id = sts.get_caller_identity()
    iam = boto3.client('iam')

    all_users = iam.list_users()
    running_as_user_id = caller_id['UserId']
    running_as_user = ''
    for u in all_users['Users']:
        if u['UserId'] == running_as_user_id:
            running_as_user = u['UserName']
            break

    tgt_user_id = iam.get_user(UserName=tgt_user_name)['User']['UserId']
    if running_as_user_id != tgt_user_id:
        logger.warning("You're running as the IAM user '%s', not '%s'!", running_as_user, tgt_user_name)
        return False
    return True


def handle_client_error(e: ClientError):
    code = e['Error']['Code']
    if code == 'UnauthorizedOperation':
        logger.error("(%s): %s", code, e.operation_name)


def quickmemo(f):
    cache = {}

    def foo(*args, **kwargs):
        if 'use_cache' in kwargs:
            if not kwargs['use_cache']:
                return f(*args, **kwargs)
        if 'a' not in cache:
            cache['a'] = f(*args, **kwargs)
            return cache['a']
        else:
            logger.debug("cache hit")
        return cache['a']
    return foo


class QuickhostAWSException(Exception):
    pass


class QuickhostUnauthorized(Exception):
    def fmt(self):
        return "{}:({}) {}".format(
            self.username,
            self.operation,
            self.message
        )

    def __init__(self, username, operation, message=''):
        self.username = username
        self.operation = operation
        self.message = message
        Exception.__init__(self, self.fmt())


class Arn:
    def __init__(self, arn):
        if self.is_arn(arn) and arn is not None:
            self.error = None
            self.arn = str(arn)
            (_, _, _, _, self.account, self.resource) = arn.split(":")
        else:
            self.error = arn
            self.arn = None

    def __repr__(self):
        return str(self.arn)

    @classmethod
    def is_arn(self, arn: str):
        if type(arn) != str or not arn.startswith("arn:") or len(arn.split(":")) != 6:
            return False
        return True


def get_my_public_ip() -> str:
    import urllib
    with urllib.request.urlopen("https://ipv4.icanhazip.com") as r:
        html = r.read()
        return html.decode('utf-8').strip() + "/32"


def _print_dict(d: dict, heading=None, underline_char='*') -> None:
    if d is None:
        logger.warning("No items to print!")
        return
    fill_char = '.'
    if heading:
        sys.stdout.write(f"\033[32m{heading}\033[0m\n")
        print( underline_char * (len(heading) // len(underline_char)) )

    if os.isatty(1):
        if os.get_terminal_size()[0] > 80:
            termwidth = 40
        else:
            termwidth = os.get_terminal_size()[0]
        for k, v in d.items():
            if not k.startswith("_"):
                if heading:
                    k = underline_char + '\t' + k
                print("{0:{fc}{align}{width}} {1}".format(
                    k, v, fc=fill_char, align='<', width=termwidth
                ))
        if heading:
            print( underline_char * (len(heading) // len(underline_char)) )
            print()
    else:
        logger.warning("There's nowhere to show your results!")
    return None
