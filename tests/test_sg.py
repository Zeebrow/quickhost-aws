import pytest
from pytest import MonkeyPatch
import boto3
from botocore.stub import Stubber
from mock import patch, Mock, MagicMock
from datetime import datetime
import tempfile
from pathlib import Path
import shutil
import os
from textwrap import dedent
from collections import namedtuple
import re
import logging

from quickhost import constants as QH_C
from quickhost_aws.utilities import QuickhostUnauthorized
from quickhost_aws import AWSSG

# from .fixtures2 import patched_get_caller_info, patched_get_session
from .fixtures2 import *


FAKE_APP_NAME = 'test-app-name'
FAKE_VPC_ID = 'vpc-12345'


@pytest.fixture
def patched_sg(caplog, patched_get_session, patched_get_caller_info):
    with caplog.at_level(logging.CRITICAL, logger="botocore.credentials"):
        with patch('quickhost_aws.AWSSG.AWSResourceBase._get_session', patched_get_session), \
            patch('quickhost_aws.AWSSG.AWSResourceBase.get_caller_info', patched_get_caller_info):
            return AWSSG.SG(app_name=FAKE_APP_NAME, vpc_id=FAKE_VPC_ID, profile='asdf', region='reg')


@pytest.fixture
def stub_describe_sg(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    # aws resource ids as they would be returned from api calls
    aws_sg_id = 'sg-12345'

    ec2_c_stubber.add_response('describe_security_groups', {
        'SecurityGroups': [{
            'GroupId': aws_sg_id,
            'IpPermissions': [{
                'IpRanges': [{'CidrIp': '1.2.3.4/5'}],
                'ToPort': 22,
                'FromPort': 22,
                'IpProtocol': "tcp"
            },
            {
                'IpRanges': [{'CidrIp': '1.2.3.4/5'}],
                'ToPort': 3456,
                'FromPort': 4567,
                'IpProtocol': "tcp"
            }]
        }]
    }, {'Filters': [{'Name': 'vpc-id', 'Values': [FAKE_VPC_ID]}, {'Name': 'group-name', 'Values': ['test-app-name']}]})

    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    return patched_sg


def test_describe_sg(stub_describe_sg):
    assert stub_describe_sg.describe() == {'sgid': 'sg-12345', 'ports': ['22/tcp', '3456/tcp-4567/tcp'], 'cidrs': ['1.2.3.4/5', '1.2.3.4/5'], 'ok': True}


@pytest.fixture
def stub_describe_sg_DNE(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    # aws resource ids as they would be returned from api calls
    aws_sg_id = 'sg-12345'

    ec2_c_stubber.add_response('describe_security_groups', { 'SecurityGroups': [] }, {'Filters': [{'Name': 'vpc-id', 'Values': [FAKE_VPC_ID]}, {'Name': 'group-name', 'Values': ['test-app-name']}]})

    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    return patched_sg


def test_describe_sg_DNE(stub_describe_sg_DNE):
    assert stub_describe_sg_DNE.describe() is None


@pytest.fixture
def stub_describe_sg_boto3_exception_handled(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    ec2_c_stubber.add_client_error('describe_security_groups', 'InvalidGroup.NotFound')
    ec2_c_stubber.add_client_error('describe_security_groups', 'some-other-error')

    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    return patched_sg


def test_describe_sg_boto3_exception_handled(stub_describe_sg_boto3_exception_handled):
    assert stub_describe_sg_boto3_exception_handled.describe() is None  # invalid group
    assert stub_describe_sg_boto3_exception_handled.describe() is None  # some-other-error


@pytest.fixture
def stub_create_sg(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    # aws resource ids as they would be returned from api calls
    aws_sg_id = 'sg-12345'

    ec2_c_stubber.add_response('create_security_group', {
        'GroupId': aws_sg_id
    }, 
        {'Description': 'Made by quickhost',
        'DryRun': False,
        'GroupName': 'test-app-name',
        'TagSpecifications': [{'ResourceType': 'security-group',
                                'Tags': [{'Key': 'Name', 'Value': 'test-app-name'},
                                        {'Key': 'quickhost',
                                            'Value': 'test-app-name'}]}],
        'VpcId': 'vpc-12345'}
    )
    ec2_c_stubber.add_response('authorize_security_group_ingress', {}, 
        {'DryRun': False,
        'GroupId': 'sg-12345',
        'IpPermissions': [{'FromPort': 23,
                            'IpProtocol': 'tcp',
                            'IpRanges': [{'CidrIp': '1.2.3.4/5',
                                            'Description': 'made with quickhosts'},
                                        {'CidrIp': '2.3.4.5/6',
                                            'Description': 'made with quickhosts'}],
                            'ToPort': 23},
                            {'FromPort': 34,
                            'IpProtocol': 'tcp',
                            'IpRanges': [{'CidrIp': '1.2.3.4/5',
                                            'Description': 'made with quickhosts'},
                                        {'CidrIp': '2.3.4.5/6',
                                            'Description': 'made with quickhosts'}],
                            'ToPort': 34},
                            {'FromPort': 56,
                            'IpProtocol': 'tcp',
                            'IpRanges': [{'CidrIp': '1.2.3.4/5',
                                            'Description': 'made with quickhosts'},
                                        {'CidrIp': '2.3.4.5/6',
                                            'Description': 'made with quickhosts'}],
                            'ToPort': 56}]}
    )


    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    return patched_sg


@pytest.fixture
def stub_create_sg_boto_exception(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    # aws resource ids as they would be returned from api calls
    aws_sg_id = 'sg-12345'

    ec2_c_stubber.add_response('create_security_group', {
        'GroupId': aws_sg_id
    }, 
        {'Description': 'Made by quickhost',
        'DryRun': False,
        'GroupName': 'test-app-name',
        'TagSpecifications': [{'ResourceType': 'security-group',
                                'Tags': [{'Key': 'Name', 'Value': 'test-app-name'},
                                        {'Key': 'quickhost',
                                            'Value': 'test-app-name'}]}],
        'VpcId': 'vpc-12345'}
    )
    ec2_c_stubber.add_client_error('authorize_security_group_ingress', 'some-exception')

    ec2_c_stubber.add_client_error('create_security_group', 'some-exception')
    ec2_c_stubber.add_response('describe_security_groups', {'SecurityGroups': [{'GroupId': aws_sg_id}]}, {'Filters': [{'Name': 'vpc-id', 'Values': [FAKE_VPC_ID]}, {'Name': 'group-name', 'Values': [FAKE_APP_NAME]}]})  # if we can't create, the assumption is it already exists
    ec2_c_stubber.add_response('authorize_security_group_ingress', {},
        {'DryRun': False,
        'GroupId': 'sg-12345',
        'IpPermissions': [{'FromPort': 23,
                            'IpProtocol': 'tcp',
                            'IpRanges': [{'CidrIp': '1.2.3.4/5',
                                            'Description': 'made with quickhosts'},
                                        {'CidrIp': '2.3.4.5/6',
                                            'Description': 'made with quickhosts'}],
                            'ToPort': 23},
                            {'FromPort': 34,
                            'IpProtocol': 'tcp',
                            'IpRanges': [{'CidrIp': '1.2.3.4/5',
                                            'Description': 'made with quickhosts'},
                                        {'CidrIp': '2.3.4.5/6',
                                            'Description': 'made with quickhosts'}],
                            'ToPort': 34},
                            {'FromPort': 56,
                            'IpProtocol': 'tcp',
                            'IpRanges': [{'CidrIp': '1.2.3.4/5',
                                            'Description': 'made with quickhosts'},
                                        {'CidrIp': '2.3.4.5/6',
                                            'Description': 'made with quickhosts'}],
                            'ToPort': 56}]}                           
    )

    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    return patched_sg


def test_create_sg_boto_exception(stub_create_sg_boto_exception):
    # exception in authorize sg
    assert not stub_create_sg_boto_exception.create(cidrs=["1.2.3.4/5", "2.3.4.5/6"], ports=[23, 34, 56])
    assert stub_create_sg_boto_exception.sgid == 'sg-12345'
    # exception in create sg
    assert not stub_create_sg_boto_exception.create(cidrs=["1.2.3.4/5", "2.3.4.5/6"], ports=[23, 34, 56])
    assert stub_create_sg_boto_exception.sgid is not None

@pytest.fixture
def stub_create_sg_boto_exception_nested_add_ingress(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    # aws resource ids as they would be returned from api calls
    aws_sg_id = 'sg-12345'

    ec2_c_stubber.add_client_error('create_security_group', 'some-exception')
    ec2_c_stubber.add_response('describe_security_groups', {'SecurityGroups': [{'GroupId': aws_sg_id}]}, {'Filters': [{'Name': 'vpc-id', 'Values': [FAKE_VPC_ID]}, {'Name': 'group-name', 'Values': [FAKE_APP_NAME]}]})  # if we can't create, the assumption is it already exists
    ec2_c_stubber.add_client_error('authorize_security_group_ingress', 'some-exception')

    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    return patched_sg


def test_create_sg_boto_exception_nested_add_ingress(stub_create_sg_boto_exception_nested_add_ingress):
    # exception in authorize sg
    assert not stub_create_sg_boto_exception_nested_add_ingress.create(cidrs=["1.2.3.4/5", "2.3.4.5/6"], ports=[23, 34, 56])
    assert stub_create_sg_boto_exception_nested_add_ingress.sgid is not None


@pytest.fixture
def stub_get_security_group_id(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    # aws resource ids as they would be returned from api calls
    aws_sg_id = 'sg-12345'

    ec2_c_stubber.add_response('describe_security_groups', {
        'SecurityGroups': [{
            'GroupName': 'test-app-name',
            'GroupId': aws_sg_id,
            'IpPermissions': [{
                'IpRanges': [{'CidrIp': '1.2.3.4/5'}],
                'ToPort': 22,
                'FromPort': 22,
                'IpProtocol': "tcp"
            },
            {
                'IpRanges': [{'CidrIp': '1.2.3.4/5'}],
                'ToPort': 3456,
                'FromPort': 4567,
                'IpProtocol': "tcp"
            }]
        }]
    }, {'Filters': [{'Name': 'vpc-id', 'Values': [FAKE_VPC_ID]}, {'Name': 'group-name', 'Values': ['test-app-name']}]})

    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    return patched_sg


def test_get_security_group_id(stub_get_security_group_id):
    assert stub_get_security_group_id.get_security_group_id() == "sg-12345"


@pytest.fixture
def stub_get_security_group_id_when_DNE(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    ec2_c_stubber.add_response('describe_security_groups', {
        'SecurityGroups': []
    }, {'Filters': [{'Name': 'vpc-id', 'Values': [FAKE_VPC_ID]}, {'Name': 'group-name', 'Values': ['test-app-name']}]})

    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    return patched_sg


def test_get_security_group_id_when_DNE(stub_get_security_group_id_when_DNE):
    assert stub_get_security_group_id_when_DNE.get_security_group_id() is None


@pytest.fixture
def stub_get_security_group_id_when_DNE_2(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    ec2_c_stubber.add_client_error('describe_security_groups', 'InvalidGroup.NotFound')
    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    return patched_sg


def test_get_security_group_id_when_DNE_2(stub_get_security_group_id_when_DNE_2):
    stub_get_security_group_id_when_DNE_2.get_security_group_id()


@pytest.fixture
def stub_destroy_sg(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    # aws resource ids as they would be returned from api calls
    aws_sg_id = 'sg-12345'

    ec2_c_stubber.add_response('describe_security_groups', {
        'SecurityGroups': [{
            'GroupName': 'test-app-name',
            'GroupId': aws_sg_id,
            'IpPermissions': [{
                'IpRanges': [{'CidrIp': '1.2.3.4/5'}],
                'ToPort': 22,
                'FromPort': 22,
                'IpProtocol': "tcp"
            },
            {
                'IpRanges': [{'CidrIp': '1.2.3.4/5'}],
                'ToPort': 3456,
                'FromPort': 4567,
                'IpProtocol': "tcp"
            }]
        }]
    }, {'Filters': [{'Name': 'vpc-id', 'Values': [FAKE_VPC_ID]}, {'Name': 'group-name', 'Values': [FAKE_APP_NAME]}]})

    ec2_c_stubber.add_response('delete_security_group', {}, {'GroupId': aws_sg_id})
    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    return patched_sg


def test_destroy_sg(stub_destroy_sg):
    assert stub_destroy_sg.destroy()


@pytest.fixture
def stub_destroy_sg_when_DNE(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    # aws resource ids as they would be returned from api calls
    aws_sg_id = 'sg-12345'

    ec2_c_stubber.add_response('describe_security_groups', {
        'SecurityGroups': []
    }, {'Filters': [{'Name': 'vpc-id', 'Values': [FAKE_VPC_ID]}, {'Name': 'group-name', 'Values': [FAKE_APP_NAME]}]})

    ec2_c_stubber.add_response('delete_security_group', {}, {'GroupId': aws_sg_id})
    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    return patched_sg


def test_destroy_sg_when_DNE(stub_destroy_sg_when_DNE):
    assert not stub_destroy_sg_when_DNE.destroy()


@pytest.fixture
def stub_destroy_sg_when_boto_exception_in_describe(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    ec2_c_stubber.add_client_error('describe_security_groups', 'InvalidGroup.NotFound')

    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    return patched_sg


def test_destroy_sg_when_boto_exception_in_describe(stub_destroy_sg_when_boto_exception_in_describe):
    assert not stub_destroy_sg_when_boto_exception_in_describe.destroy()


@pytest.fixture
def stub_destroy_sg_when_boto_exception_in_destroy(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    # aws resource ids as they would be returned from api calls
    aws_sg_id = 'sg-12345'

    ec2_c_stubber.add_response('describe_security_groups', {
        'SecurityGroups': []
    }, {'Filters': [{'Name': 'vpc-id', 'Values': [FAKE_VPC_ID]}, {'Name': 'group-name', 'Values': [FAKE_APP_NAME]}]})

    ec2_c_stubber.add_client_error('destroy_security_group', 'some-boto-error')
    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    return patched_sg


def test_destroy_sg_when_boto_exception_in_destroy(stub_destroy_sg_when_boto_exception_in_destroy):
    assert not stub_destroy_sg_when_boto_exception_in_destroy.destroy()

@pytest.fixture
def stub_describe_security_ingress(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    # aws resource ids as they would be returned from api calls
    aws_sg_id = 'sg-12345'

    ec2_c_stubber.add_response('describe_security_groups', {
        'SecurityGroups': []
    }, {'Filters': [{'Name': 'vpc-id', 'Values': [FAKE_VPC_ID]}, {'Name': 'group-name', 'Values': [FAKE_APP_NAME]}]})

    ec2_c_stubber.add_response('delete_security_group', {}, {'GroupId': aws_sg_id})
    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    return patched_sg


def test_describe_security_ingress(stub_describe_security_ingress):
    ingress = [
        {
            'IpRanges': [{'CidrIp': '1.2.3.4/5'}],
            'ToPort': 22,
            'FromPort': 22,
            'IpProtocol': "tcp"
        },
        {
            'IpRanges': [{'CidrIp': '1.2.3.4/5'}],
            'ToPort': 3456,
            'FromPort': 4567,
            'IpProtocol': "tcp"
        }
    ]

    r = stub_describe_security_ingress._describe_sg_ingress(ingress)
    assert r[0] == ['22/tcp', '3456/tcp-4567/tcp']
    assert r[1] == ['1.2.3.4/5', '1.2.3.4/5']
    assert r[2]

def test_describe_security_ingress_on_invalid_input(stub_describe_security_ingress):
    r = stub_describe_security_ingress._describe_sg_ingress([{}])
    assert len(r[0]) == 0
    assert len(r[1]) == 0
    assert not r[2]


@pytest.fixture
def stub_add_ingress(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    ec2_c_stubber.add_response('authorize_security_group_ingress', {}, 
        {'DryRun': False,
        'GroupId': 'sg-12345',
        'IpPermissions': [{'FromPort': 23,
                            'IpProtocol': 'tcp',
                            'IpRanges': [{'CidrIp': '1.2.3.4/5',
                                            'Description': 'made with quickhosts'},
                                        {'CidrIp': '2.3.4.5/6',
                                            'Description': 'made with quickhosts'}],
                            'ToPort': 23},
                            {'FromPort': 34,
                            'IpProtocol': 'tcp',
                            'IpRanges': [{'CidrIp': '1.2.3.4/5',
                                            'Description': 'made with quickhosts'},
                                        {'CidrIp': '2.3.4.5/6',
                                            'Description': 'made with quickhosts'}],
                            'ToPort': 34},
                            {'FromPort': 56,
                            'IpProtocol': 'tcp',
                            'IpRanges': [{'CidrIp': '1.2.3.4/5',
                                            'Description': 'made with quickhosts'},
                                        {'CidrIp': '2.3.4.5/6',
                                            'Description': 'made with quickhosts'}],
                            'ToPort': 56}]}
    )

    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    patched_sg.sgid = "sg-12345"
    return patched_sg


def test_add_ingress(stub_add_ingress):
    assert stub_add_ingress._add_ingress(
        cidrs=['1.2.3.4/5', '2.3.4.5/6'],
        ports=[23, 34, 56]
    )



@pytest.fixture
def stub_add_ingress_boto_exception(patched_get_session, patched_sg):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    ec2_c_stubber.add_client_error('authorize_security_group_ingress', 'some-error')

    ec2_c_stubber.activate()
    patched_sg.client = ec2_c
    patched_sg.sgid = "sg-12345"
    return patched_sg


def test_add_ingress_boto_exception(stub_add_ingress_boto_exception):
    assert not stub_add_ingress_boto_exception._add_ingress(
        cidrs=['1.2.3.4/5', '2.3.4.5/6'],
        ports=[23, 34, 56]
    )