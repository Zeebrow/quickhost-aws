import pytest
from pytest import MonkeyPatch
import boto3
from botocore.stub import Stubber
from mock import patch, Mock
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
from quickhost_aws import AWSIam
# from .fixtures2 import patched_get_caller_info, patched_get_session, home_dir
from .fixtures2 import *



@pytest.fixture
def aws_files_admin(aws_files_empty: FakeAWSFiles):
    """"before-quickhost" aws files"""
    with open(aws_files_empty.credentials_file, 'w') as cf:
        cf.write(dedent(f"""
            [default]
            aws_access_key_id = notouching_access_key_id1
            aws_secret_access_key = notouching_secret_access_key1

            [some-profile]
            aws_access_key_id = notouching_access_key_id2
            aws_secret_access_key = notouching_secret_access_key2
        """))
    with open(aws_files_empty.config_file, 'w') as config:
        config.write(dedent(f"""
            [default]
            region = some-other-region
            output = text

            [profile some-profile]
            region = some-region
            output = json
        """))

    return aws_files_empty

@pytest.fixture
def patched_get_session_admin(aws_files_admin):
    def _f(*args, **kwargs):
        s = boto3.session.Session()
        assert s.profile_name == 'default'
        assert 'some-profile' in s.available_profiles
        return s
    return _f


@pytest.fixture
def patched_aws_iam(patched_get_session, patched_get_caller_info):
    with patch('quickhost_aws.AWSIam.AWSResourceBase._get_session', patched_get_session), \
        patch('quickhost_aws.AWSIam.AWSResourceBase.get_caller_info', patched_get_caller_info):
        awsiam = AWSIam.Iam(profile='asdf', region='reg')
        return awsiam


@pytest.fixture
def patched_admin_get_caller_info():
    def _f(*args, **kwargs):
        return {
            'username': 'some-admin-user',
            'Account': 'some-aws-account'
        }
    return _f


@pytest.fixture
def patched_admin_aws_iam(patched_get_session_admin, patched_admin_get_caller_info):
    with patch('quickhost_aws.AWSIam.AWSResourceBase._get_session', patched_get_session_admin), \
        patch('quickhost_aws.AWSIam.AWSResourceBase.get_caller_info', patched_admin_get_caller_info):
        awsiam = AWSIam.Iam(profile='admin_asdf', region='reg')
        return awsiam


@pytest.fixture
def stub_describe_iam(patched_get_session, patched_aws_iam: AWSIam.Iam):
    iam_r = patched_get_session().resource("iam")
    iam_c = patched_get_session().client("iam")
    iam_r_stubber = Stubber(iam_r.meta.client)
    iam_c_stubber = Stubber(iam_c)

    param_group_name = 'quickhost-users'

    # aws resource ids as they would be returned from api calls
    aws_username = 'quickhost-user'
    aws_user_id = 'AIDA123456789EXAMPLE'
    aws_user_path = '/quickhost/'
    aws_user_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:user{aws_user_path}{aws_username}'
    aws_user_creation_date = datetime.now()

    aws_group_name = 'quickhost-users'
    aws_group_id = 'AIDGPMS9RO4H3FEXAMPLE'
    aws_group_path = '/quickhost/'
    aws_group_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:group{aws_group_path}{aws_group_name}'
    aws_group_creation_date = aws_user_creation_date

    iam_r_stubber.add_response('get_user',
        {'User': {
            'UserName': aws_username,
            'UserId': aws_user_id,
            'Path': aws_user_path,
            'Arn': aws_user_arn,
            'CreateDate': aws_user_creation_date,
        }},
        {'UserName': aws_username}
    )

    iam_r_stubber.add_response('list_access_keys', {'AccessKeyMetadata': [{'UserName': aws_username}]}, {'UserName': aws_username})
    iam_r_stubber.add_response('get_group', 
        {'Group': {
            'Path': aws_group_path,
            'GroupName': aws_group_name,
            'GroupId': aws_group_id,
            'Arn': aws_group_arn,
            'CreateDate': aws_group_creation_date,
        },
        'Users': [],
        },
    {'GroupName': param_group_name})

    iam_r_stubber.add_response('list_attached_group_policies', {}, {'GroupName': param_group_name})
    iam_c_stubber.add_response('list_policies', {'Policies': []}, {'PathPrefix': aws_user_path})

    iam_r_stubber.activate()
    iam_c_stubber.activate()
    patched_aws_iam.iam = iam_r
    patched_aws_iam.client = iam_c
    return patched_aws_iam


def test_describe_iam(caplog, stub_describe_iam: AWSIam.Iam):
    caplog.set_level(logging.DEBUG, logger='quickhost_aws.AWSIam')
    stub_describe_iam.describe()

def test_describe_no_config_or_credentials_file_contents(stub_describe_iam: AWSIam.Iam):
    d = tempfile.mkdtemp()
    (Path(d) / '.aws').mkdir()
    (Path(d) / '.aws' / 'credentials').touch()
    (Path(d) / '.aws' / 'config').touch()

    with MonkeyPatch.context() as m:
        m.setenv("HOME", d)
        describe = stub_describe_iam.describe()
        assert describe['credentials'] == {'default-region': '', 'credentials-exist': False}

    shutil.rmtree(d)

def test_describe_config_or_credentials_files_DNE(stub_describe_iam: AWSIam.Iam):
    d = tempfile.mkdtemp()
    with MonkeyPatch.context() as m:
        m.setenv("HOME", d)
        describe = stub_describe_iam.describe()
        assert describe['credentials'] == {'default-region': '', 'credentials-exist': False}


@pytest.fixture
def stub_create_iam_user_and_group(patched_get_session_admin, patched_admin_aws_iam: AWSIam.Iam):
    iam_r = patched_get_session_admin().resource("iam")
    iam_c = patched_get_session_admin().client("iam")
    iam_r_stubber = Stubber(iam_r.meta.client)
    iam_c_stubber = Stubber(iam_c)

    # aws resource ids as they would be returned from api calls
    aws_username = 'quickhost-user'
    aws_user_id = 'AIDA123456789EXAMPLE'
    aws_user_path = '/quickhost/'
    aws_user_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:user{aws_user_path}{aws_username}'
    aws_user_creation_date = datetime.now()

    aws_group_name = 'quickhost-users'
    aws_group_id = 'AIDGPMS9RO4H3FEXAMPLE'
    aws_group_path = '/quickhost/'
    aws_group_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:group{aws_group_path}{aws_group_name}'
    aws_group_creation_date = aws_user_creation_date

    aws_user_response = {
        'UserName': aws_username,
        'UserId': aws_user_id,
        'Path': aws_user_path,
        'Arn': aws_user_arn,
        'CreateDate': aws_user_creation_date,
    }

    aws_group_response = {
        'GroupName': aws_group_name,
        'GroupId': aws_group_id,
        'Path': aws_group_path,
        'Arn': aws_group_arn,
        'CreateDate': aws_group_creation_date,
    }

    iam_r_stubber.add_response(
        method='create_user',
        service_response={'User': aws_user_response},
        expected_params={'UserName': aws_username, 'Path': aws_user_path, 'Tags': [{'Key': 'quickhost', 'Value': 'aws'}]}
    )
    iam_r_stubber.add_response('create_group',
        {'Group': aws_group_response},
        {'GroupName': aws_group_name, 'Path': aws_group_path}
    )
    iam_r_stubber.add_response('get_group', {
        'Group': aws_group_response,
        'Users': [],
    }, {'GroupName': aws_group_name})

    iam_r_stubber.activate()
    iam_c_stubber.activate()
    patched_admin_aws_iam.iam = iam_r
    patched_admin_aws_iam.client = iam_c
    return patched_admin_aws_iam


def test_create_iam_user_and_group(stub_create_iam_user_and_group: AWSIam.Iam):
    assert {
        'iam_group_arn': f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:group/quickhost/quickhost-users',
        'iam_user_arn': f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:user/quickhost/quickhost-user'
    } == stub_create_iam_user_and_group.create_iam_user_and_group()


@pytest.fixture
def stub_create_iam_user_and_group_when_exists(patched_get_session_admin, patched_admin_aws_iam: AWSIam.Iam):
    iam_r = patched_get_session_admin().resource("iam")
    iam_c = patched_get_session_admin().client("iam")
    iam_r_stubber = Stubber(iam_r.meta.client)
    iam_c_stubber = Stubber(iam_c)

    # aws resource ids as they would be returned from api calls
    aws_username = 'quickhost-user'
    aws_user_id = 'AIDA123456789EXAMPLE'
    aws_user_path = '/quickhost/'
    aws_user_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:user{aws_user_path}{aws_username}'
    aws_user_creation_date = datetime.now()

    aws_group_name = 'quickhost-users'
    aws_group_id = 'AIDGPMS9RO4H3FEXAMPLE'
    aws_group_path = '/quickhost/'
    aws_group_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:group{aws_group_path}{aws_group_name}'
    aws_group_creation_date = aws_user_creation_date

    aws_user_response = {
        'UserName': aws_username,
        'UserId': aws_user_id,
        'Path': aws_user_path,
        'Arn': aws_user_arn,
        'CreateDate': aws_user_creation_date,
    }

    aws_group_response = {
        'GroupName': aws_group_name,
        'GroupId': aws_group_id,
        'Path': aws_group_path,
        'Arn': aws_group_arn,
        'CreateDate': aws_group_creation_date,
    }

    iam_r_stubber.add_client_error(
        method='create_user',
        service_error_code='EntityAlreadyExists',
        expected_params={'UserName': aws_username, 'Path': aws_user_path, 'Tags': [{'Key': 'quickhost', 'Value': 'aws'}]}
    )
    iam_c_stubber.add_response('get_user', {'User': aws_user_response}, {'UserName': aws_username})
    iam_r_stubber.add_client_error(
        method='create_group',
        service_error_code='EntityAlreadyExists',
        expected_params={'GroupName': aws_group_name, 'Path': aws_group_path}
    )
    iam_c_stubber.add_response('get_group', {
        'Group': aws_group_response,
        'Users': [],
    }, {'GroupName': aws_group_name})

    iam_r_stubber.activate()
    iam_c_stubber.activate()
    patched_admin_aws_iam.iam = iam_r
    patched_admin_aws_iam.client = iam_c
    return patched_admin_aws_iam


def test_create_iam_user_and_group_when_exists(stub_create_iam_user_and_group_when_exists: AWSIam.Iam):
    assert {
        'iam_group_arn': f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:group/quickhost/quickhost-users',
        'iam_user_arn': f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:user/quickhost/quickhost-user'
    } == stub_create_iam_user_and_group_when_exists.create_iam_user_and_group()


@pytest.fixture
def stub_destroy_iam(patched_get_session_admin, patched_admin_aws_iam: AWSIam.Iam):
    iam_r = patched_get_session_admin().resource("iam")
    iam_c = patched_get_session_admin().client("iam")
    iam_r_stubber = Stubber(iam_r.meta.client)
    iam_c_stubber = Stubber(iam_c)

    # aws resource ids as they would be returned from api calls
    aws_username = 'quickhost-user'
    aws_user_id = 'AIDA123456789EXAMPLE'
    aws_user_path = '/quickhost/'
    aws_user_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:user{aws_user_path}{aws_username}'
    aws_user_creation_date = datetime.now()

    aws_group_name = 'quickhost-users'
    aws_group_id = 'AIDGPMS9RO4H3FEXAMPLE'
    aws_group_path = '/quickhost/'
    aws_group_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:group{aws_group_path}{aws_group_name}'
    aws_group_creation_date = aws_user_creation_date

    aws_user_response = {
        'UserName': aws_username,
        'UserId': aws_user_id,
        'Path': aws_user_path,
        'Arn': aws_user_arn,
        'CreateDate': aws_user_creation_date,
    }

    aws_group_response = {
        'GroupName': aws_group_name,
        'GroupId': aws_group_id,
        'Path': aws_group_path,
        'Arn': aws_group_arn,
        'CreateDate': aws_group_creation_date,
    }

    aws_policy_arn_create = f'arn:aws:iam::{FAKE_ACCOUNT}:policy/ci-quickhost-create'
    aws_policy_arn_describe = f'arn:aws:iam::{FAKE_ACCOUNT}:policy/ci-quickhost-describe'
    aws_policy_arn_destroy = f'arn:aws:iam::{FAKE_ACCOUNT}:policy/ci-quickhost-destroy'
    aws_policy_arn_update = f'arn:aws:iam::{FAKE_ACCOUNT}:policy/ci-quickhost-update'

    iam_c_stubber.add_response(
        method='list_policies',
        service_response={'Policies': [
            {'PolicyName': 'quickhost-create', 'Arn': aws_policy_arn_create},
            {'PolicyName': 'quickhost-describe', 'Arn': aws_policy_arn_describe},
            {'PolicyName': 'quickhost-destroy', 'Arn': aws_policy_arn_destroy},
            {'PolicyName': 'quickhost-update', 'Arn': aws_policy_arn_update},
        ]},
        expected_params={'PathPrefix': '/quickhost/'},
    )
    iam_r_stubber.add_response('remove_user_from_group',
        {},
        {'GroupName': aws_group_name, 'UserName': aws_username}
    )

    iam_r_stubber.add_response('get_policy',        {'Policy': {'PolicyName': 'asdf'}}, {'PolicyArn': aws_policy_arn_create})
    iam_r_stubber.add_response('detach_group_policy', {}, {'GroupName': 'quickhost-users', 'PolicyArn': aws_policy_arn_create})
    iam_r_stubber.add_response('delete_policy',     {}, {'PolicyArn': aws_policy_arn_create})

    iam_r_stubber.add_response('get_policy',        {'Policy': {'PolicyName': 'asdf'}}, {'PolicyArn': aws_policy_arn_describe})
    iam_r_stubber.add_response('detach_group_policy', {}, {'GroupName': 'quickhost-users', 'PolicyArn': aws_policy_arn_describe})
    iam_r_stubber.add_response('delete_policy',     {}, {'PolicyArn': aws_policy_arn_describe})

    iam_r_stubber.add_response('get_policy',        {'Policy': {'PolicyName': 'asdf'}}, {'PolicyArn': aws_policy_arn_update})
    iam_r_stubber.add_response('detach_group_policy', {}, {'GroupName': 'quickhost-users', 'PolicyArn': aws_policy_arn_update})
    iam_r_stubber.add_response('delete_policy',     {}, {'PolicyArn': aws_policy_arn_update})

    iam_r_stubber.add_response('get_policy',        {'Policy': {'PolicyName': 'asdf'}}, {'PolicyArn': aws_policy_arn_destroy})
    iam_r_stubber.add_response('detach_group_policy', {}, {'GroupName': 'quickhost-users', 'PolicyArn': aws_policy_arn_destroy})
    iam_r_stubber.add_response('delete_policy',     {}, {'PolicyArn': aws_policy_arn_destroy})


    iam_r_stubber.add_response('delete_group',      {}, {'GroupName': aws_group_name})
    iam_r_stubber.add_response('get_group',         {'Group': aws_group_response, 'Users': []}, {'GroupName': aws_group_name})
    iam_r_stubber.add_response('get_user',          {'User': aws_user_response}, {'UserName': aws_username})
    iam_r_stubber.add_response('list_access_keys',  {'AccessKeyMetadata': [{'UserName': aws_username}]}, {'UserName': aws_username})
    iam_r_stubber.add_response('get_group',         {'Group': aws_group_response, 'Users': []}, {'GroupName': aws_group_name})
    iam_r_stubber.add_response('list_attached_group_policies', {}, {'GroupName': aws_group_name})
    iam_c_stubber.add_response('list_policies',     {'Policies': [ ]}, {'PathPrefix': '/quickhost/'},)
    iam_r_stubber.add_response('get_user',          {'User': aws_user_response}, {'UserName': aws_username})
    iam_r_stubber.add_response('list_access_keys',  {'AccessKeyMetadata': [{'UserName': aws_username}]}, {'UserName': aws_username})
    iam_r_stubber.add_response('get_group',         {'Group': aws_group_response, 'Users': []}, {'GroupName': aws_group_name})
    iam_r_stubber.add_response('list_attached_group_policies', {}, {'GroupName': aws_group_name})
    iam_c_stubber.add_response('list_policies',     {'Policies': [ ]}, {'PathPrefix': '/quickhost/'},)
    iam_r_stubber.add_response('list_access_keys',  {'AccessKeyMetadata': [{'UserName': aws_username}]}, {'UserName': aws_username})
    iam_r_stubber.add_response('delete_user',       {}, {'UserName': aws_username})
    iam_r_stubber.add_response('get_user',          {'User': aws_user_response}, {'UserName': aws_username})

    iam_r_stubber.activate()
    iam_c_stubber.activate()
    patched_admin_aws_iam.iam = iam_r
    patched_admin_aws_iam.client = iam_c
    return patched_admin_aws_iam


def test_iam_destroy(stub_destroy_iam: AWSIam.Iam):
    stub_destroy_iam.destroy()


@pytest.fixture
def stub_destroy_iam_resources_dont_exist(patched_get_session_admin, patched_admin_aws_iam: AWSIam.Iam):
    iam_r = patched_get_session_admin().resource("iam")
    iam_c = patched_get_session_admin().client("iam")
    iam_r_stubber = Stubber(iam_r.meta.client)
    iam_c_stubber = Stubber(iam_c)

    # aws resource ids as they would be returned from api calls
    aws_username = 'quickhost-user'
    aws_user_id = 'AIDA123456789EXAMPLE'
    aws_user_path = '/quickhost/'
    aws_user_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:user{aws_user_path}{aws_username}'
    aws_user_creation_date = datetime.now()

    aws_group_name = 'quickhost-users'
    aws_group_id = 'AIDGPMS9RO4H3FEXAMPLE'
    aws_group_path = '/quickhost/'
    aws_group_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:group{aws_group_path}{aws_group_name}'
    aws_group_creation_date = aws_user_creation_date

    aws_user_response = {
        'UserName': aws_username,
        'UserId': aws_user_id,
        'Path': aws_user_path,
        'Arn': aws_user_arn,
        'CreateDate': aws_user_creation_date,
    }

    aws_group_response = {
        'GroupName': aws_group_name,
        'GroupId': aws_group_id,
        'Path': aws_group_path,
        'Arn': aws_group_arn,
        'CreateDate': aws_group_creation_date,
    }

    iam_c_stubber.add_response(
        method='list_policies',
        service_response={'Policies': []},
        expected_params={'PathPrefix': '/quickhost/'},
    )
    iam_r_stubber.add_client_error('remove_user_from_group', 'NoSuchEntity')
    iam_r_stubber.add_client_error('delete_group', 'NoSuchEntity')
    iam_r_stubber.add_client_error('get_user', 'NoSuchEntity')
    iam_r_stubber.add_client_error('get_group', 'NoSuchEntity')
    iam_c_stubber.add_response(
        method='list_policies',
        service_response={'Policies': []},
        expected_params={'PathPrefix': '/quickhost/'},
    )
    iam_r_stubber.add_client_error('get_user', 'NoSuchEntity')
    iam_r_stubber.add_client_error('get_group', 'NoSuchEntity')
    iam_c_stubber.add_response(
        method='list_policies',
        service_response={'Policies': []},
        expected_params={'PathPrefix': '/quickhost/'},
    )

    # @@@ this is jank - boto stubber doesn't detect the iam.User() call
    # immediately before list_access_keys(). so there is no error to catch, and
    # that is what is supposed to be testsed. wtf???
    iam_r_stubber.add_response('list_access_keys',  {'AccessKeyMetadata': [{'UserName': aws_username}]}, {'UserName': aws_username})
    iam_r_stubber.add_client_error('delete_user',  'NoSuchEntity')

    iam_r_stubber.activate()
    iam_c_stubber.activate()
    patched_admin_aws_iam.iam = iam_r
    patched_admin_aws_iam.client = iam_c
    return patched_admin_aws_iam


def test_destroy_iam_resources_dont_exist(stub_destroy_iam_resources_dont_exist: AWSIam.Iam):
    stub_destroy_iam_resources_dont_exist.destroy()


@pytest.fixture
def stub_attach_policies_and_group(patched_get_session_admin, patched_admin_aws_iam: AWSIam.Iam):
    iam_r = patched_get_session_admin().resource("iam")
    iam_c = patched_get_session_admin().client("iam")
    iam_r_stubber = Stubber(iam_r.meta.client)
    iam_c_stubber = Stubber(iam_c)

    aws_username = 'quickhost-user'
    aws_user_id = 'AIDA123456789EXAMPLE'
    aws_user_path = '/quickhost/'
    aws_user_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:user{aws_user_path}{aws_username}'
    aws_user_creation_date = datetime.now()

    aws_group_name = 'quickhost-users'
    aws_group_id = 'AIDGPMS9RO4H3FEXAMPLE'
    aws_group_path = '/quickhost/'
    aws_group_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:group{aws_group_path}{aws_group_name}'
    aws_group_creation_date = aws_user_creation_date

    aws_user_response = {
        'UserName': aws_username,
        'UserId': aws_user_id,
        'Path': aws_user_path,
        'Arn': aws_user_arn,
        'CreateDate': aws_user_creation_date,
    }

    aws_group_response = {
        'GroupName': aws_group_name,
        'GroupId': aws_group_id,
        'Path': aws_group_path,
        'Arn': aws_group_arn,
        'CreateDate': aws_group_creation_date,
    }

    iam_c_stubber.add_response(
        method='list_policies',
        service_response={'Policies': [
            {'PolicyName': 'quickhost-create', 'Arn': 'arn:policy-create-123'},
            {'PolicyName': 'quickhost-describe', 'Arn': 'arn:policy-describe-123'},
            {'PolicyName': 'quickhost-destroy', 'Arn': 'arn:policy-destroy-123'},
            {'PolicyName': 'quickhost-update', 'Arn': 'arn:policy-update-123'},
        ]},
        expected_params={'PathPrefix': '/quickhost/'},
    )

    iam_r_stubber.add_response( 'add_user_to_group', {}, {'GroupName': aws_group_name, 'UserName': aws_username})


    iam_r_stubber.activate()
    iam_c_stubber.activate()
    patched_admin_aws_iam.iam = iam_r
    patched_admin_aws_iam.client = iam_c
    return patched_admin_aws_iam

def test_attach_policies_and_group(stub_attach_policies_and_group: AWSIam.Iam):
    assert stub_attach_policies_and_group.attach_policies_and_group()

@pytest.fixture
def stub_attach_policies_and_group_as_wrong_user(patched_get_session, patched_aws_iam: AWSIam.Iam):
    iam_r = patched_get_session().resource("iam")
    iam_c = patched_get_session().client("iam")
    iam_r_stubber = Stubber(iam_r.meta.client)
    iam_c_stubber = Stubber(iam_c)

    # aws resource ids as they would be returned from api calls
    aws_username = 'quickhost-user'
    aws_user_id = 'AIDA123456789EXAMPLE'
    aws_user_path = '/quickhost/'
    aws_user_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:user{aws_user_path}{aws_username}'
    aws_user_creation_date = datetime.now()

    aws_group_name = 'quickhost-users'
    aws_group_id = 'AIDGPMS9RO4H3FEXAMPLE'
    aws_group_path = '/quickhost/'
    aws_group_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:group{aws_group_path}{aws_group_name}'
    aws_group_creation_date = aws_user_creation_date

    aws_user_response = {
        'UserName': aws_username,
        'UserId': aws_user_id,
        'Path': aws_user_path,
        'Arn': aws_user_arn,
        'CreateDate': aws_user_creation_date,
    }

    aws_group_response = {
        'GroupName': aws_group_name,
        'GroupId': aws_group_id,
        'Path': aws_group_path,
        'Arn': aws_group_arn,
        'CreateDate': aws_group_creation_date,
    }

    aws_policy_arn_create = f'arn:aws:iam::{FAKE_ACCOUNT}:policy/ci-quickhost-create'
    aws_policy_arn_describe = f'arn:aws:iam::{FAKE_ACCOUNT}:policy/ci-quickhost-describe'
    aws_policy_arn_destroy = f'arn:aws:iam::{FAKE_ACCOUNT}:policy/ci-quickhost-destroy'
    aws_policy_arn_update = f'arn:aws:iam::{FAKE_ACCOUNT}:policy/ci-quickhost-update'

    iam_c_stubber.add_response(
        method='list_policies',
        service_response={'Policies': [
            {'PolicyName': 'quickhost-create', 'Arn': aws_policy_arn_create},
            {'PolicyName': 'quickhost-describe', 'Arn': aws_policy_arn_describe},
            {'PolicyName': 'quickhost-destroy', 'Arn': aws_policy_arn_destroy},
            {'PolicyName': 'quickhost-update', 'Arn': aws_policy_arn_update},
        ]},
        expected_params={'PathPrefix': '/quickhost/'},
    )
    iam_r_stubber.add_response('attach_group_policy', {}, {'GroupName': aws_group_name, 'PolicyArn': aws_policy_arn_create})
    iam_r_stubber.add_response('attach_group_policy', {}, {'GroupName': aws_group_name, 'PolicyArn': aws_policy_arn_describe})
    iam_r_stubber.add_response('attach_group_policy', {}, {'GroupName': aws_group_name, 'PolicyArn': aws_policy_arn_update})
    iam_r_stubber.add_response('attach_group_policy', {}, {'GroupName': aws_group_name, 'PolicyArn': aws_policy_arn_destroy})

    iam_r_stubber.add_client_error('add_user_to_group', 'UnauthorizedOperation')

    iam_r_stubber.activate()
    iam_c_stubber.activate()
    patched_aws_iam.iam = iam_r
    patched_aws_iam.client = iam_c
    return patched_aws_iam

def test_attach_policies_and_group_as_wrong_user(stub_attach_policies_and_group_as_wrong_user: AWSIam.Iam):
    assert not stub_attach_policies_and_group_as_wrong_user.attach_policies_and_group()


@pytest.fixture
def stub_iam_create(patched_get_session_admin, patched_admin_aws_iam: AWSIam.Iam):
    iam_r = patched_get_session_admin().resource("iam")
    iam_c = patched_get_session_admin().client("iam")
    iam_r_stubber = Stubber(iam_r.meta.client)
    iam_c_stubber = Stubber(iam_c)

    # aws resource ids as they would be returned from api calls
    aws_username = 'quickhost-user'
    aws_user_id = 'AIDA123456789EXAMPLE'
    aws_user_path = '/quickhost/'
    aws_user_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:user{aws_user_path}{aws_username}'
    aws_user_creation_date = datetime.now()

    aws_group_name = 'quickhost-users'
    aws_group_id = 'AIDGPMS9RO4H3FEXAMPLE'
    aws_group_path = '/quickhost/'
    aws_group_arn = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:group{aws_group_path}{aws_group_name}'
    aws_group_creation_date = aws_user_creation_date

    aws_access_key_id = 'asdf-12345678901'
    aws_secret_access_key = 'asdf-secret-access-key-123'


    aws_user_response = {
        'UserName': aws_username,
        'UserId': aws_user_id,
        'Path': aws_user_path,
        'Arn': aws_user_arn,
        'CreateDate': aws_user_creation_date,
    }
    aws_group_response = {
        'GroupName': aws_group_name,
        'GroupId': aws_group_id,
        'Path': aws_group_path,
        'Arn': aws_group_arn,
        'CreateDate': aws_group_creation_date,
    }

    aws_policy_arn_create = f'arn:aws:iam::{FAKE_ACCOUNT}:policy/ci-quickhost-create'
    aws_policy_arn_describe = f'arn:aws:iam::{FAKE_ACCOUNT}:policy/ci-quickhost-describe'
    aws_policy_arn_destroy = f'arn:aws:iam::{FAKE_ACCOUNT}:policy/ci-quickhost-destroy'
    aws_policy_arn_update = f'arn:aws:iam::{FAKE_ACCOUNT}:policy/ci-quickhost-update'

    create_policy_params = {
        'Description': 'Allow quickhost-users to create apps',
        'Path': '/quickhost/',
        'PolicyDocument': '{"Version": "2012-10-17", "Statement": [{"Sid": '
                        '"quickhostCreate", "Effect": "Allow", "Action": '
                        '["ec2:CreateKeyPair", "ec2:CreateTags", '
                        '"ec2:RunInstances", "ec2:AuthorizeSecurityGroupIngress", '
                        '"ec2:CreateSecurityGroup"], "Resource": "*"}]}',
        'PolicyName': 'quickhost-create',
        'Tags': [{'Key': 'quickhost', 'Value': 'aws'}]
    }

    describe_policy_params = {
        'Description': 'Allow quickhost-users to describe apps',
        'Path': '/quickhost/',
        'PolicyDocument': '{"Version": "2012-10-17", "Statement": [{"Sid": '
                        '"quickhostDescribeUserActions", "Effect": "Allow", '
                        '"Action": ["iam:GetUser", "iam:GetGroup", "iam:ListUsers", '
                        '"iam:ListAccessKeys", "iam:ListAttachedGroupPolicies"], '
                        '"Resource": '
                        '["arn:aws:iam::some-aws-account:user/quickhost/*", '
                        '"arn:aws:iam::some-aws-account:group/quickhost/*"]}, '
                        '{"Sid": "quickhostDescribePolicies", "Effect": "Allow", '
                        '"Action": ["iam:ListPolicies"], "Resource": '
                        '"arn:aws:iam::some-aws-account:policy/quickhost/*"}, '
                        '{"Sid": "quickhostDescribe", "Effect": "Allow", "Action": '
                        '["ec2:DescribeInstances", "ec2:DescribeVpcs", '
                        '"ec2:DescribeSubnets", "ec2:DescribeInternetGateways", '
                        '"ec2:DescribeRouteTables", "ec2:DescribeImages", '
                        '"ec2:GetPasswordData"], "Resource": "*"}]}',
        'PolicyName': 'quickhost-describe',
        'Tags': [{'Key': 'quickhost', 'Value': 'aws'}]
    }

    update_policy_params = {
        'Description': 'Allow quickhost-users to update apps',
        'Path': '/quickhost/',
        'PolicyDocument': '{"Version": "2012-10-17", "Statement": [{"Sid": '
                        '"quickhostUpdate", "Effect": "Allow", "Action": [], '
                        '"Resource": "*"}]}',
        'PolicyName': 'quickhost-update',
        'Tags': [{'Key': 'quickhost', 'Value': 'aws'}]
    }

    delete_policy_params = {
        'Description': 'Allow quickhost-users to destroy apps',
        'Path': '/quickhost/',
        'PolicyDocument': '{"Version": "2012-10-17", "Statement": [{"Sid": '
                        '"quickhostDelete", "Effect": "Allow", "Action": '
                        '["ec2:DescribeSecurityGroups", "ec2:DeleteSecurityGroup", '
                        '"ec2:DeleteKeyPair", "ec2:DescribeKeyPairs", '
                        '"ec2:TerminateInstances"], "Resource": "*"}]}',
        'PolicyName': 'quickhost-destroy',
        'Tags': [{'Key': 'quickhost', 'Value': 'aws'}]
    }

    iam_c_stubber.add_response(
        method='list_policies',
        service_response={'Policies': [
            {'PolicyName': 'quickhost-create', 'Arn': aws_policy_arn_create},
            {'PolicyName': 'quickhost-describe', 'Arn': aws_policy_arn_describe},
            {'PolicyName': 'quickhost-destroy', 'Arn': aws_policy_arn_destroy},
            {'PolicyName': 'quickhost-update', 'Arn': aws_policy_arn_update},
        ]},
        expected_params={'PathPrefix': '/quickhost/'},
    )

    # _create_user_and_group()
    iam_r_stubber.add_response(
        method='create_user',
        service_response={'User': aws_user_response},
        expected_params={'UserName': aws_username, 'Path': aws_user_path, 'Tags': [{'Key': 'quickhost', 'Value': 'aws'}]}
    )
    iam_r_stubber.add_response('create_group',
        {'Group': aws_group_response},
        {'GroupName': aws_group_name, 'Path': aws_group_path}
    )
    iam_r_stubber.add_response('get_group', {
        'Group': aws_group_response,
        'Users': [],
    }, {'GroupName': aws_group_name})

    # _create_user_config()
    iam_r_stubber.add_response('get_user',
        {'User': {
            'UserName': aws_username,
            'UserId': aws_user_id,
            'Path': aws_user_path,
            'Arn': aws_user_arn,
            'CreateDate': aws_user_creation_date,
        }},
        {'UserName': aws_username}
    )

    # self._describe_iam_user()
    iam_r_stubber.add_response('list_access_keys', {'AccessKeyMetadata': [{'UserName': aws_username}]}, {'UserName': aws_username})
    iam_r_stubber.add_response('get_group', 
        {'Group': {
            'Path': aws_group_path,
            'GroupName': aws_group_name,
            'GroupId': aws_group_id,
            'Arn': aws_group_arn,
            'CreateDate': aws_user_creation_date,
            },
            'Users': [],
        },
        {'GroupName': aws_group_name}
    )

    iam_r_stubber.add_response('list_attached_group_policies', {}, {'GroupName': aws_group_name})
    iam_c_stubber.add_response('list_policies', {'Policies': []}, {'PathPrefix': aws_user_path})

    # self._create_user_credentials()
    iam_r_stubber.add_response('get_user',
        {'User': {
            'UserName': aws_username,
            'UserId': aws_user_id,
            'Path': aws_user_path,
            'Arn': aws_user_arn,
            'CreateDate': aws_user_creation_date,
        }},
        {'UserName': aws_username}
    )

    iam_r_stubber.add_response('list_access_keys', {'AccessKeyMetadata': [{'UserName': aws_username}]}, {'UserName': aws_username})
    iam_r_stubber.add_response('get_group', 
        {'Group': {
            'Path': aws_group_path,
            'GroupName': aws_group_name,
            'GroupId': aws_group_id,
            'Arn': aws_group_arn,
            'CreateDate': aws_user_creation_date,
        },
        'Users': [],
        },
    {'GroupName': aws_group_name})
    iam_r_stubber.add_response('list_attached_group_policies', {}, {'GroupName': aws_group_name})
    iam_r_stubber.add_response(
        method='create_access_key',
        service_response={
            'AccessKey': {
                'UserName': aws_username,
                'AccessKeyId': aws_access_key_id,
                'Status': 'asdf',
                'SecretAccessKey': aws_secret_access_key,
            }
        },
        expected_params={'UserName': aws_username}
    )

    # _create_qh_policy()
    # qh_policy_arns()
    iam_c_stubber.add_response('list_policies', {'Policies': []}, {'PathPrefix': aws_user_path})
    iam_c_stubber.add_response('list_policies', {'Policies': []}, {'PathPrefix': aws_user_path})
    iam_c_stubber.add_response('create_policy', {'Policy': {'Arn': aws_policy_arn_create}}, create_policy_params)
    iam_c_stubber.add_response('list_policies', {'Policies': []}, {'PathPrefix': aws_user_path})
    iam_c_stubber.add_response('create_policy', {'Policy': {'Arn': aws_policy_arn_describe}}, describe_policy_params)
    iam_c_stubber.add_response('list_policies', {'Policies': []}, {'PathPrefix': aws_user_path})
    iam_c_stubber.add_response('create_policy', {'Policy': {'Arn': aws_policy_arn_describe}}, update_policy_params)
    iam_c_stubber.add_response('list_policies', {'Policies': []}, {'PathPrefix': aws_user_path})
    iam_c_stubber.add_response('create_policy', {'Policy': {'Arn': aws_policy_arn_describe}}, delete_policy_params)
    iam_c_stubber.add_response('list_policies', {'Policies': []}, {'PathPrefix': aws_user_path})

    # attach_policies_and_group()
    iam_r_stubber.add_response('add_user_to_group', {}, {'GroupName': aws_group_name, 'UserName': aws_username})

    iam_r_stubber.activate()
    iam_c_stubber.activate()
    patched_admin_aws_iam.iam = iam_r
    patched_admin_aws_iam.client = iam_c
    return patched_admin_aws_iam


def test_iam_create(stub_iam_create):
    stub_iam_create.create()

@pytest.fixture
def stub_iam_create_non_admin_user(patched_get_session, patched_aws_iam: AWSIam.Iam):
    iam_r = patched_get_session().resource("iam")
    iam_c = patched_get_session().client("iam")
    iam_r_stubber = Stubber(iam_r.meta.client)
    iam_c_stubber = Stubber(iam_c)

    iam_r_stubber.activate()
    iam_c_stubber.activate()
    patched_aws_iam.iam = iam_r
    patched_aws_iam.client = iam_c
    return patched_aws_iam

def test_iam_create_non_admin_user(stub_iam_create_non_admin_user):
    with pytest.raises(QuickhostUnauthorized):
        stub_iam_create_non_admin_user.create()

###############################################
# aws profile actions
###############################################

def test_create_user_config_creates_when_no_quickhost_profile(aws_files: FakeAWSFiles, stub_describe_iam: AWSIam.Iam):
    with open(aws_files.config_file, 'r') as f:
        config_before_create = f.read()

    assert not re.search(r'\[profile quickhost-user\]', config_before_create)
    assert re.search(r'\[profile some-other-profile\]', config_before_create)

    with patch('quickhost_aws.AWSIam.Iam.describe', lambda x: {'credentials': {'default-region': ''}}):
        with MonkeyPatch.context() as m:
            m.setenv("HOME", aws_files.home_dir)
            stub_describe_iam._create_user_config()

    with open(aws_files.config_file, 'r') as f:
        config_after_create = f.read()

    assert re.search(r'\[profile quickhost-user\]', config_after_create)
    assert re.search(r'\[profile some-other-profile\]', config_after_create)

def test_create_user_config_create_idempotent_when_quickhost_profile_exists(aws_files_qh: FakeAWSFiles, stub_describe_iam: AWSIam.Iam):
    with open(aws_files_qh.config_file, 'r') as f:
        config_before_create = f.read()

    assert re.search(r'\[profile quickhost-user\]', config_before_create)
    assert re.search(r'\[profile some-other-profile\]', config_before_create)

    with patch('quickhost_aws.AWSIam.Iam.describe', lambda x: {'credentials': {'default-region': 'some-region'}}):
        with MonkeyPatch.context() as m:
            m.setenv("HOME", aws_files_qh.home_dir)
            stub_describe_iam._create_user_config()

    with open(aws_files_qh.config_file, 'r') as f:
        config_after_create = f.read()

    assert config_after_create == config_before_create


def test_delete_user_config_deletes_when_quickhost_profile_exists(aws_files_qh: FakeAWSFiles, stub_describe_iam: AWSIam.Iam):
    with open(aws_files_qh.config_file, 'r') as f:
        config_before_delete = f.read()

    assert re.search(r'\[profile quickhost-user\]', config_before_delete)
    assert re.search(r'\[profile some-other-profile\]', config_before_delete)

    with patch('quickhost_aws.AWSIam.Iam.describe', lambda x: {'credentials': {'default-region': 'some-region'}}):
        with MonkeyPatch.context() as m:
            m.setenv("HOME", aws_files_qh.home_dir)
            stub_describe_iam._delete_user_config()

    with open(aws_files_qh.config_file, 'r') as f:
        config_after_delete = f.read()

    assert not re.search(r'\[profile quickhost-user\]', config_after_delete)
    assert re.search(r'\[profile some-other-profile\]', config_after_delete)


def test_delete_user_config_delete_idempotent_when_quickhost_profile_DNE(aws_files: FakeAWSFiles, stub_describe_iam: AWSIam.Iam):
    with open(aws_files.config_file, 'r') as f:
        creds_before_delete = f.read()

    assert not re.search(r'\[profile quickhost-user\]', creds_before_delete)
    assert re.search(r'\[profile some-other-profile\]', creds_before_delete)

    with patch('quickhost_aws.AWSIam.Iam.describe', lambda x: {'credentials': {'default-region': 'some-region'}}):
        with MonkeyPatch.context() as m:
            m.setenv("HOME", aws_files.home_dir)
            stub_describe_iam._delete_user_config()

    with open(aws_files.config_file, 'r') as f:
        creds_after_delete = f.read()

    assert creds_after_delete == creds_before_delete


@pytest.fixture
def stub_create_user_credentials_appends_to_aws_credentials_file(patched_get_session, patched_aws_iam: AWSIam.Iam):
    iam_r = patched_get_session().resource("iam")
    iam_c = patched_get_session().client("iam")
    iam_r_stubber = Stubber(iam_r.meta.client)
    iam_c_stubber = Stubber(iam_c)

    # aws resource ids as they would be returned from api calls
    aws_username = 'quickhost-user'

    iam_r_stubber.add_response(
        method='create_access_key',
        service_response={
            'AccessKey': {
                'UserName': aws_username,
                'AccessKeyId': 'asdf-12345678901',
                'Status': 'asdf',
                'SecretAccessKey': 'asdf-secret-access-key-123'
            }
        },
        expected_params={'UserName': aws_username}
    )

    iam_r_stubber.activate()
    iam_c_stubber.activate()
    patched_aws_iam.iam = iam_r
    patched_aws_iam.client = iam_c
    return patched_aws_iam


def test_create_user_credentials_appends_to_aws_credentials_file(aws_files: FakeAWSFiles, stub_create_user_credentials_appends_to_aws_credentials_file: AWSIam.Iam):
    with open(aws_files.credentials_file, 'r') as f:
        creds_before_create = f.read()

    assert not re.search(r'\[quickhost-user\]', creds_before_create)
    assert re.search(r'\[default\]', creds_before_create)
    assert re.search(r'\[some-other-profile\]', creds_before_create)

    with patch('quickhost_aws.AWSIam.Iam.describe', lambda x: {'credentials': {'credentials-exist': False}}):
        with MonkeyPatch.context() as m:
            m.setenv("HOME", aws_files.home_dir)
            stub_create_user_credentials_appends_to_aws_credentials_file._create_user_credentials()

    with open(aws_files.credentials_file, 'r') as f:
        creds_after_create = f.read()

    assert re.search(r'\[quickhost-user\]', creds_after_create)
    assert re.search(r'\[default\]', creds_after_create)
    assert re.search(r'\[some-other-profile\]', creds_after_create)


def test_create_user_credentials_dempotent_when_aws_credentials_exists(aws_files_qh: FakeAWSFiles, stub_describe_iam: AWSIam.Iam):
    with open(aws_files_qh.credentials_file, 'r') as f:
        creds_before_create = f.read()

    assert re.search(r'\[quickhost-user\]', creds_before_create)
    assert re.search(r'\[default\]', creds_before_create)
    assert re.search(r'\[some-other-profile\]', creds_before_create)

    with patch('quickhost_aws.AWSIam.Iam.describe', lambda x: {'credentials': {'credentials-exist': True}}):
        with MonkeyPatch.context() as m:
            m.setenv("HOME", aws_files_qh.home_dir)
            stub_describe_iam._create_user_credentials()

    with open(aws_files_qh.credentials_file, 'r') as f:
        creds_after_create = f.read()

    assert creds_before_create == creds_after_create

@pytest.fixture
def stub_delete_user_credentials_when_aws_credentials_exists(patched_get_session, patched_aws_iam: AWSIam.Iam):
    iam_r = patched_get_session().resource("iam")
    iam_c = patched_get_session().client("iam")
    iam_r_stubber = Stubber(iam_r.meta.client)
    iam_c_stubber = Stubber(iam_c)

    # aws resource ids as they would be returned from api calls
    aws_username = 'quickhost-user'
    aws_access_key_id = 'asdf-12345678901'

    iam_r_stubber.add_response(
        method='list_access_keys',
        service_response={
            'AccessKeyMetadata': [{
                'UserName': aws_username,
                'AccessKeyId': aws_access_key_id,
            }]
        },
        expected_params={'UserName': aws_username}
    )
    iam_r_stubber.add_response(
        method='delete_access_key',
        service_response={},
        expected_params={'AccessKeyId': aws_access_key_id, 'UserName': aws_username}
    )

    iam_r_stubber.activate()
    iam_c_stubber.activate()
    patched_aws_iam.iam = iam_r
    patched_aws_iam.client = iam_c
    return patched_aws_iam


def test_delete_user_credentials_when_aws_credentials_exists(aws_files_qh: FakeAWSFiles, stub_delete_user_credentials_when_aws_credentials_exists: AWSIam.Iam):
    with open(aws_files_qh.credentials_file, 'r') as f:
        creds_before_create = f.read()

    assert re.search(r'\[quickhost-user\]', creds_before_create)
    assert re.search(r'\[default\]', creds_before_create)
    assert re.search(r'\[some-other-profile\]', creds_before_create)

    with patch('quickhost_aws.AWSIam.Iam.describe', lambda x: {'credentials': {'credentials-exist': True}}):
        with MonkeyPatch.context() as m:
            m.setenv("HOME", aws_files_qh.home_dir)
            stub_delete_user_credentials_when_aws_credentials_exists._delete_user_credentials()

    with open(aws_files_qh.credentials_file, 'r') as f:
        creds_after_create = f.read()

    assert not re.search(r'\[quickhost-user\]', creds_after_create)
    assert re.search(r'\[default\]', creds_after_create)
    assert re.search(r'\[some-other-profile\]', creds_after_create)


# i guess make sure that quickhost user credentials are deleted, even if there
# are no credentials to be found in the aws credentials file.
@pytest.fixture
def stub_delete_user_credentials_idempotent_when_aws_credentials_DNE(patched_get_session, patched_aws_iam: AWSIam.Iam):
    iam_r = patched_get_session().resource("iam")
    iam_c = patched_get_session().client("iam")
    iam_r_stubber = Stubber(iam_r.meta.client)
    iam_c_stubber = Stubber(iam_c)

    # aws resource ids as they would be returned from api calls
    aws_username = 'quickhost-user'
    aws_access_key_id = 'asdf-12345678901'

    iam_r_stubber.add_response(
        method='list_access_keys',
        service_response={
            'AccessKeyMetadata': [{
                'UserName': aws_username,
                'AccessKeyId': aws_access_key_id,
            }]
        },
        expected_params={'UserName': aws_username}
    )
    iam_r_stubber.add_response(
        method='delete_access_key',
        service_response={},
        expected_params={'AccessKeyId': aws_access_key_id, 'UserName': aws_username}
    )

    iam_r_stubber.activate()
    iam_c_stubber.activate()
    patched_aws_iam.iam = iam_r
    patched_aws_iam.client = iam_c
    return patched_aws_iam


def test_delete_user_credentials_idempotent_when_aws_credentials_DNE(aws_files: FakeAWSFiles, stub_delete_user_credentials_idempotent_when_aws_credentials_DNE: AWSIam.Iam):
    with open(aws_files.credentials_file, 'r') as f:
        creds_before_create = f.read()

    assert not re.search(r'\[quickhost-user\]', creds_before_create)
    assert re.search(r'\[default\]', creds_before_create)
    assert re.search(r'\[some-other-profile\]', creds_before_create)

    with patch('quickhost_aws.AWSIam.Iam.describe', lambda x: {'credentials': {'credentials-exist': False}}):
        with MonkeyPatch.context() as m:
            m.setenv("HOME", aws_files.home_dir)
            stub_delete_user_credentials_idempotent_when_aws_credentials_DNE._delete_user_credentials()

    with open(aws_files.credentials_file, 'r') as f:
        creds_after_create = f.read()
    
    assert creds_after_create == creds_before_create


def test_describe_user_credentials_qh_DNE(aws_files: FakeAWSFiles, patched_aws_iam: AWSIam.Iam):
    with open(aws_files.credentials_file, 'r') as f:
        creds_before_create = f.read()

    assert not re.search(r'\[quickhost-user\]', creds_before_create)
    assert re.search(r'\[default\]', creds_before_create)
    assert re.search(r'\[some-other-profile\]', creds_before_create)

    with MonkeyPatch.context() as m:
        m.setenv("HOME", aws_files.home_dir)
        resp = patched_aws_iam._describe_user_credentials()
        assert not resp['credentials-exist']


def test_describe_user_credentials_qh(aws_files_qh: FakeAWSFiles, patched_aws_iam: AWSIam.Iam):
    with open(aws_files_qh.credentials_file, 'r') as f:
        creds_before_create = f.read()

    assert re.search(r'\[quickhost-user\]', creds_before_create)
    assert re.search(r'\[default\]', creds_before_create)
    assert re.search(r'\[some-other-profile\]', creds_before_create)

    with MonkeyPatch.context() as m:
        m.setenv("HOME", aws_files_qh.home_dir)
        resp = patched_aws_iam._describe_user_credentials()
        assert resp['credentials-exist']


def test_describe_user_credentials_no_files(home_dir: str):
    print(os.environ.get("HOME"))
    print(home_dir)
    for f in (Path(home_dir)).iterdir():
        print(f)
        assert False  # home_dir should be empty
    def _patched_session(*args, **kwargs):
        return boto3.session.Session(aws_access_key_id=FAKE_AWS_ACCESS_KEY_ID, aws_secret_access_key=FAKE_AWS_SECRET_ACCESS_KEY)
    def _patched_caller_info(*args, **kwargs):
        pass
    with patch('quickhost_aws.AWSIam.AWSResourceBase._get_session', _patched_session), \
        patch('quickhost_aws.AWSIam.AWSResourceBase.get_caller_info', _patched_caller_info):
        awsiam = AWSIam.Iam(profile='asdf', region='reg')
    resp = awsiam._describe_user_credentials()
    assert not resp['credentials-exist']
    assert resp['default-region'] == ''
