import tempfile
import shutil
from pathlib import Path
from textwrap import dedent
from collections import namedtuple
import logging

import pytest
from pytest import MonkeyPatch

from botocore.stub import Stubber
from mock import patch, Mock
import boto3


FAKE_APP_NAME = 'test-app-name'
FAKE_AWS_ACCESS_KEY_ID = 'AKIAISACAR'
FAKE_AWS_SECRET_ACCESS_KEY = 'asdfkljh'
FAKE_REGION = 'some-region'
FAKE_ACCOUNT = '012345678901'

FakeAWSFiles = namedtuple('FakeAWSFiles', ['home_dir', 'credentials_file', 'config_file'])


@pytest.fixture
def caplog_gate(caplog):
    with caplog.at_level(logging.CRITICAL, logger='botocore'), \
            caplog.at_level(logging.CRITICAL, logger='boto3') \
        :
        yield caplog


@pytest.fixture
def home_dir():
    """
    Linux: patch the HOME environment variable with a temporary directory, and yield the directory
    """
    cd = tempfile.mkdtemp()
    with MonkeyPatch.context() as m:
        m.setenv("HOME", cd)
        try:
            yield cd
        finally:
            shutil.rmtree(cd)

@pytest.fixture
def home_dir_fixture():
    """
    Linux: patch the HOME environment variable with a temporary directory, and yield the directory
    """
    cd = tempfile.mkdtemp()
    with MonkeyPatch.context() as m:
        m.setenv("HOME", cd)
        try:
            yield cd
        finally:
            shutil.rmtree(cd)


@pytest.fixture
def aws_files_empty(home_dir):
    aws_dir = Path(home_dir) / '.aws'
    aws_dir.mkdir()
    creds_file = (aws_dir / 'credentials')
    creds_file.touch()
    config_file = (aws_dir / 'config')
    config_file.touch()

    return FakeAWSFiles(home_dir=str(home_dir), credentials_file=str(creds_file.absolute()), config_file=str(config_file.absolute()))

@pytest.fixture
def aws_files_empty_fixture(home_dir_fixture):
    aws_dir = Path(home_dir_fixture) / '.aws'
    aws_dir.mkdir()
    creds_file = (aws_dir / 'credentials')
    creds_file.touch()
    config_file = (aws_dir / 'config')
    config_file.touch()

    return FakeAWSFiles(home_dir=str(home_dir_fixture), credentials_file=str(creds_file.absolute()), config_file=str(config_file.absolute()))

@pytest.fixture
def aws_files(aws_files_empty: FakeAWSFiles):
    """"before-quickhost" aws files"""
    with open(aws_files_empty.credentials_file, 'w') as cf:
        cf.write(dedent(f"""
            [default]
            aws_access_key_id = notouching_access_key_id1
            aws_secret_access_key = notouching_secret_access_key1

            [some-other-profile]
            aws_access_key_id = notouching_access_key_id2
            aws_secret_access_key = notouching_secret_access_key2
        """))
    with open(aws_files_empty.config_file, 'w') as config:
        config.write(dedent(f"""
            [default]
            region = some-other-region
            output = text

            [profile some-other-profile]
            region = some-other-region
            output = json
        """))

    return aws_files_empty

@pytest.fixture
def aws_files_qh(aws_files: FakeAWSFiles):
    """"after-quickhost" aws files"""
    with open(aws_files.credentials_file, 'a') as cf:
        cf.write(dedent(f"""
            [quickhost-user]
            aws_access_key_id = {FAKE_AWS_ACCESS_KEY_ID}
            aws_secret_access_key = {FAKE_AWS_SECRET_ACCESS_KEY}
        """))
    with open(aws_files.config_file, 'a') as config:
        config.write(dedent(f"""
            [profile quickhost-user]
            region = {FAKE_REGION}
        """))

    return aws_files

@pytest.fixture
def aws_files_fixture(aws_files_empty_fixture: FakeAWSFiles):
    """"after-quickhost" aws files"""
    with open(aws_files_empty_fixture.credentials_file, 'a') as cf:
        cf.write(dedent(f"""
            [default]
            aws_access_key_id = {FAKE_AWS_ACCESS_KEY_ID}
            aws_secret_access_key = {FAKE_AWS_SECRET_ACCESS_KEY}

            [quickhost-user]
            aws_access_key_id = {FAKE_AWS_ACCESS_KEY_ID}
            aws_secret_access_key = {FAKE_AWS_SECRET_ACCESS_KEY}
        """))
    with open(aws_files_empty_fixture.config_file, 'a') as config:
        config.write(dedent(f"""
            [default]
            region = {FAKE_REGION}
            [profile quickhost-user]
            region = {FAKE_REGION}
        """))

    return aws_files_empty_fixture


@pytest.fixture
def patched_get_session(caplog_gate, aws_files_fixture):
    """Use a fake set of AWS credentials files and patched HOME environment variable (Linux) to create a boto3 session as a stub."""
    def _f(*args, **kwargs):
        # if args:
        #     print(f"{args=}")
        # if len(kwargs):
        #     print("desired session: {}".format([(k,v) for k,v in kwargs.items() ]) )

        # There is no guarantee that the code being tested with call
        # get_session() with args or kwargs; there is no practical reason to
        # enforce this. So, it is safe to simply ignore whatever is passed to
        # _get_session(), and return a valid session to stub with.
        s = boto3.session.Session(profile_name='quickhost-user')
        assert s.region_name == 'some-region'
        return s
    return _f


@pytest.fixture
def patched_get_caller_info():
    def _f(*args, **kwargs):
        return {
            'username': 'quickhost-user'
        }
    return _f


FakeSSHFiles = namedtuple('FakeSSHFiles', ['home_dir', 'existing_pub_file', 'existing_pem_file'])

@pytest.fixture
def ssh_dir(home_dir):
    ssh_dir = Path(home_dir) / '.ssh'
    ssh_dir.mkdir(exist_ok=False)
    creds_file = (ssh_dir / 'credentials')
    creds_file.touch(exist_ok=False)
    existing_pem_file = (ssh_dir / 'id_rsa.pem')
    existing_pem_file.touch(exist_ok=False, mode=0o600)
    existing_pub_file = (ssh_dir / 'id_rsa')
    existing_pub_file.touch(exist_ok=False, mode=0o600)

    return FakeSSHFiles(home_dir=str(home_dir), existing_pub_file=str(existing_pub_file.absolute()), existing_pem_file=str(existing_pem_file.absolute()))

@pytest.fixture
def aws_files_qh_and_ssh(aws_files: FakeAWSFiles):
    """"after-quickhost" aws files"""
    with open(aws_files.credentials_file, 'a') as cf:
        cf.write(dedent(f"""
            [quickhost-user]
            aws_access_key_id = {FAKE_AWS_ACCESS_KEY_ID}
            aws_secret_access_key = {FAKE_AWS_SECRET_ACCESS_KEY}
        """))
    with open(aws_files.config_file, 'a') as config:
        config.write(dedent(f"""
            [profile quickhost-user]
            region = {FAKE_REGION}
        """))

    ssh_dir = Path(aws_files.home_dir) / '.ssh'
    ssh_dir.mkdir(exist_ok=False)
    creds_file = (ssh_dir / 'credentials')
    creds_file.touch(exist_ok=False)
    existing_pem_file = (ssh_dir / 'id_rsa.pem')
    existing_pem_file.touch(exist_ok=False, mode=0o600)
    existing_pub_file = (ssh_dir / 'id_rsa')
    existing_pub_file.touch(exist_ok=False, mode=0o600)

    ssh_files = FakeSSHFiles(home_dir=str(aws_files.home_dir), existing_pub_file=str(existing_pub_file.absolute()), existing_pem_file=str(existing_pem_file.absolute()))

    return aws_files, ssh_files
