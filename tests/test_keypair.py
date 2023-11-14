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
from quickhost_aws import AWSKeypair

from .fixtures2 import *


@pytest.fixture
def patched_kp(patched_get_session, patched_get_caller_info):
    with patch('quickhost_aws.AWSSG.AWSResourceBase._get_session', patched_get_session), \
        patch('quickhost_aws.AWSSG.AWSResourceBase.get_caller_info', patched_get_caller_info):
        return AWSKeypair.KP(app_name=FAKE_APP_NAME, profile='asdf', region='reg')


def test_create_ssh_key_file(ssh_dir: FakeSSHFiles, patched_kp: AWSKeypair.KP):
    new_priv_key = Path(ssh_dir.home_dir) / '.ssh' / 'some-keyname.pem'
    new_key_material = 'asdf'

    assert not new_priv_key.exists()

    patched_kp._create_ssh_key_file(key_material=new_key_material, ssh_key_filepath=new_priv_key.absolute())

    assert new_priv_key.exists()
    with new_priv_key.open('r') as f:
        assert f.read() == new_key_material
    assert Path(ssh_dir.existing_pem_file).exists()
    assert Path(ssh_dir.existing_pub_file).exists()


def test_create_ssh_key_file_doesnt_create_when_exists(ssh_dir: FakeSSHFiles, patched_kp: AWSKeypair.KP):
    new_priv_key = Path(ssh_dir.home_dir) / '.ssh' / 'id_rsa.pem'
    new_key_material = 'asdf'

    assert new_priv_key.exists()

    with pytest.raises(SystemExit):
        patched_kp._create_ssh_key_file(key_material=new_key_material, ssh_key_filepath=new_priv_key.absolute())

    assert new_priv_key.exists()
    with new_priv_key.open('r') as f:
        assert f.read() == ''
    assert Path(ssh_dir.existing_pem_file).exists()
    assert Path(ssh_dir.existing_pub_file).exists()


@pytest.fixture
def stub_get_key_id(patched_get_session, patched_kp):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    # aws resource ids as they would be returned from api calls
    aws_kp_id = 'key-pair-id-12345'

    ec2_c_stubber.add_response('describe_key_pairs',
        {'KeyPairs': [{
            'KeyPairId': aws_kp_id
        }]},
        {'DryRun': False, 'IncludePublicKey': True, 'KeyNames': [FAKE_APP_NAME]}
    )

    ec2_c_stubber.activate()
    patched_kp.client = ec2_c
    return patched_kp


def test_get_key_id(stub_get_key_id):
    assert stub_get_key_id.get_key_id() == 'key-pair-id-12345'


@pytest.fixture
def stub_get_key_id_DNE(patched_get_session, patched_kp):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    ec2_c_stubber.add_response('describe_key_pairs', {'KeyPairs': []}, {'DryRun': False, 'IncludePublicKey': True, 'KeyNames': [FAKE_APP_NAME]})

    ec2_c_stubber.activate()
    patched_kp.client = ec2_c
    return patched_kp


def test_get_key_id_DNE(stub_get_key_id_DNE):
    assert stub_get_key_id_DNE.get_key_id() is None


@pytest.fixture
def stub_get_key_id_boto_exception(patched_get_session, patched_kp):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)

    ec2_c_stubber.add_client_error('describe_key_pairs', 'some-error')

    ec2_c_stubber.activate()
    patched_kp.client = ec2_c
    return patched_kp


def test_get_key_id_boto_exception(stub_get_key_id_boto_exception):
    assert stub_get_key_id_boto_exception.get_key_id() is None
    

@pytest.fixture
def stub_keypair_create_already_exists_raises(patched_get_session, patched_kp):
    print(patched_get_session().profile_name)
    r = patched_get_session().resource("ec2")
    s = patched_get_session().client("ec2")
    ec2_r_stubber = Stubber(r.meta.client)
    ec2_c_stubber = Stubber(s)

    aws_keypair_id = "some_key_id"
    aws_keypair_name = "some_key_name"
    aws_key_fingerprint = "1f:51:ae:28:bf:89:e9:d8:1f:25:5d:37:2d:7d:b8:ca:9f:f5:f1:6f"

    ec2_c_stubber.add_response('describe_key_pairs',
        {'KeyPairs':[{
            'KeyPairId': aws_keypair_id,
            'KeyName': aws_keypair_name,
            'KeyFingerprint': aws_key_fingerprint,
            'Tags': [
                {'Key':'asdf', 'Value': 'asdf'},
                {'Key':'asdf', 'Value': 'asdf'}
            ]
        }]},
        
        {'KeyNames': [FAKE_APP_NAME], 'DryRun': False, 'IncludePublicKey': True}
    )

    ec2_r_stubber.activate()
    ec2_c_stubber.activate()
    patched_kp.ec2 = r
    patched_kp.client = s
    return patched_kp


def test_keypair_create_already_exists_raises(stub_keypair_create_already_exists_raises):
    with pytest.raises(SystemExit):
        stub_keypair_create_already_exists_raises.create(ssh_key_filepath='/some/useless/dir/')


@pytest.fixture
def stub_keypair_create(ssh_dir, patched_get_session, patched_kp):
    def _w(expected_ssh_filepath: str):
        r = patched_get_session().resource("ec2")
        s = patched_get_session().client("ec2")
        ec2_r_stubber = Stubber(r.meta.client)
        ec2_c_stubber = Stubber(s)

        aws_keypair_name = "some_key_name"
        aws_keypair_id = "some_key_id"
        aws_key_fingerprint = "1f:51:ae:28:bf:89:e9:d8:1f:25:5d:37:2d:7d:b8:ca:9f:f5:f1:6f"
        aws_key_material = 'asdf'

        ec2_c_stubber.add_client_error('describe_key_pairs', 'InvalidKeyPair.NotFound')
        ec2_c_stubber.add_response('create_key_pair',
            {
                'KeyName': aws_keypair_name,
                'KeyMaterial': aws_key_material,
                'KeyPairId': aws_keypair_id,
                'KeyFingerprint': aws_key_fingerprint,
            },
            {'DryRun': False, 'KeyName': FAKE_APP_NAME, 'KeyType': 'rsa',
                'TagSpecifications': [
                    {
                        'ResourceType': 'key-pair',
                        'Tags': [
                            {'Key': 'quickhost', 'Value': FAKE_APP_NAME},
                            {'Key': 'ssh_key_filepath', 'Value': expected_ssh_filepath}
                        ]}]
            }
        )

        ec2_r_stubber.activate()
        ec2_c_stubber.activate()
        patched_kp.ec2 = r
        patched_kp.client = s
        return patched_kp
    return _w


def test_keypair_create(ssh_dir: FakeSSHFiles, stub_keypair_create: AWSKeypair.KP):
    aws_keypair_name = "some_key_name"
    aws_keypair_id = "some_key_id"
    aws_key_fingerprint = "1f:51:ae:28:bf:89:e9:d8:1f:25:5d:37:2d:7d:b8:ca:9f:f5:f1:6f"
    aws_key_material = 'asdf'

    new_priv_key = Path(ssh_dir.home_dir) / '.ssh' / 'some-keyname.pem'
    new_priv_key_str = str(new_priv_key.absolute())

    assert not ( 'home' in new_priv_key_str )
    assert not new_priv_key.exists()

    r = stub_keypair_create( new_priv_key_str ).create(ssh_key_filepath=new_priv_key_str)

    assert r == {
        'key_name': aws_keypair_name,
        'ssh_key_filepath': new_priv_key_str,
        'key_id': aws_keypair_id,
        'key_fingerprint': aws_key_fingerprint,
    }

    assert new_priv_key.exists()
    with new_priv_key.open('r') as f:
        assert f.read() == aws_key_material


@pytest.fixture
def stub_keypair_destroy(ssh_dir, patched_get_session, patched_kp):
    def _w(expected_ssh_filepath: str):
        s = patched_get_session().client("ec2")
        ec2_c_stubber = Stubber(s)

        aws_keypair_id = "some_key_id"
        aws_keypair_name = "some_key_name"
        aws_key_fingerprint = "1f:51:ae:28:bf:89:e9:d8:1f:25:5d:37:2d:7d:b8:ca:9f:f5:f1:6f"
        aws_key_material = 'asdf'

        ec2_c_stubber.add_response('describe_key_pairs',
            {'KeyPairs':[{
                'KeyPairId': aws_keypair_id,
                'KeyName': aws_keypair_name,
                'KeyFingerprint': aws_key_fingerprint,
                'Tags': [
                    {'Key':'quickhost', 'Value': FAKE_APP_NAME},
                    {'Key':'ssh_key_filepath', 'Value': expected_ssh_filepath}
                ]
            }]},
            
            {'KeyNames': [FAKE_APP_NAME], 'DryRun': False, 'IncludePublicKey': True}
        )
        ec2_c_stubber.add_response('delete_key_pair',
            {},
            {'DryRun': False, 'KeyPairId': aws_keypair_id},
        )


        ec2_c_stubber.activate()
        patched_kp.client = s
        return patched_kp
    return _w


def test_keypair_destroy(ssh_dir: FakeSSHFiles, stub_keypair_destroy: AWSKeypair.KP):
    aws_keypair_id = "some_key_id"
    aws_key_fingerprint = "1f:51:ae:28:bf:89:e9:d8:1f:25:5d:37:2d:7d:b8:ca:9f:f5:f1:6f"
    aws_key_material = 'asdf'

    new_priv_key = Path(ssh_dir.home_dir) / '.ssh' / 'some-keyname.pem'
    new_priv_key.touch()
    new_priv_key_str = str(new_priv_key.absolute())
    assert not ( 'home' in new_priv_key_str )

    assert new_priv_key.exists()
    r = stub_keypair_destroy( new_priv_key_str ).destroy()
    assert not new_priv_key.exists()
    assert Path(ssh_dir.existing_pem_file).exists()
    assert Path(ssh_dir.existing_pub_file).exists()


@pytest.fixture
def stub_keypair_destroy_aws_key_DNE(ssh_dir, patched_get_session, patched_kp):
    s = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(s)

    ec2_c_stubber.add_client_error('describe_key_pairs', 'InvalidKeyPair.NotFound')

    ec2_c_stubber.activate()
    patched_kp.client = s
    return patched_kp


def test_keypair_destroy_aws_key_DNE(ssh_dir: FakeSSHFiles, stub_keypair_destroy_aws_key_DNE: AWSKeypair.KP):
    assert not stub_keypair_destroy_aws_key_DNE.destroy()


@pytest.fixture
def stub_keypair_destroy_key_file_DNE(ssh_dir, patched_get_session, patched_kp):
    def _w(expected_ssh_filepath: str):
        s = patched_get_session().client("ec2")
        ec2_c_stubber = Stubber(s)

        aws_keypair_id = "some_key_id"
        aws_keypair_name = "some_key_name"
        aws_key_fingerprint = "1f:51:ae:28:bf:89:e9:d8:1f:25:5d:37:2d:7d:b8:ca:9f:f5:f1:6f"
        aws_key_material = 'asdf'


        ec2_c_stubber.add_response('describe_key_pairs',
            {'KeyPairs':[{
                'KeyPairId': aws_keypair_id,
                'KeyName': aws_keypair_name,
                'KeyFingerprint': aws_key_fingerprint,
                'Tags': [
                    {'Key':'quickhost', 'Value': FAKE_APP_NAME},
                    {'Key': 'ssh_key_filepath', 'Value': expected_ssh_filepath}
                ]
            }]},
            
            {'KeyNames': [FAKE_APP_NAME], 'DryRun': False, 'IncludePublicKey': True}
        )
        ec2_c_stubber.add_response('delete_key_pair',
            {},
            {'DryRun': False, 'KeyPairId': aws_keypair_id},
        )

        ec2_c_stubber.activate()
        patched_kp.client = s
        return patched_kp
    return _w


def test_keypair_destroy_key_file_DNE(ssh_dir: FakeSSHFiles, stub_keypair_destroy_key_file_DNE: AWSKeypair.KP):
    new_priv_key = Path(ssh_dir.home_dir) / '.ssh' / 'some-keyname.pem'
    new_priv_key_str = str(new_priv_key.absolute())

    assert not new_priv_key.exists()
    assert not stub_keypair_destroy_key_file_DNE( new_priv_key_str ).destroy()


@pytest.fixture
def stub_keypair_windows_get_password_raises_fnf(ssh_dir, patched_get_session, patched_kp):
    def _w(expected_ssh_filepath: str):
        s = patched_get_session().client("ec2")
        ec2_c_stubber = Stubber(s)

        aws_keypair_id = "some_key_id"
        aws_keypair_name = "some_key_name"
        aws_key_fingerprint = "1f:51:ae:28:bf:89:e9:d8:1f:25:5d:37:2d:7d:b8:ca:9f:f5:f1:6f"


        ec2_c_stubber.add_response('describe_key_pairs',
            {'KeyPairs':[{
                'KeyPairId': aws_keypair_id,
                'KeyName': aws_keypair_name,
                'KeyFingerprint': aws_key_fingerprint,
                'Tags': [
                    {'Key':'quickhost', 'Value': FAKE_APP_NAME},
                    {'Key': 'ssh_key_filepath', 'Value': expected_ssh_filepath}
                ]
            }]},
            
            {'KeyNames': [FAKE_APP_NAME], 'DryRun': False, 'IncludePublicKey': True}
        )

        ec2_c_stubber.activate()
        patched_kp.client = s
        return patched_kp
    return _w


def test_keypair_windows_get_password_raises_fnf(ssh_dir: FakeSSHFiles, stub_keypair_windows_get_password_raises_fnf: AWSKeypair.KP):
    new_priv_key = Path(ssh_dir.home_dir) / '.ssh' / 'some-keyname.pem'
    new_priv_key_str = str(new_priv_key.absolute())

    assert not new_priv_key.exists()
    with pytest.raises(FileNotFoundError):
        assert not stub_keypair_windows_get_password_raises_fnf( new_priv_key_str ).windows_get_password('some-instnace-id')


@pytest.fixture
def stub_keypair_windows_get_password(ssh_dir, patched_get_session, patched_kp):
    def _w(expected_ssh_filepath: str):
        s = patched_get_session().client("ec2")
        ec2_c_stubber = Stubber(s)

        aws_keypair_id = "some_key_id"
        aws_keypair_name = "some_key_name"
        aws_key_fingerprint = "1f:51:ae:28:bf:89:e9:d8:1f:25:5d:37:2d:7d:b8:ca:9f:f5:f1:6f"


        ec2_c_stubber.add_response('describe_key_pairs',
            {'KeyPairs':[{
                'KeyPairId': aws_keypair_id,
                'KeyName': aws_keypair_name,
                'KeyFingerprint': aws_key_fingerprint,
                'Tags': [
                    {'Key':'quickhost', 'Value': FAKE_APP_NAME},
                    {'Key': 'ssh_key_filepath', 'Value': expected_ssh_filepath}
                ]
            }]},
            
            {'KeyNames': [FAKE_APP_NAME], 'DryRun': False, 'IncludePublicKey': True}
        )

        ec2_c_stubber.add_response('get_password_data', {'PasswordData': 'some-encrypted-content'}, {'InstanceId': 'some-instnace-id'})

        ec2_c_stubber.activate()
        patched_kp.client = s
        return patched_kp
    return _w


@pytest.mark.xfail
def test_keypair_windows_get_password(ssh_dir: FakeSSHFiles, stub_keypair_windows_get_password: AWSKeypair.KP):
    new_priv_key = Path(ssh_dir.home_dir) / '.ssh' / 'some-keyname.pem'
    new_priv_key_str = str(new_priv_key.absolute())
    new_priv_key.touch()

    assert new_priv_key.exists()
    assert not stub_keypair_windows_get_password( new_priv_key_str ).windows_get_password('some-instnace-id')
