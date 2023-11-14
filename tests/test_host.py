import pytest
import boto3
from botocore.stub import Stubber
from mock import patch, MagicMock
import tempfile
import os
from datetime import datetime

from quickhost_aws import AWSHost

# from .fixtures2 import patched_get_caller_info, patched_get_session
from .fixtures2 import *

FAKE_APP_NAME = 'test-app-name'

@pytest.fixture
def fake_userdata_file():
    ud = tempfile.mkstemp()
    try:
        yield ud
    finally:
        os.unlink(ud)


def patched_sleep(*args, **kwargs):
    pass

@pytest.fixture
def patched_aws_host(patched_get_session, patched_get_caller_info):
    with patch('quickhost_aws.AWSHost.AWSResourceBase._get_session', patched_get_session), \
        patch('quickhost_aws.AWSHost.AWSResourceBase.get_caller_info', patched_get_caller_info):
        return AWSHost.AWSHost(app_name=FAKE_APP_NAME, profile='asdf', region='reg')

@pytest.fixture
def stub_host_describe_empty_results(patched_get_session, patched_aws_host):
    ec2_r = patched_get_session().resource("ec2")
    ec2_c = patched_get_session().client("ec2")
    ec2_r_stubber = Stubber(ec2_r.meta.client)
    ec2_c_stubber = Stubber(ec2_c)
    filters = [{'Name': 'tag:quickhost', 'Values': [FAKE_APP_NAME]}, {'Name': 'instance-state-name', 'Values': ['running', 'pending']}]

    ec2_c_stubber.add_response('describe_instances', {
        'Reservations': [ {'Instances': []} ], 
    }, {'Filters': filters, 'MaxResults': 10, 'DryRun': False})

    ec2_r_stubber.activate()
    ec2_c_stubber.activate()
    patched_aws_host.ec2 = ec2_r
    patched_aws_host.client = ec2_c
    return patched_aws_host

def test_host_describe_empty_results(stub_host_describe_empty_results):
    assert len(stub_host_describe_empty_results.describe()) == 0


@pytest.fixture
def stub_host_describe_one_result(patched_get_session, patched_aws_host):
    ec2_r = patched_get_session().resource("ec2")
    ec2_c = patched_get_session().client("ec2")
    ec2_r_stubber = Stubber(ec2_r.meta.client)
    ec2_c_stubber = Stubber(ec2_c)
    filters = [{'Name': 'tag:quickhost', 'Values': [FAKE_APP_NAME]}, {'Name': 'instance-state-name', 'Values': ['running', 'pending']}]

    ec2_c_stubber.add_response('describe_instances', {
        'Reservations': [ {'Instances': [
            {
                'InstanceId': 'asdf',
                'LaunchTime': datetime(year=2023, month=1, day=1, hour=1, minute=1, second=1),
                'InstanceType': 'asdf',
                'KeyName': 'asdf',
                'PublicIpAddress': '1.2.3.4',
                'PrivateIpAddress': '9.8.7.6',
                'SubnetId': 'asdf',
                'VpcId': 'asdf',
                'Platform': 'ecks-d',
                'SecurityGroups': [{'GroupName': 'sg_name', 'GroupId': 'sg_id'}],
                'PlatformDetails': 'ecks-d',
                'State': {'Name':'running', 'Code': 69},
            }
        ]} ], 
    }, {'Filters': filters, 'MaxResults': 10, 'DryRun': False})

    ec2_r_stubber.activate()
    ec2_c_stubber.activate()
    patched_aws_host.ec2 = ec2_r
    patched_aws_host.client = ec2_c
    return patched_aws_host

def test_host_describe_one_result(stub_host_describe_one_result: AWSHost.AWSHost):
    d = stub_host_describe_one_result.describe()
    assert len(d) == 1
    assert isinstance(d[0], AWSHost.HostsDescribe)
    assert d[0].security_group == 'sg_id'
    assert d[0].platform == 'ecks-d'
    assert d[0].public_ip == '1.2.3.4'
    assert d[0].private_ip == '9.8.7.6'
    assert d[0].uptime_hrs


@pytest.fixture
def stub_host_get_latest_image(patched_get_session, patched_aws_host):
    ec2_r = patched_get_session().resource("ec2")
    ec2_c = patched_get_session().client("ec2")
    ec2_r_stubber = Stubber(ec2_r.meta.client)
    ec2_c_stubber = Stubber(ec2_c)

    ec2_c_stubber.add_response('describe_images', 
        {
            'Images': [
                {
                    'ImageId':'correct_latest_image',
                    'CreationDate': "2000-01-01T20:00:01.123Z",
                    'BlockDeviceMappings': [ {'DeviceName': 'xvda1', 'Ebs': {'VolumeSize': 20}} ],
                },{
                    'ImageId':'incorrect_latest_image',
                    'CreationDate': "1999-01-01T20:00:01.123Z",
                    'BlockDeviceMappings': [ {'DeviceName': 'xvda1', 'Ebs': {'VolumeSize': 20}} ],
                }
            ]
        }, {
            'DryRun': False, 
            'Filters': [
                {'Name': 'state', 'Values': ['available']},
                {'Name': 'architecture', 'Values': ['x86_64']},
                {'Name': 'name', 'Values': ['al2023-ami-2023.*-kernel-6.?-x86_64']}
            ], 'IncludeDeprecated': False}
    )

    ec2_r_stubber.activate()
    ec2_c_stubber.activate()
    patched_aws_host.ec2 = ec2_r
    patched_aws_host.client = ec2_c
    return patched_aws_host


def test_host_get_latest_image(stub_host_get_latest_image: AWSHost.AWSHost):
    assert stub_host_get_latest_image.get_latest_image(os='al2023')['image_id'] == 'correct_latest_image'


@pytest.fixture
def stub_wait_hosts_terminate(patched_get_session, patched_aws_host):
    ec2_r = patched_get_session().resource("ec2")
    ec2_c = patched_get_session().client("ec2")
    ec2_r_stubber = Stubber(ec2_r.meta.client)
    ec2_c_stubber = Stubber(ec2_c)
    filters = [{'Name': 'tag:quickhost', 'Values': [FAKE_APP_NAME]}, { 'Name': 'instance-state-name', 'Values': ['running', 'terminated', 'shutting-down'] }]
    describe_instance_response = lambda state: {
        'Reservations': [ {'Instances': [
            {
                'InstanceId': 'asdf',
                'InstanceType': 'asdf',
                'KeyName': 'asdf',
                'PublicIpAddress': '1.2.3.4',
                'SubnetId': 'asdf',
                'VpcId': 'asdf',
                'Platform': 'ecks-d',
                'SecurityGroups': [{'GroupName': 'sg_name', 'GroupId': 'sg_id'}],
                'PlatformDetails': 'ecks-d',
                'State': {'Name': state, 'Code': 123},
            }
        ]} ], 
    }

    ec2_c_stubber.add_response('describe_instances', describe_instance_response('running'), {'Filters': filters, 'MaxResults': 10, 'DryRun': False})
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('shutting-down'), {'Filters': filters, 'MaxResults': 10, 'DryRun': False})
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('terminated'), {'Filters': filters, 'MaxResults': 10, 'DryRun': False})

    ec2_r_stubber.activate()
    ec2_c_stubber.activate()
    patched_aws_host.ec2 = ec2_r
    patched_aws_host.client = ec2_c
    return patched_aws_host


def test_wait_hosts_terminate(stub_wait_hosts_terminate: AWSHost.AWSHost):
    with patch('quickhost_aws.AWSHost.time.sleep', patched_sleep):
        stub_wait_hosts_terminate.wait_for_hosts_to_terminate(['asdf'])

@pytest.fixture
def stub_wait_hosts_start(patched_get_session, patched_aws_host):
    ec2_r = patched_get_session().resource("ec2")
    ec2_c = patched_get_session().client("ec2")
    ec2_r_stubber = Stubber(ec2_r.meta.client)
    ec2_c_stubber = Stubber(ec2_c)
    filters = [{'Name': 'tag:quickhost', 'Values': [FAKE_APP_NAME]}, {'Name': 'instance-state-name', 'Values': ['running', 'pending']}]
    describe_instance_response = lambda state: {
        'Reservations': [ {'Instances': [
            {
                'InstanceId': 'asdf',
                'InstanceType': 'asdf',
                'KeyName': 'asdf',
                'PublicIpAddress': '1.2.3.4',
                'SubnetId': 'asdf',
                'VpcId': 'asdf',
                'Platform': 'ecks-d',
                'SecurityGroups': [{'GroupName': 'sg_name', 'GroupId': 'sg_id'}],
                'PlatformDetails': 'ecks-d',
                'State': {'Name': state, 'Code': 123},
            }
        ]} ], 
    }

    ec2_c_stubber.add_response('describe_instances', describe_instance_response('some-state-'), {'Filters': filters, 'MaxResults': 10, 'DryRun': False})
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('pending'), {'Filters': filters, 'MaxResults': 10, 'DryRun': False})
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('running'), {'Filters': filters, 'MaxResults': 10, 'DryRun': False})

    ec2_r_stubber.activate()
    ec2_c_stubber.activate()
    patched_aws_host.ec2 = ec2_r
    patched_aws_host.client = ec2_c
    return patched_aws_host


def test_wait_hosts_start(stub_wait_hosts_start: AWSHost.AWSHost):
    with patch('quickhost_aws.AWSHost.time.sleep', patched_sleep):
        stub_wait_hosts_start.wait_for_hosts_to_start(1)

@pytest.fixture
def stub_host_create(patched_get_session, patched_aws_host):
    ec2_r = patched_get_session().resource("ec2")
    ec2_c = patched_get_session().client("ec2")
    ec2_r_stubber = Stubber(ec2_r.meta.client)
    ec2_c_stubber = Stubber(ec2_c)
    param_host_count = 1

    filters = [{'Name': 'tag:quickhost', 'Values': [FAKE_APP_NAME]}, {'Name': 'instance-state-name', 'Values': ['running', 'pending']}]

    describe_instances_filter = lambda state_names: {'DryRun': False,
        'Filters': [{'Name': 'tag:quickhost', 'Values': [FAKE_APP_NAME]},
                    {'Name': 'instance-state-name', 'Values': state_names}],
        'MaxResults': 10}                           

    describe_instance_response = lambda state: {
        'Reservations': [ {'Instances': [
            {
                'InstanceId': 'asdf',
                'LaunchTime': datetime(year=2023, month=1, day=1, hour=1, minute=1, second=1),
                'InstanceType': 'asdf',
                'KeyName': 'asdf',
                'PublicIpAddress': '1.2.3.4',
                'PrivateIpAddress': '9.8.7.6',
                'SubnetId': 'asdf',
                'VpcId': 'asdf',
                'Platform': 'ecks-d',
                'SecurityGroups': [{'GroupName': 'sg_name', 'GroupId': 'sg_id'}],
                'PlatformDetails': 'ecks-d',
                'State': {'Name': state, 'Code': 123},
            }
        ]} ], 
    }

    # get_latest_image()
    ec2_c_stubber.add_response('describe_images', 
        {
            'Images': [{
                'ImageId': 'ami-1234567890EXAMPLE',
                'CreationDate': "2000-01-01T20:00:01.123Z",
                'BlockDeviceMappings': [ {'DeviceName': '/dev/sda1', 'Ebs': {'VolumeSize': 20}} ], 
            }]
        }, 
        {
            'DryRun': False, 
            'Filters': [
                {'Name': 'state', 'Values': ['available']},
                {'Name': 'architecture', 'Values': ['x86_64']},
                {'Name': 'name', 'Values': ['al2023-ami-2023.*-kernel-6.?-x86_64']}
            ], 'IncludeDeprecated': False
        }
    )

    # stub the check for existing hosts with FAKE_APP_NAME tag
    ec2_c_stubber.add_response('describe_instances', {
        'Reservations': [ { 'Instances': [] } ],
    }, 
        {'DryRun': False,
        'Filters': [{'Name': 'tag:quickhost', 'Values': [FAKE_APP_NAME]},
                    {'Name': 'instance-state-name', 'Values': ['running']}],
        'MaxResults': 10}                           
    )
    ec2_c_stubber.add_response('run_instances', {}, 
        {'BlockDeviceMappings': [{'DeviceName': '/dev/sda1',
                                        'Ebs': {'VolumeSize': 30}}],
                'DisableApiTermination': False,
                'DryRun': False,
                'ImageId': 'ami-1234567890EXAMPLE',
                'InstanceInitiatedShutdownBehavior': 'terminate',
                'InstanceType': '',
                'KeyName': '',
                'MaxCount': param_host_count,
                'MinCount': 1,
                'Monitoring': {'Enabled': False},
                'NetworkInterfaces': [{'AssociatePublicIpAddress': True,
                                    'DeviceIndex': 0,
                                    'Groups': [''],
                                    'SubnetId': ''}],
                'TagSpecifications': [{'ResourceType': 'instance',
                                    'Tags': [{'Key': 'quickhost', 'Value': 'test-app-name'},
                                                {'Key': 'Name', 'Value': 'test-app-name'}]},
                                    {'ResourceType': 'volume',
                                    'Tags': [{'Key': 'quickhost',
                                                'Value': 'test-app-name'}]}]}
    )

    # wait_for_hosts_to_start()
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('some-state-'), describe_instances_filter(['running', 'pending']))
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('pending'), describe_instances_filter(['running', 'pending']))
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('pending'), describe_instances_filter(['running', 'pending']))
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('pending'), describe_instances_filter(['running', 'pending']))
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('pending'), describe_instances_filter(['running', 'pending']))
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('running'), describe_instances_filter(['running', 'pending']))

    # _get_app_instances()
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('running'), describe_instances_filter(['running']))


    ec2_r_stubber.activate()
    ec2_c_stubber.activate()
    patched_aws_host.ec2 = ec2_r
    patched_aws_host.client = ec2_c
    return patched_aws_host

def test_host_create(stub_host_create: AWSHost.AWSHost):
    # NOTE: parameter validation happens in AWSApp().create()
    with patch('quickhost_aws.AWSHost.time.sleep', patched_sleep):
        assert stub_host_create.create(
            disk_size=30,
            instance_type='',
            key_name='',
            num_hosts=1,
            sgid='',
            ssh_key_filepath='',
            subnet_id='',
            userdata=None,
            _os='al2023'  # al2023, amazon-linux-2, ubuntu, windows, windows-core
        ) == {'region': 'reg', 'num_hosts': 1, 'instance_type': '', 'sgid': '', 'subnet_id': '', 'userdata': None, 'key_name': '', 'os': 'al2023', 'image_id': 'ami-1234567890EXAMPLE', 'disk_size': 30}


@pytest.fixture
def stub_host_destroy_idempotent_when_describe_instances_returns_empty(patched_get_session, patched_aws_host):
    ec2_r = patched_get_session().resource("ec2")
    ec2_c = patched_get_session().client("ec2")
    ec2_r_stubber = Stubber(ec2_r.meta.client)
    ec2_c_stubber = Stubber(ec2_c)

    ec2_c_stubber.add_response('describe_instances', {
        'Reservations': [ { 'Instances': [] } ],
    }, 
        {'DryRun': False,
        'Filters': [{'Name': 'tag:quickhost', 'Values': [FAKE_APP_NAME]},
                    {'Name': 'instance-state-name', 'Values': ['running']}],
        'MaxResults': 10}                           
    )

    ec2_r_stubber.activate()
    ec2_c_stubber.activate()
    patched_aws_host.ec2 = ec2_r
    patched_aws_host.client = ec2_c
    return patched_aws_host

def test_host_destroy_idempotent_when_describe_instances_returns_empty(stub_host_destroy_idempotent_when_describe_instances_returns_empty: AWSHost.AWSHost):
    with patch('quickhost_aws.AWSHost.time.sleep', patched_sleep):
        stub_host_destroy_idempotent_when_describe_instances_returns_empty.destroy()


@pytest.fixture
def stub_host_destroy(patched_get_session, patched_aws_host):
    ec2_r = patched_get_session().resource("ec2")
    ec2_c = patched_get_session().client("ec2")
    ec2_r_stubber = Stubber(ec2_r.meta.client)
    ec2_c_stubber = Stubber(ec2_c)
    param_host_count = 1

    filters = [{'Name': 'tag:quickhost', 'Values': [FAKE_APP_NAME]}, {'Name': 'instance-state-name', 'Values': ['running', 'pending']}]

    describe_instances_filter = lambda state_names: {'DryRun': False,
        'Filters': [{'Name': 'tag:quickhost', 'Values': [FAKE_APP_NAME]},
                    {'Name': 'instance-state-name', 'Values': state_names}],
        'MaxResults': 10}                           

    describe_instance_response = lambda state: {
        'Reservations': [ {'Instances': [
            {
                'InstanceId': 'asdf',
                'LaunchTime': datetime(year=2023, month=1, day=1, hour=1, minute=1, second=1),
                'InstanceType': 'asdf',
                'KeyName': 'asdf',
                'PublicIpAddress': '1.2.3.4',
                'PrivateIpAddress': '9.8.7.6',
                'SubnetId': 'asdf',
                'VpcId': 'asdf',
                'Platform': 'ecks-d',
                'SecurityGroups': [{'GroupName': 'sg_name', 'GroupId': 'sg_id'}],
                'PlatformDetails': 'ecks-d',
                'State': {'Name': state, 'Code': 123},
            }
        ]} ], 
    }

    ec2_c_stubber.add_response('describe_instances', describe_instance_response('running'), describe_instances_filter(['running']))
    ec2_c_stubber.add_response('terminate_instances', {}, {'InstanceIds': ['asdf']})

    # wait_for_hosts_to_terminate()
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('running'), describe_instances_filter(['running', 'terminated', 'shutting-down']))
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('shutting-down'), describe_instances_filter(['running', 'terminated', 'shutting-down']))
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('terminated'), describe_instances_filter(['running', 'terminated', 'shutting-down']))

    ec2_r_stubber.activate()
    ec2_c_stubber.activate()
    patched_aws_host.ec2 = ec2_r
    patched_aws_host.client = ec2_c
    return patched_aws_host

def test_host_destroy(stub_host_destroy: AWSHost.AWSHost):
    # NOTE: parameter validation happens in AWSApp().create()
    with patch('quickhost_aws.AWSHost.time.sleep', patched_sleep):
        stub_host_destroy.destroy()


@pytest.fixture
def stub_get_all_running_apps(patched_get_session, patched_aws_host):
    ec2_r = patched_get_session().resource("ec2")
    ec2_c = patched_get_session().client("ec2")
    ec2_r_stubber = Stubber(ec2_r.meta.client)
    ec2_c_stubber = Stubber(ec2_c)
    param_host_count = 1

    filters = [{'Name': 'tag:quickhost', 'Values': [FAKE_APP_NAME]}, {'Name': 'instance-state-name', 'Values': ['running', 'pending']}]

    describe_instances_filter = lambda state_names: {'DryRun': False,
        'Filters': [{'Name': 'tag:quickhost', 'Values': [FAKE_APP_NAME]},
                    {'Name': 'instance-state-name', 'Values': state_names}],
        'MaxResults': 10}                           

    describe_instance_response = lambda state: {
        'Reservations': [ {'Instances': [
            {
                'InstanceId': 'asdf',
                'LaunchTime': datetime(year=2023, month=1, day=1, hour=1, minute=1, second=1),
                'InstanceType': 'asdf',
                'KeyName': 'asdf',
                'PublicIpAddress': '1.2.3.4',
                'SubnetId': 'asdf',
                'VpcId': 'asdf',
                'Platform': 'ecks-d',
                'SecurityGroups': [{'GroupName': 'sg_name', 'GroupId': 'sg_id'}],
                'PlatformDetails': 'ecks-d',
                'State': {'Name': state, 'Code': 123},
            }
        ]} ], 
    }

    ec2_c_stubber.add_response('describe_instances', describe_instance_response('running'), describe_instances_filter(['running']))
    ec2_c_stubber.add_response('terminate_instances', {}, {'InstanceIds': ['asdf']})

    # wait_for_hosts_to_terminate()
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('running'), describe_instances_filter(['running', 'terminated', 'shutting-down']))
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('shutting-down'), describe_instances_filter(['running', 'terminated', 'shutting-down']))
    ec2_c_stubber.add_response('describe_instances', describe_instance_response('terminated'), describe_instances_filter(['running', 'terminated', 'shutting-down']))

    ec2_r_stubber.activate()
    ec2_c_stubber.activate()
    patched_aws_host.ec2 = ec2_r
    patched_aws_host.client = ec2_c
    return patched_aws_host

def test_get_all_running_apps(patched_get_session):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)
    ec2_c_stubber.add_response('describe_instances', {
        'Reservations': [ {'Instances' : [
            {'Tags': [{'Key': 'Name', 'Value': 'app1'}]},
            {'Tags': [{'Key': 'Name', 'Value': 'app2'}]},
            {'Tags': [{'Key': 'Name', 'Value': 'app3'}]}
        ]} ]
    }, {'DryRun': False,
            'Filters': [{'Name': 'tag-key', 'Values': ['quickhost']},
                        {'Name': 'instance-state-name', 'Values': ['running']}],
            'MaxResults': 101})

    ec2_c_stubber.activate()

    class MockSession(MagicMock):
        def __init__(self, *args, **kwargs):
            super().__init__()

        def client(self, *args, **kwargs):
            return ec2_c

    with patch('quickhost_aws.AWSHost.boto3.session.Session', MockSession):
        assert AWSHost.AWSHost.get_all_running_apps('some-region') == ['app1', 'app2', 'app3']


def test_get_all_running_apps_returns_none_when_no_apps(patched_get_session):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)
    ec2_c_stubber.add_response('describe_instances', {
        'Reservations': [ {'Instances' : []} ]
    }, {'DryRun': False,
            'Filters': [{'Name': 'tag-key', 'Values': ['quickhost']},
                        {'Name': 'instance-state-name', 'Values': ['running']}],
            'MaxResults': 101})

    ec2_c_stubber.activate()

    class MockSession(MagicMock):
        def __init__(self, *args, **kwargs):
            super().__init__()

        def client(self, *args, **kwargs):
            return ec2_c

    with patch('quickhost_aws.AWSHost.boto3.session.Session', MockSession):
        assert AWSHost.AWSHost.get_all_running_apps('some-region') is None


def test_get_all_running_apps_with_multi_host_app(patched_get_session):
    ec2_c = patched_get_session().client("ec2")
    ec2_c_stubber = Stubber(ec2_c)
    ec2_c_stubber.add_response('describe_instances', {
        'Reservations': [ {'Instances' : [
            {'Tags': [{'Key': 'Name', 'Value': 'app1'}]},
            {'Tags': [{'Key': 'Name', 'Value': 'app1'}]},
            {'Tags': [{'Key': 'Name', 'Value': 'app3'}]},
            {'Tags': [{'Key': 'Name', 'Value': 'app3'}]},
            {'Tags': [{'Key': 'Name', 'Value': 'app3'}]}
        ]} ]
    }, {'DryRun': False,
            'Filters': [{'Name': 'tag-key', 'Values': ['quickhost']},
                        {'Name': 'instance-state-name', 'Values': ['running']}],
            'MaxResults': 101})

    ec2_c_stubber.activate()

    class MockSession(MagicMock):
        def __init__(self, *args, **kwargs):
            super().__init__()

        def client(self, *args, **kwargs):
            return ec2_c

    with patch('quickhost_aws.AWSHost.boto3.session.Session', MockSession):
        assert AWSHost.AWSHost.get_all_running_apps('some-region') == ['app1 (2)', 'app3 (3)']