import pytest
import boto3
from botocore.stub import Stubber
from mock import patch, Mock, MagicMock

from quickhost_aws import utilities
from quickhost import constants as QH_C

# workaround for describe() caching
def quickmemo_override(*args, **kwargs):
    def _f(func):
        return func
    return _f(*args, **kwargs)

utilities.quickmemo = quickmemo_override

from .fixtures2 import *

from quickhost_aws.AWSApp import AWSApp
from quickhost_aws.utilities import QuickhostAWSException, QuickhostUnauthorized
from quickhost_aws.AWSNetworking import AWSNetworking
from quickhost_aws.AWSHost import AWSHost, HostsDescribe
from quickhost_aws.AWSSG import SG
from quickhost_aws.AWSKeypair import KP
from quickhost_aws.AWSIam import Iam


FAKE_AWS_USERNAME = 'quickhost-user'
FAKE_AWS_USER_ID = 'quickhost-user-id'
FAKE_USER_ARN = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:user/quickhost/{FAKE_AWS_USERNAME}'

FAKE_ADMIN_USER_ID = 'big-strong-admin-id'
FAKE_ADMIN_USER_ARN = f'arn:aws:iam:some-region:{FAKE_ACCOUNT}:user/bigstrongadmin'

def new_mock_session_object(stubbed_client=None, stubbed_resource=None):
    class MockSession(MagicMock):
        def __init__(self, *args, **kwargs):
            super().__init__()
            self.region_name = "some-region"

        def client(self, *args, **kwargs):
            return stubbed_client

        def resource(self, *args, **kwargs):
            return stubbed_resource
    return MockSession


@pytest.fixture
def patched_aws_app_admin_init(aws_files, patched_get_session, patched_get_caller_info):
    r = patched_get_session().resource("ec2")
    sts = patched_get_session().client("sts")
    ec2_r_stubber = Stubber(r.meta.client)
    sts_c_stubber = Stubber(sts)

    sts_c_stubber.add_response('get_caller_identity', {'ResponseMetadata': {}, 'Arn': FAKE_ADMIN_USER_ARN, 'UserId': FAKE_ADMIN_USER_ID, 'Account': FAKE_ACCOUNT}, {})
    sts_c_stubber.add_response('get_caller_identity', {'ResponseMetadata': {}, 'Arn': FAKE_ADMIN_USER_ARN, 'UserId': FAKE_ADMIN_USER_ID, 'Account': FAKE_ACCOUNT}, {})
    sts_c_stubber.add_response('get_caller_identity', {'ResponseMetadata': {}, 'Arn': FAKE_ADMIN_USER_ARN, 'UserId': FAKE_ADMIN_USER_ID, 'Account': FAKE_ACCOUNT}, {})
    sts_c_stubber.add_response('get_caller_identity', {'ResponseMetadata': {}, 'Arn': FAKE_ADMIN_USER_ARN, 'UserId': FAKE_ADMIN_USER_ID, 'Account': FAKE_ACCOUNT}, {})

    ec2_r_stubber.activate()
    sts_c_stubber.activate()

    m_session = new_mock_session_object(stubbed_client=sts)

    class MockNW(Mock):
        def __init__(self, *args, **kwargs):
            super().__init__()

    m_aws_networking = MockNW
    m_aws_networking._get_session = patched_get_session
    m_aws_networking._get_caller_info = patched_get_caller_info
    m_aws_networking.describe = lambda *args, **kwargs: { 'vpc_id': 'vpc-12345', 'subnet_id': 'subnet-12345' }
    m_aws_networking.create = lambda *args, **kwargs: {}

    with patch('quickhost_aws.AWSApp.boto3.session.Session', m_session), \
            patch('quickhost_aws.AWSApp.AWSNetworking', m_aws_networking):
        app = AWSApp
        yield app

@pytest.fixture
def patched_aws_app_init(aws_files_qh, patched_get_session, patched_get_caller_info):
    r = patched_get_session().resource("ec2")
    sts = patched_get_session().client("sts")
    ec2_r_stubber = Stubber(r.meta.client)
    sts_c_stubber = Stubber(sts)

    sts_c_stubber.add_response('get_caller_identity', {'ResponseMetadata': {}, 'Arn': FAKE_USER_ARN, 'UserId': FAKE_AWS_USER_ID, 'Account': FAKE_ACCOUNT}, {})
    sts_c_stubber.add_response('get_caller_identity', {'ResponseMetadata': {}, 'Arn': FAKE_USER_ARN, 'UserId': FAKE_AWS_USER_ID, 'Account': FAKE_ACCOUNT}, {})
    sts_c_stubber.add_response('get_caller_identity', {'ResponseMetadata': {}, 'Arn': FAKE_USER_ARN, 'UserId': FAKE_AWS_USER_ID, 'Account': FAKE_ACCOUNT}, {})
    sts_c_stubber.add_response('get_caller_identity', {'ResponseMetadata': {}, 'Arn': FAKE_USER_ARN, 'UserId': FAKE_AWS_USER_ID, 'Account': FAKE_ACCOUNT}, {})

    ec2_r_stubber.activate()
    sts_c_stubber.activate()

    m_session = new_mock_session_object(stubbed_client=sts)

    class MockNW(Mock):
        def __init__(self, *args, **kwargs):
            super().__init__()

    m_aws_networking = MockNW
    m_aws_networking._get_session = patched_get_session
    m_aws_networking._get_caller_info = patched_get_caller_info
    m_aws_networking.describe = lambda *args, **kwargs: { 'vpc_id': 'vpc-12345', 'subnet_id': 'subnet-12345' }

    with patch('quickhost_aws.AWSApp.boto3.session.Session', m_session), \
            patch('quickhost_aws.AWSApp.AWSNetworking', m_aws_networking):
        app = AWSApp
        yield app


@pytest.fixture
def stub_aws_app_load_default_config(patched_aws_app_init):
        return patched_aws_app_init


def test_aws_app_load_default_config(stub_aws_app_load_default_config):
    app = stub_aws_app_load_default_config(FAKE_APP_NAME)
    assert app.vpc_id is None
    assert app.subnet_id is None
    app.load_default_config('asd', 'f')
    assert app.vpc_id is not None
    assert app.subnet_id is not None


@pytest.fixture
def patched_aws_app_load_default_config_qhaws_expection(aws_files_qh, patched_get_session, patched_get_caller_info):
    r = patched_get_session().resource("ec2")
    sts = patched_get_session().client("sts")
    ec2_r_stubber = Stubber(r.meta.client)
    sts_c_stubber = Stubber(sts)

    sts_c_stubber.add_response('get_caller_identity', {'ResponseMetadata': {}, 'Arn': FAKE_USER_ARN}, {})

    ec2_r_stubber.activate()
    sts_c_stubber.activate()

    m_session = new_mock_session_object(stubbed_client=sts)

    class MockNW(Mock):
        def __init__(self, *args, **kwargs):
            super().__init__()
            raise QuickhostAWSException("test")

    m_aws_networking = MockNW
    m_aws_networking._get_session = patched_get_session
    m_aws_networking._get_caller_info = patched_get_caller_info
    m_aws_networking.describe = lambda *args, **kwargs: { 'vpc_id': 'vpc-12345', 'subnet_id': 'subnet-12345' }

    with patch('quickhost_aws.AWSApp.boto3.session.Session', m_session), \
            patch('quickhost_aws.AWSApp.AWSNetworking', m_aws_networking):
        app = AWSApp
        yield app


@pytest.fixture
def stub_aws_app_load_default_config_qhaws_exception(patched_aws_app_load_default_config_qhaws_expection):
        return patched_aws_app_load_default_config_qhaws_expection

def test_aws_app_load_default_config_qhaws_exception(stub_aws_app_load_default_config_qhaws_exception):
    app = stub_aws_app_load_default_config_qhaws_exception(FAKE_APP_NAME)
    assert app.vpc_id is None
    assert app.subnet_id is None
    with pytest.raises(SystemExit):
        app.load_default_config('asd', 'f')


@pytest.fixture
def patched_aws_app_plugin_destroy(patched_aws_app_init, patched_get_session, patched_get_caller_info):
    m_sg = Mock()
    m_sg().destroy = lambda *args, **kwargs: True

    m_kp = Mock()
    m_kp().destroy = lambda *args, **kwargs: True

    m_host = Mock()
    m_host().get_all_running_apps =  lambda *args, **kwargs: ['app-1', 'app-2']
    m_host().destroy = lambda *args, **kwargs: True
    m_host().describe = lambda *args, **kwargs: [HostsDescribe(
        app_name=FAKE_APP_NAME,
        ami='some-ami-id',
        private_ip='9.8.7.6',
        uptime_hrs=123,
        instance_id='some-instance-id',
        instance_type='some-micro',
        public_ip='1.2.3.4',
        security_group='sg-12345',
        state='running',
        subnet_id='subnet-12345',
        vpc_id='vpc-12345',
        platform='Windows',
    )]

    m_iam = Mock()
    m_iam().destroy = lambda *args, **kwargs: True
    m_iam().describe = lambda *args, **kwargs: { 'vpc_id': 'vpc-12345', 'subnet_id': 'subnet-12345' }

    with patch('quickhost_aws.AWSApp.input', lambda *args, **kwargs: 'yes'), \
            patch('quickhost_aws.AWSApp.AWSHost', m_host), \
            patch('quickhost_aws.AWSApp.AWSResourceBase._get_session', patched_get_session ), \
            patch('quickhost_aws.AWSApp.SG', m_sg), \
            patch('quickhost_aws.AWSApp.Iam', m_iam), \
            patch('quickhost_aws.AWSApp.KP', m_kp) \
                :
        app = patched_aws_app_init
        yield (app, m_host, m_sg, None, m_iam, m_kp)


def test_aws_app_plugin_destroy(patched_aws_app_plugin_destroy):
    app = patched_aws_app_plugin_destroy[0](FAKE_APP_NAME)
    cli_resopnse = app.plugin_destroy({
        'profile': 'some-profile'
    })
    assert cli_resopnse.rc == 0


@pytest.fixture
def patched_aws_app_destroy_all(patched_aws_app_init, patched_get_session):
    """i have no idea what im doing"""
    # m_host_class = Mock
    # m_host_class.get_all_running_apps =  Mock(return_value=['app-1', 'app-2'], spec=list, )  # classmethod

    m_sg = Mock(spec=SG)
    # m_sg_destroy = Mock(return_value=True)
    # m_sg.attach_mock(m_sg_destroy, 'destroy')
    m_sg.destroy = Mock(return_value=True)

    m_kp = Mock(spec=KP)
    m_kp.attach_mock(Mock(return_value=True), 'destroy')
    # m_kp.destroy = lambda *args, **kwargs: True

    m_host = Mock(spec=AWSHost)
    m_host().get_all_running_apps =  lambda *args, **kwargs: ['app-1', 'app-2']
    m_host().destroy = lambda *args, **kwargs: True
    m_host().describe = lambda *args, **kwargs: [HostsDescribe(
        app_name=FAKE_APP_NAME,
        ami='some-ami-id',
        private_ip='9.8.7.6',
        uptime_hrs=123,
        instance_id='some-instance-id',
        instance_type='some-micro',
        public_ip='1.2.3.4',
        security_group='sg-12345',
        state='running',
        subnet_id='subnet-12345',
        vpc_id='vpc-12345',
        platform='Windows',
    )]

    m_iam = Mock(spec=Iam)
    m_iam.destroy = Mock()
    m_iam.describe = Mock()

    with patch('quickhost_aws.AWSApp.input', lambda *args, **kwargs: 'yes'), \
            patch('quickhost_aws.AWSApp.AWSHost', m_host), \
            patch('quickhost_aws.AWSApp.AWSResourceBase._get_session', patched_get_session ), \
            patch('quickhost_aws.AWSApp.SG', m_sg), \
            patch('quickhost_aws.AWSApp.Iam', m_iam), \
            patch('quickhost_aws.AWSApp.KP', m_kp) \
                :
        app = patched_aws_app_init
        yield (app, None,  m_host, m_sg, None, m_iam, m_kp)


def test_aws_app_destroy_all(patched_aws_app_destroy_all):
    app = patched_aws_app_destroy_all[0]
    m_host_inst: Mock = patched_aws_app_destroy_all[1]
    m_host: Mock = patched_aws_app_destroy_all[2]
    m_sg: Mock = patched_aws_app_destroy_all[3]
    m_network: Mock = patched_aws_app_destroy_all[4]
    m_iam: Mock = patched_aws_app_destroy_all[5]
    m_kp: Mock = patched_aws_app_destroy_all[6]
    cli_resopnse = app.destroy_all({
        'profile': 'some-profile'
    })

    assert cli_resopnse.rc == 0
    assert cli_resopnse.stdout == "Destroyed 2 apps"
    assert cli_resopnse.stderr == None


@pytest.fixture
def patched_aws_app_plugin_init(patched_aws_app_admin_init, patched_get_session):
    m_sg = Mock(spec=SG)
    m_sg.destroy = Mock(return_value=True)

    m_kp = Mock(spec=KP)
    m_kp.attach_mock(Mock(return_value=True), 'destroy')

    m_host = Mock
    m_host.get_all_running_apps =  Mock(return_value=['app-1', 'app-2'], spec=list, )  # classmethod
    m_host().destroy = Mock(return_value=True)

    m_network = Mock(spec=AWSNetworking)
    m_network().create = Mock(return_value={'asdf':'asdf'})

    m_iam = Mock(spec=Iam)
    m_iam().create = Mock(return_value={'asdf':'asdf'})
    m_iam.describe = Mock()

    with patch('quickhost_aws.AWSApp.input', lambda *args, **kwargs: 'yes'), \
            patch('quickhost_aws.AWSApp.AWSHost', m_host), \
            patch('quickhost_aws.AWSApp.AWSHost.get_all_running_apps', lambda *args, **kwargs: ['app-1', 'app-2']), \
            patch('quickhost_aws.AWSApp.AWSResourceBase._get_session', patched_get_session ), \
            patch('quickhost_aws.AWSApp.SG', m_sg), \
            patch('quickhost_aws.AWSApp.Iam', m_iam), \
            patch('quickhost_aws.AWSApp.KP', m_kp) \
                :
        app = patched_aws_app_admin_init
        yield (app, None,  m_host, m_sg, None, m_iam, m_kp)


def test_aws_app_plugin_init(patched_aws_app_plugin_init):
    app = patched_aws_app_plugin_init[0]("init")
    m_host_inst: Mock = patched_aws_app_plugin_init[1]
    m_host: Mock = patched_aws_app_plugin_init[2]
    m_sg: Mock = patched_aws_app_plugin_init[3]
    m_network: Mock = patched_aws_app_plugin_init[4]
    m_iam: Mock = patched_aws_app_plugin_init[5]
    m_kp: Mock = patched_aws_app_plugin_init[6]
    cli_resopnse = app.plugin_init(init_args={
        'region': 'some-region',
        'profile': 'some-profile'
    })

    print(cli_resopnse)
    assert cli_resopnse.rc == 0
    assert cli_resopnse.stdout == "Done"
    assert cli_resopnse.stderr == None



@pytest.fixture
def patched_aws_app_plugin_init_fails_when_unautherized(patched_aws_app_init, patched_get_session):
    m_sg = Mock(spec=SG)
    m_sg.destroy = Mock(return_value=True)

    m_kp = Mock(spec=KP)
    m_kp.attach_mock(Mock(return_value=True), 'destroy')

    m_host = Mock
    m_host.get_all_running_apps =  Mock(return_value=['app-1', 'app-2'], spec=list, )  # classmethod
    m_host().destroy = Mock(return_value=True)

    m_network = Mock(spec=AWSNetworking)
    m_network().create = Mock(return_value={'asdf':'asdf'})

    m_iam = Mock(spec=Iam)
    m_iam().create = Mock(side_effect=QuickhostUnauthorized('some-user', 'asdf'))

    with patch('quickhost_aws.AWSApp.input', lambda *args, **kwargs: 'yes'), \
            patch('quickhost_aws.AWSApp.AWSHost', m_host), \
            patch('quickhost_aws.AWSApp.AWSHost.get_all_running_apps', lambda *args, **kwargs: ['app-1', 'app-2']), \
            patch('quickhost_aws.AWSApp.AWSResourceBase._get_session', patched_get_session ), \
            patch('quickhost_aws.AWSApp.SG', m_sg), \
            patch('quickhost_aws.AWSApp.Iam', m_iam), \
            patch('quickhost_aws.AWSApp.KP', m_kp) \
                :
        app = patched_aws_app_init
        yield (app, None,  m_host, m_sg, None, m_iam, m_kp)


def test_aws_app_plugin_init_fails_when_unautherized(patched_aws_app_plugin_init_fails_when_unautherized):
    app = patched_aws_app_plugin_init_fails_when_unautherized[0]("init")
    cli_resopnse = app.plugin_init(init_args={
        'region': 'some-region',
        'profile': 'some-profile'
    })

    assert cli_resopnse.rc > 0
    assert cli_resopnse.stdout is None
    assert not cli_resopnse.stderr is None


@pytest.fixture
def patched_aws_app_describe(patched_aws_app_init, patched_get_session):
    m_sg = Mock(spec=SG)
    m_sg().describe = lambda *args, **kwargs: {'asdf':'sg-asdf'}

    m_kp = Mock()
    m_kp().windows_get_password = lambda *args, **kwargs: 'xxxxxxxxxxxxxxx'
    m_kp().describe = lambda *args, **kwargs: {
        'key_id': 'some-key-id',
        'key_fingerprint': 'aa:bb:cc:dd:ee',
        'ssh_key_filepath': '/some/key/file.pem'
    }

    m_host = Mock()
    m_host().describe = Mock(return_value=[HostsDescribe(
        app_name=FAKE_APP_NAME,
        ami='some-ami-id',
        private_ip='9.8.7.6',
        uptime_hrs=123,
        instance_id='some-instance-id',
        instance_type='some-micro',
        public_ip='1.2.3.4',
        security_group='sg-12345',
        state='running',
        subnet_id='subnet-12345',
        vpc_id='vpc-12345',
        platform='Windows',
    )])

    m_network = Mock(spec=AWSNetworking)
    m_network().describe = lambda *args, **kwargs: {
        'vpc_id': 'vpc-12345',
        'subnet_id': 'subnet-12345',
        'rt_id': 'rt-12345',
        'igw_id': 'igw-12345'
    }

    m_iam = Mock(spec=Iam)
    m_iam().describe = lambda *args, **kwargs: {
        'credentials': {
            'default-region': 'some-region',
            'credentials-exist': True,
        },
        'iam-user': {
            'name': 'quickhost-user',
            'arn': 'arn:aws:iam:some-region:012345678901:user/quickhost/quickhost-user',
            'access-keys': [],
        },
        'iam-group': {
            'arn': 'arn:aws:iam:some-region:012345678901:group/quickhost/quickhost-users',
            'attached-policies': [],
        },
        'iam-policies': {
            'create': None,
            'describe': None,
            'update': None,
            'destroy': None,
        },
    }

    with patch('quickhost_aws.AWSApp.AWSHost', m_host), \
            patch('quickhost_aws.AWSApp.AWSResourceBase._get_session', patched_get_session ), \
            patch('quickhost_aws.AWSApp.SG', m_sg), \
            patch('quickhost_aws.AWSApp.Iam', m_iam), \
            patch('quickhost_aws.AWSApp.KP', m_kp) \
                :
        app = patched_aws_app_init
        yield (app, None,  m_host, m_sg, None, m_iam, m_kp)


def test_aws_app_describe(patched_aws_app_describe):
    app: AWSApp = patched_aws_app_describe[0](app_name=FAKE_APP_NAME)
    cli_resopnse = app.describe(args={
        'region': 'some-region',
        'show_password': True,
        'verbosity': 0
    })

    assert cli_resopnse.rc == 0
    assert cli_resopnse.stdout == 'Done' 
    assert cli_resopnse.stderr is None


@pytest.fixture
def patched_aws_app_describe_no_hosts(patched_aws_app_init, patched_get_session):
    m_sg = Mock(spec=SG)
    m_sg().describe = lambda *args, **kwargs: None

    m_kp = Mock()
    m_kp().describe = lambda *args, **kwargs: None

    m_host = Mock()
    m_host().describe = Mock(return_value=[])

    m_network = Mock(spec=AWSNetworking)
    m_network().describe = lambda *args, **kwargs: {
        'vpc_id': 'vpc-12345',
        'subnet_id': 'subnet-12345',
        'rt_id': 'rt-12345',
        'igw_id': 'igw-12345'
    }

    m_iam = Mock(spec=Iam)
    m_iam().describe = lambda *args, **kwargs: {
        'credentials': {
            'default-region': 'some-region',
            'credentials-exist': True,
        },
        'iam-user': {
            'name': 'quickhost-user',
            'arn': 'arn:aws:iam:some-region:012345678901:user/quickhost/quickhost-user',
            'access-keys': [],
        },
        'iam-group': {
            'arn': 'arn:aws:iam:some-region:012345678901:group/quickhost/quickhost-users',
            'attached-policies': [],
        },
        'iam-policies': {
            'create': None,
            'describe': None,
            'update': None,
            'destroy': None,
        },
    }

    with patch('quickhost_aws.AWSApp.AWSHost', m_host), \
            patch('quickhost_aws.AWSApp.AWSResourceBase._get_session', patched_get_session ), \
            patch('quickhost_aws.AWSApp.SG', m_sg), \
            patch('quickhost_aws.AWSApp.Iam', m_iam), \
            patch('quickhost_aws.AWSApp.KP', m_kp) \
                :
        app = patched_aws_app_init
        yield (app, None,  m_host, m_sg, None, m_iam, m_kp)


def test_aws_app_describe_no_hosts(patched_aws_app_describe_no_hosts):
    app: AWSApp = patched_aws_app_describe_no_hosts[0](app_name=FAKE_APP_NAME)
    cli_resopnse = app.describe(args={
        'region': 'some-region',
        'show_password': True
    })

    assert cli_resopnse.rc == 1
    assert cli_resopnse.stdout is None
    assert cli_resopnse.stderr is not None


@pytest.fixture
def patched_aws_app_create(patched_aws_app_init, patched_get_session):
    m_host = Mock(spec=AWSHost)
    m_host().describe = lambda *args, **kwargs: []
    m_host().create =  lambda *args, **kwargs: {
        'region': 'reg',
        'num_hosts': 1,
        'instance_type': '',
        'sgid': '',
        'subnet_id': '',
        'userdata': None,
        'key_name': '',
        'os': 'al2023',
        'image_id': 'ami-1234567890EXAMPLE',
        'disk_size': 30
    }

    m_sg = Mock()
    m_sg().create = lambda *args, **kwargs: True

    m_kp = Mock()
    m_kp().create = lambda *args, **kwargs: {
        'key_name': 'asdf'
    }

    m_network = Mock()
    m_network().describe = lambda *args, **kwargs: { 'vpc_id': 'vpc-12345', 'subnet_id': 'subnet-12345' }

    m_iam = Mock()
    m_iam().describe = lambda *args, **kwargs: { 'vpc_id': 'vpc-12345', 'subnet_id': 'subnet-12345' }

    with patch('quickhost_aws.AWSApp.input', lambda *args, **kwargs: 'yes'), \
            patch('quickhost_aws.AWSApp.AWSHost', m_host), \
            patch('quickhost_aws.AWSApp.AWSResourceBase._get_session', patched_get_session ), \
            patch('quickhost_aws.AWSApp.SG', m_sg), \
            patch('quickhost_aws.AWSApp.AWSNetworking', m_network), \
            patch('quickhost_aws.AWSApp.Iam', m_iam), \
            patch('quickhost_aws.AWSApp.KP', m_kp) \
                :
        app = patched_aws_app_init
        yield (app, m_host, m_sg, m_network, m_iam, m_kp)


def test_aws_app_create(patched_aws_app_create):
    app = patched_aws_app_create[0](FAKE_APP_NAME)
    cli_resopnse = app.create({
        'ip': None,
        'os': 'al2023',
        'userdata': None,
        'region': 'some-region2',
        'ssh_key_filepath': None,

        'host_count': 1,
        'instance_type': 'some-instance-type',
    })
    assert cli_resopnse.rc == 0



@pytest.fixture
def patched_aws_app_new_ssh_key_filepath(patched_get_session, patched_get_caller_info):
    r = patched_get_session().resource("ec2")
    sts = patched_get_session().client("sts")
    ec2_r_stubber = Stubber(r.meta.client)
    sts_c_stubber = Stubber(sts)

    sts_c_stubber.add_response('get_caller_identity', {'ResponseMetadata': {}, 'Arn': FAKE_USER_ARN, 'UserId': FAKE_AWS_USER_ID, 'Account': FAKE_ACCOUNT}, {})
    sts_c_stubber.add_response('get_caller_identity', {'ResponseMetadata': {}, 'Arn': FAKE_USER_ARN, 'UserId': FAKE_AWS_USER_ID, 'Account': FAKE_ACCOUNT}, {})
    sts_c_stubber.add_response('get_caller_identity', {'ResponseMetadata': {}, 'Arn': FAKE_USER_ARN, 'UserId': FAKE_AWS_USER_ID, 'Account': FAKE_ACCOUNT}, {})
    sts_c_stubber.add_response('get_caller_identity', {'ResponseMetadata': {}, 'Arn': FAKE_USER_ARN, 'UserId': FAKE_AWS_USER_ID, 'Account': FAKE_ACCOUNT}, {})

    ec2_r_stubber.activate()
    sts_c_stubber.activate()

    m_session = new_mock_session_object(stubbed_client=sts)

    class MockNW(Mock):
        def __init__(self, *args, **kwargs):
            super().__init__()

    m_aws_networking = MockNW
    m_aws_networking._get_session = patched_get_session
    m_aws_networking._get_caller_info = patched_get_caller_info
    m_aws_networking.describe = lambda *args, **kwargs: { 'vpc_id': 'vpc-12345', 'subnet_id': 'subnet-12345' }

    with patch('quickhost_aws.AWSApp.boto3.session.Session', m_session), \
            patch('quickhost_aws.AWSApp.AWSNetworking', m_aws_networking):
        app = AWSApp
        yield app

def test_aws_app_new_ssh_key_filepath(patched_aws_app_new_ssh_key_filepath, aws_files_qh_and_ssh):
    app = patched_aws_app_new_ssh_key_filepath(FAKE_APP_NAME)
    assert app.new_ssh_key_filepath(None) == str(Path(aws_files_qh_and_ssh[1].home_dir) / '.ssh' / f"quickhost-{FAKE_APP_NAME}.pem")


def test_aws_app_new_ssh_key_filepath_path_exists(patched_aws_app_new_ssh_key_filepath, aws_files_qh_and_ssh):
    app = patched_aws_app_new_ssh_key_filepath(FAKE_APP_NAME)
    tgt_dir = str(Path(aws_files_qh_and_ssh[1].home_dir) / '.ssh')
    assert app.new_ssh_key_filepath(tgt_dir) == str(Path(tgt_dir) /  f"quickhost-{FAKE_APP_NAME}.pem")

def test_aws_app_new_ssh_key_filepath_path_dir_DNE_raises(patched_aws_app_new_ssh_key_filepath, aws_files_qh_and_ssh):
    app = patched_aws_app_new_ssh_key_filepath(FAKE_APP_NAME)
    tgt_dir = Path('/somewhere') / 'dne'
    with pytest.raises(SystemExit):
        app.new_ssh_key_filepath(tgt_dir)