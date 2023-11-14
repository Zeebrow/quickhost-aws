import pytest
import boto3
from botocore.stub import Stubber
from mock import patch, Mock

from quickhost_aws import utilities
from quickhost import constants as QH_C

# workaround for describe() caching
def quickmemo_override(*args, **kwargs):
    def _f(func):
        return func
    return _f(*args, **kwargs)

utilities.quickmemo = quickmemo_override

from quickhost_aws.AWSNetworking import AWSNetworking
# from .fixtures2 import patched_get_session, patched_get_caller_info
from .fixtures2 import *


@pytest.fixture
def patched_aws_networking(patched_get_session):
    with patch('quickhost_aws.AWSNetworking.AWSResourceBase._get_session', patched_get_session):
        awsn = AWSNetworking(profile='asdf', region='reg')
        return awsn


@pytest.fixture
def stub_init_doesnt_create_qh_resources_when_they_exist(patched_get_session, patched_aws_networking):
    r = patched_get_session().resource("ec2")
    s = patched_get_session().client("ec2")
    ec2_r_stubber = Stubber(r.meta.client)
    ec2_c_stubber = Stubber(s)

    # aws resource ids as they would be returned from api calls
    aws_tags = [{'Key':'Name', 'Value':'quickhost'}]
    expected_filters = [{'Name': 'tag:Name', 'Values': ['quickhost']}]
    aws_vpc_id = "vpc-12345"
    aws_subnet_id = "subnet-12345"
    aws_igw_id = "igw-12345"
    aws_rt_id = "rt-12345"
    aws_igws = [{'InternetGatewayId': aws_igw_id, "Attachments": [{'VpcId': aws_vpc_id, 'State': 'attached'}], 'Tags': aws_tags}]

    aws_rts = [{'RouteTableId': aws_rt_id, 'Associations':[{'SubnetId': aws_subnet_id, 'RouteTableId': aws_rt_id, "AssociationState": {"State": "associated"}}]}]

    # describe() to get "state"
    ec2_c_stubber.add_response('describe_vpcs',              {"Vpcs": [{'VpcId': aws_vpc_id, 'Tags': aws_tags}]}, {'Filters': expected_filters})
    ec2_c_stubber.add_response('describe_subnets',           {"Subnets": [{'SubnetId': aws_subnet_id, 'Tags': aws_tags}]}, {'Filters': expected_filters})
    ec2_c_stubber.add_response('describe_internet_gateways', {"InternetGateways": aws_igws}, {'Filters': expected_filters})
    ec2_r_stubber.add_response('describe_internet_gateways', {"InternetGateways": aws_igws}, {'InternetGatewayIds': [aws_igw_id]})
    ec2_c_stubber.add_response('describe_route_tables',      {"RouteTables": aws_rts}, {'Filters': expected_filters})

    # continuing with create()
    ec2_r_stubber.add_response('describe_internet_gateways', {"InternetGateways": aws_igws}, {'InternetGatewayIds': [aws_igw_id]})
    ec2_r_stubber.add_response('describe_route_tables',      {"RouteTables": aws_rts}, {'RouteTableIds': [aws_rt_id]})

    ec2_r_stubber.activate()
    ec2_c_stubber.activate()
    patched_aws_networking.ec2 = r
    patched_aws_networking.client = s
    return patched_aws_networking


def test_init_doesnt_create_qh_resources_when_they_exist(stub_init_doesnt_create_qh_resources_when_they_exist: AWSNetworking):
    assert {
        'vpc_id': "vpc-12345",
        'subnet_id': "subnet-12345",
        'igw_id': "igw-12345",
        'rt_id': "rt-12345",
    } == stub_init_doesnt_create_qh_resources_when_they_exist.create('asdf')


@pytest.fixture
def stub_init_creates_resources_when_none_exist(patched_get_session, patched_aws_networking):
    r = patched_get_session().resource("ec2")
    s = patched_get_session().client("ec2")
    ec2_r_stubber = Stubber(r.meta.client)
    ec2_c_stubber = Stubber(s)

    def _wrapper(params_vpc_cidr_block=None, params_subnet_cidr_block=None):

        # user input params
        # params_vpc_cidr_block = '1.2.3.4/5'
        # params_subnet_cidr_block='2.3.4.5/6'
        if not params_vpc_cidr_block:
            params_vpc_cidr_block = QH_C.APP_CONST.DEFAULT_VPC_CIDR
        if not params_subnet_cidr_block:
            params_subnet_cidr_block = QH_C.APP_CONST.DEFAULT_SUBNET_CIDR

        # AWS resource ids
        # These would be returned from boto3's api calls. In this case
        # after describe(), which would return nothing for nonexistent resources
        aws_tags = [{'Key':'Name', 'Value':'quickhost'}]
        expected_filters = [{'Name': 'tag:Name', 'Values': ['quickhost']}]
        aws_vpc_id = "vpc-12345"
        aws_subnet_id = "subnet-12345"
        aws_igw_id = "igw-12345"
        aws_rt_id = "rt-12345"
        aws_igws = [{'InternetGatewayId': aws_igw_id, "Attachments": [{'VpcId': aws_vpc_id, 'State': 'attached'}], 'Tags': aws_tags}]

        aws_rts = [{'RouteTableId': aws_rt_id, 'Associations':[{'SubnetId': aws_subnet_id, 'RouteTableId': aws_rt_id, "AssociationState": {"State": "associated"}}]}]

        def _wait_until_vpc_available_response():
            return {
                "ResponseMetadata": {"HTTPStatusCode": 200},
                'Vpcs':[{
                    'CidrBlock': params_vpc_cidr_block, 'DhcpOptionsId': 'dopt-0788d9b60da860289', 'State': 'available', 'VpcId': aws_vpc_id, 'OwnerId': '123456789012', 'InstanceTenancy': 'default', 
                    'CidrBlockAssociationSet': [{
                            'AssociationId': 'vpc-cidr-assoc-abcdef1',
                            'CidrBlock': params_vpc_cidr_block,
                            'CidrBlockState': {'State': 'associated'}
                    }],
                    'IsDefault': False,
                    'Tags': aws_tags,
                }]
            }


        # describe() to get "state"
        ec2_c_stubber.add_response('describe_vpcs',              {"Vpcs": []}, {'Filters': expected_filters})
        ec2_c_stubber.add_response('describe_subnets',           {"Subnets": []}, {'Filters': expected_filters})
        ec2_c_stubber.add_response('describe_internet_gateways', {"InternetGateways": []}, {'Filters': expected_filters})
        ec2_c_stubber.add_response('describe_route_tables',      {"RouteTables": []}, {'Filters': expected_filters})

        # continuing with create()
        ec2_r_stubber.add_response('create_vpc', {"Vpc": {"VpcId": aws_vpc_id}}, {'CidrBlock': params_vpc_cidr_block, 'DryRun': False, 'TagSpecifications': [{'ResourceType': 'vpc', 'Tags': aws_tags}]})
        ec2_r_stubber.add_response(
            method='describe_vpcs', 
            service_response=_wait_until_vpc_available_response(),
            expected_params={ 'VpcIds': [aws_vpc_id] }
        )

        ec2_r_stubber.add_response('create_tags', {}, {'Resources': [aws_vpc_id], 'Tags': aws_tags})
        ec2_r_stubber.add_response('describe_vpcs', {"Vpcs": [{"VpcId": aws_vpc_id}]}, {'VpcIds': [aws_vpc_id]})
        ec2_c_stubber.add_response(
            method='create_internet_gateway',
            service_response={'InternetGateway':{'InternetGatewayId': aws_igw_id}},
            expected_params={'DryRun': False, 'TagSpecifications': [{'ResourceType': 'internet-gateway','Tags': aws_tags}]},
        )
        ec2_r_stubber.add_response(
            method='attach_internet_gateway',
            service_response={'ResponseMetadata': {}},
            expected_params={'DryRun': False, 'InternetGatewayId': aws_igw_id, 'VpcId': aws_vpc_id},
        )
        ec2_r_stubber.add_response(
            method='describe_internet_gateways',
            service_response={'InternetGateways':[{'InternetGatewayId': aws_igw_id, 'Attachments':[{'VpcId': aws_vpc_id, 'State': 'attached'}]}]},
            expected_params={'InternetGatewayIds': [aws_igw_id]},
        )
        ec2_r_stubber.add_response(
            method='create_subnet', 
            service_response={'Subnet':{'CidrBlock': params_subnet_cidr_block, 'SubnetId': aws_subnet_id}},
            expected_params={'CidrBlock': params_subnet_cidr_block, 'VpcId': aws_vpc_id, 'TagSpecifications': [{'ResourceType': 'subnet', 'Tags': aws_tags}], 'DryRun': False}
        )
        ec2_r_stubber.add_response('create_tags', {}, {'Resources': [aws_subnet_id], 'Tags': aws_tags})
        ec2_r_stubber.add_response(
            method='describe_subnets', 
            service_response={'Subnets':[{'CidrBlock':params_vpc_cidr_block, 'SubnetId': aws_subnet_id}]},
            expected_params={'SubnetIds': [aws_subnet_id]},
        )
        ec2_r_stubber.add_response(
            method='create_route_table', 
            service_response={'RouteTable':{'RouteTableId': aws_rt_id}},
            expected_params={'VpcId': aws_vpc_id, 'TagSpecifications': [{'ResourceType': 'route-table', 'Tags': aws_tags}], 'DryRun': False}
        )
        ec2_r_stubber.add_response(
            method='create_route', 
            service_response={'Return': True},
            expected_params={'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': aws_igw_id, 'RouteTableId': aws_rt_id, 'DryRun': False}
        )
        ec2_r_stubber.add_response(
            method='associate_route_table', 
            service_response={},
            expected_params={'RouteTableId': aws_rt_id, 'SubnetId': aws_subnet_id, 'DryRun': False}
        )
        ec2_r_stubber.add_response(
            method='describe_route_tables', 
            service_response={'RouteTables':[{'Associations':[{'SubnetId': aws_subnet_id, "AssociationState": {"State": "associated"}}]}]},
            expected_params={'RouteTableIds': [aws_rt_id]}
        )

        ec2_r_stubber.activate()
        ec2_c_stubber.activate()
        patched_aws_networking.ec2 = r
        patched_aws_networking.client = s
        return patched_aws_networking
    return _wrapper


def test_init_creates_resources_when_none_exist(stub_init_creates_resources_when_none_exist: AWSNetworking):
    assert {
        'vpc_id': "vpc-12345",
        'subnet_id': "subnet-12345",
        'igw_id': "igw-12345",
        'rt_id': "rt-12345",
    } == stub_init_creates_resources_when_none_exist(
        params_vpc_cidr_block='1.2.3.4/5',
        params_subnet_cidr_block='2.3.4.5/6',
    ).create(
        vpc_cidr_block='1.2.3.4/5',
        subnet_cidr_block='2.3.4.5/6',
    )

def test_init_creates_default_valued_resources_when_none_exist(stub_init_creates_resources_when_none_exist: AWSNetworking):
    assert {
        'vpc_id': "vpc-12345",
        'subnet_id': "subnet-12345",
        'igw_id': "igw-12345",
        'rt_id': "rt-12345",
    } == stub_init_creates_resources_when_none_exist().create()


@pytest.fixture
def stub_init_detects_and_fixes_detatched_igw_rt(patched_get_session, patched_aws_networking):
    r = patched_get_session().resource("ec2")
    s = patched_get_session().client("ec2")
    ec2_r_stubber = Stubber(r.meta.client)
    ec2_c_stubber = Stubber(s)

    # aws resource ids as they would be returned from api calls
    aws_tags = [{'Key':'Name', 'Value':'quickhost'}]
    expected_filters = [{'Name': 'tag:Name', 'Values': ['quickhost']}]
    aws_vpc_id = "vpc-12345"
    aws_subnet_id = "subnet-12345"
    aws_igw_id = "igw-12345"
    aws_rt_id = "rt-12345"
    aws_igw_no_attachments = [{'InternetGatewayId': aws_igw_id, "Attachments": [], 'Tags': aws_tags}]
    aws_igw_with_attachments = [{'InternetGatewayId': aws_igw_id, "Attachments": [{'VpcId': aws_vpc_id, 'State': 'attached'}], 'Tags': aws_tags}]

    aws_rts_no_association = [{'RouteTableId': aws_rt_id, 'Associations':[]}]
    aws_rts_with_association = [{ 'RouteTableId': aws_rt_id, 'Associations':[{'SubnetId': aws_subnet_id, 'RouteTableId': aws_rt_id, "AssociationState": {"State": "associated"}}]}]

    # describe() to get "state"
    ec2_c_stubber.add_response('describe_vpcs',              {"Vpcs": [{'VpcId': aws_vpc_id, 'Tags': aws_tags}]}, {'Filters': expected_filters})
    ec2_c_stubber.add_response('describe_subnets',           {"Subnets": [{'SubnetId': aws_subnet_id, 'Tags': aws_tags}]}, {'Filters': expected_filters})
    ec2_c_stubber.add_response('describe_internet_gateways', {"InternetGateways": aws_igw_no_attachments}, {'Filters': expected_filters})
    ec2_r_stubber.add_response('describe_internet_gateways', {"InternetGateways": aws_igw_no_attachments}, {'InternetGatewayIds': [aws_igw_id]})
    ec2_c_stubber.add_response('describe_route_tables',      {"RouteTables": aws_rts_no_association}, {'Filters': expected_filters})

    # continuing with create()
    ec2_r_stubber.add_response('describe_internet_gateways', {"InternetGateways": aws_igw_no_attachments}, {'InternetGatewayIds': [aws_igw_id]})
    ec2_r_stubber.add_response('attach_internet_gateway',    {}, {'DryRun': False, 'InternetGatewayId': aws_igw_id, 'VpcId': aws_vpc_id})  # primary behavior sought
    ec2_r_stubber.add_response('describe_internet_gateways', {"InternetGateways": aws_igw_with_attachments}, {'InternetGatewayIds': [aws_igw_id]})
    ec2_r_stubber.add_response('describe_route_tables',      {"RouteTables": aws_rts_no_association}, {'RouteTableIds': [aws_rt_id]})
    ec2_r_stubber.add_response('associate_route_table',      {}, {'RouteTableId': aws_rt_id, 'SubnetId': aws_subnet_id, 'DryRun': False})  # primary behavior sought
    ec2_r_stubber.add_response('describe_route_tables',      {"RouteTables": aws_rts_with_association}, {'RouteTableIds': [aws_rt_id]})

    ec2_r_stubber.activate()
    ec2_c_stubber.activate()
    patched_aws_networking.ec2 = r
    patched_aws_networking.client = s
    return patched_aws_networking


def test_init_detects_and_fixes_detatched_igw(stub_init_detects_and_fixes_detatched_igw_rt: AWSNetworking):
    assert {
        'vpc_id': "vpc-12345",
        'subnet_id': "subnet-12345",
        'igw_id': "igw-12345",
        'rt_id': "rt-12345",
    } == stub_init_detects_and_fixes_detatched_igw_rt.create() 

# @@@ moar


################################################################
# destroy
################################################################

@pytest.fixture
def stub_init_destroys_resources(patched_get_session, patched_aws_networking):
    r = patched_get_session().resource("ec2")
    s = patched_get_session().client("ec2")
    ec2_r_stubber = Stubber(r.meta.client)
    ec2_c_stubber = Stubber(s)

    # aws resource ids as they would be returned from api calls
    aws_tags = [{'Key':'Name', 'Value':'quickhost'}]
    expected_filters = [{'Name': 'tag:Name', 'Values': ['quickhost']}]
    aws_vpc_id = "vpc-12345"
    aws_subnet_id = "subnet-12345"
    aws_igw_id = "igw-12345"
    aws_rt_id = "rt-12345"

    # "intermediate" aws values
    _aws_rt_assoc_id = "assoc-id"
    aws_igws = [{'InternetGatewayId': aws_igw_id, "Attachments": [{'VpcId': aws_vpc_id, 'State': 'attached'}], 'Tags': aws_tags}]

    aws_rts = [{'RouteTableId': aws_rt_id, 'Associations':[{'RouteTableAssociationId': _aws_rt_assoc_id, 'SubnetId': aws_subnet_id, 'RouteTableId': aws_rt_id, "AssociationState": {"State": "associated"}}]}]

    # describe() to get "state"
    ec2_c_stubber.add_response('describe_vpcs',              {"Vpcs": [{'VpcId': aws_vpc_id, 'Tags': aws_tags}]}, {'Filters': expected_filters})
    ec2_c_stubber.add_response('describe_subnets',           {"Subnets": [{'SubnetId': aws_subnet_id, 'Tags': aws_tags}]}, {'Filters': expected_filters})
    ec2_c_stubber.add_response('describe_internet_gateways', {"InternetGateways": aws_igws}, {'Filters': expected_filters})
    ec2_r_stubber.add_response('describe_internet_gateways', {"InternetGateways": aws_igws}, {'InternetGatewayIds': [aws_igw_id]})
    ec2_c_stubber.add_response('describe_route_tables',      {"RouteTables": aws_rts}, {'Filters': expected_filters})

    # continuing with destroy()
    ec2_r_stubber.add_response('describe_route_tables',     {"RouteTables": aws_rts}, {'RouteTableIds': [aws_rt_id]})
    ec2_r_stubber.add_response('disassociate_route_table',  {}, {'AssociationId': 'assoc-id', 'DryRun': False})
    ec2_r_stubber.add_response('delete_route_table',        {}, {'DryRun': False, 'RouteTableId': aws_rt_id})
    ec2_r_stubber.add_response('detach_internet_gateway',   {}, {'DryRun': False, 'InternetGatewayId': aws_igw_id, 'VpcId': aws_vpc_id})
    ec2_r_stubber.add_response('delete_internet_gateway',   {}, {'DryRun': False, 'InternetGatewayId': aws_igw_id})
    ec2_r_stubber.add_response('delete_subnet',             {}, {'DryRun': False, 'SubnetId': aws_subnet_id})
    ec2_r_stubber.add_response('delete_vpc',                {}, {'DryRun': False, 'VpcId': aws_vpc_id})

    ec2_r_stubber.activate()
    ec2_c_stubber.activate()
    patched_aws_networking.ec2 = r
    patched_aws_networking.client = s
    return patched_aws_networking


def test_init_destroys_resources_when_none_exist(stub_init_destroys_resources: AWSNetworking):
    stub_init_destroys_resources.destroy()

# ??? should there be a test which includes a route table with more than one
# association, even though it is an invalid state?


