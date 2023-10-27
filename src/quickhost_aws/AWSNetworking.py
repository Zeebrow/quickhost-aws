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

from botocore.exceptions import ClientError

from quickhost import APP_CONST as C, store_test_data, scrub_datetime

from .utilities import get_single_result_id, QuickhostUnauthorized, quickmemo
from .AWSResource import AWSResourceBase

logger = logging.getLogger(__name__)


class AWSNetworking(AWSResourceBase):
    DefaultFilter = { 'Name': 'tag:Name', 'Values': [ C.DEFAULT_APP_NAME ] }
    DefaultTag = { 'Value': C.DEFAULT_APP_NAME, 'Key': 'Name' }

    # @@@ testme
    # ERROR: AWSNetworking.TagSpec() takes 1 positional argument but 2 were given
    # Traceback (most recent call last):
    #   File "/home/zeebrow/repos/github.com/zeebrow/quickhost-plugins/plugins/aws/src/quickhost_aws/AWSApp.py", line 200, in plugin_init
    #     networking_params.create()
    #   File "/home/zeebrow/repos/github.com/zeebrow/quickhost-plugins/plugins/aws/src/quickhost_aws/AWSNetworking.py", line 59, in create
    #     TagSpecifications=[ AWSNetworking.TagSpec('vpc'), ]
    # TypeError: AWSNetworking.TagSpec() takes 1 positional argument but 2 were given
    # @classmethod # 
    def TagSpec(resource):
        return { 'ResourceType': resource, 'Tags': [ { 'Value': C.DEFAULT_APP_NAME, 'Key': 'Name' } ] }

    def __init__(self, profile, region, dry_run=False):
        session = self._get_session(profile=profile, region=region)
        self.client = session.client('ec2')
        self.ec2 = session.resource('ec2')
        self.dry_run = dry_run
        self.vpc_id = None
        self.igw_id = None
        self.subnet_id = None
        self.rt_id = None

    def create(self, cidr_block=C.DEFAULT_VPC_CIDR):
        self.__dict__.update(self.describe())
        ####################################################
        # vpc
        ####################################################
        vpc = None
        if not self.vpc_id:
            logger.debug("creating vpc...")
            vpc = self.ec2.create_vpc(
                CidrBlock=cidr_block,
                DryRun=self.dry_run,
                TagSpecifications=[ AWSNetworking.TagSpec('vpc'), ]
            )
            vpc.wait_until_available()
            vpc.create_tags(Tags=[AWSNetworking.DefaultTag])
            self.vpc_id = vpc.id
            vpc.reload()
            logger.info(f"Created VPC: {self.vpc_id}")
        else:
            logger.warning(f"Found existing vpc: {self.vpc_id}")
            vpc = self.ec2.Vpc(self.vpc_id)

        ####################################################
        # igw
        ####################################################
        igw = None
        igw_status = 'Not OK'
        if not self.igw_id:
            logger.debug("creating igw...")
            igw_id = self.client.create_internet_gateway(
                DryRun=self.dry_run,
                TagSpecifications=[ AWSNetworking.TagSpec('internet-gateway'), ]
            )
            self.igw_id = get_single_result_id("InternetGateway", igw_id, plural=False)
            igw = self.ec2.InternetGateway(self.igw_id)
            logger.debug(f"...attaching igw ({self.igw_id}) to vpc ({self.vpc_id})...")
            igw.attach_to_vpc(DryRun=False, VpcId=self.vpc_id)
            igw.reload()
            logger.info(f"Created Internet Gateway: {self.igw_id}")
        else:
            logger.debug(f"Have igw: {self.igw_id}")
            igw_status = 'Check attachment'
            igw = self.ec2.InternetGateway(self.igw_id)
            # fixes attachment issue
            if len(igw.attachments) == 0:
                igw.attach_to_vpc(DryRun=False, VpcId=self.vpc_id)
                igw.reload()
            if len(igw.attachments) == 1 and igw.attachments[0]['VpcId'] == self.vpc_id:
                igw_status = f"Attached to vpc {self.vpc_id}"
            logger.warning(f"Found existing internet gateway with id: {self.igw_id} ({igw_status})")

        ####################################################
        # subnet
        ####################################################
        subnet = None
        if not self.subnet_id:
            logger.debug("creating subnet...")
            subnet = vpc.create_subnet(
                CidrBlock=C.DEFAULT_SUBNET_CIDR,
                VpcId=self.vpc_id,
                DryRun=self.dry_run,
                TagSpecifications=[ AWSNetworking.TagSpec('subnet'), ]
            )
            subnet.create_tags(Tags=[AWSNetworking.DefaultTag])
            self.subnet_id = subnet.id
            subnet.reload()
            logger.info(f"Created subnet: {self.subnet_id}")
        else:
            logger.warning(f"Found existing subnet: {self.subnet_id}")
            subnet = self.ec2.Subnet(self.subnet_id)

        ####################################################
        # route-table
        ####################################################
        rt_ok = 'Not OK'
        route_table = None
        if not self.rt_id:
            logger.debug("creating route table...")
            route_table = vpc.create_route_table(
                VpcId=self.vpc_id,
                DryRun=self.dry_run,
                TagSpecifications=[ AWSNetworking.TagSpec('route-table'), ]
            )
            logger.debug(f"creating route for igw ({self.igw_id})..")
            route_table.create_route(
                DestinationCidrBlock='0.0.0.0/0',
                DryRun=False,
                GatewayId=self.igw_id,
                # neat
                # NetworkInterfaceId='string',
            )
            self.rt_id = route_table.id
            rt_ok = 'Check association'
            logger.debug(f"associating route table ({self.rt_id}) with subnet ({self.subnet_id})...")
            route_table.associate_with_subnet(
                DryRun=False,
                SubnetId=self.subnet_id,
            )
            route_table.reload()
            if route_table.associations_attribute[0]['SubnetId'] == self.subnet_id and route_table.associations_attribute[0]['AssociationState']['State'] == "associated":
                rt_ok = f"Associated with subnet {self.subnet_id}"
            logger.info("Created Route Table. self.rt_id={} ({})".format(self.rt_id, rt_ok))
        else:
            rt_ok = 'Check association'
            route_table = self.ec2.RouteTable(self.rt_id)
            if len(route_table.associations_attribute) == 0:
                route_table.associate_with_subnet(
                    DryRun=False,
                    SubnetId=self.subnet_id,
                )
                route_table.reload()
                rt_ok = 'ok'
            if route_table.associations_attribute[0]['SubnetId'] == self.subnet_id and route_table.associations_attribute[0]['AssociationState']['State'] == "associated":
                rt_ok = f"Associated with subnet {self.subnet_id}"
            logger.warning(f"Found existing route table: {self.rt_id} ({rt_ok})")
        # rt = self.ec2.RouteTable(self.rt_id)
        return {
            "vpc_id": self.vpc_id,
            "subnet_id": self.subnet_id,
            "rt_id": self.rt_id,
            "igw_id": self.igw_id,
        }

    @quickmemo
    def describe(self, use_cache=True):
        logger.debug("AWSNetworking.describe")
        try:
            # permissions exceptions are normally caught in AWSApp.py
            # these are special because they are called for all actions
            existing_vpcs = self.client.describe_vpcs( Filters=[ AWSNetworking.DefaultFilter ],)
            vpc_id = get_single_result_id("Vpc", existing_vpcs)
            existing_subnets = self.client.describe_subnets( Filters=[ AWSNetworking.DefaultFilter ],)
            subnet_id = get_single_result_id("Subnet", existing_subnets)
            store_test_data(resource='AWSNetworking', action='describe_vpcs', response_data=scrub_datetime(existing_vpcs))
            store_test_data(resource='AWSNetworking', action='describe_subnets', response_data=scrub_datetime(existing_subnets))
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'UnauthorizedOperation' or code == 'AccessDenied':
                logger.critical(f"The user {self.caller_info['username']} couldn't perform the operation '{e.operation_name}'.")
                raise QuickhostUnauthorized(username=self.caller_info['username'], operation=e.operation_name)
        existing_igws = self.client.describe_internet_gateways( Filters=[ AWSNetworking.DefaultFilter ],)
        igw_id = get_single_result_id("InternetGateway", existing_igws)
        if igw_id is not None:
            igw = self.ec2.InternetGateway(igw_id)
            if igw.attachments == []:
                logger.warn(f"Internet Gateway '{igw_id}' is not attached to a vpc!")
            else:
                if igw.attachments[0]['VpcId'] != vpc_id:
                    logger.error(f"Internet Gateway '{igw_id}' is not attached to the correct vpc!")
        existing_rts = self.client.describe_route_tables(Filters=[ AWSNetworking.DefaultFilter ])
        rt_id = get_single_result_id("RouteTable", existing_rts)
        store_test_data(resource='AWSNetworking', action='describe_route_tables', response_data=scrub_datetime(existing_rts))
        store_test_data(resource='AWSNetworking', action='describe_internet_gateways', response_data=scrub_datetime(existing_igws))
        return {
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,
            "rt_id": rt_id,
            "igw_id": igw_id,
        }

    def destroy(self):
        """
        Destroy all networking-related AWS resources. Requires that no apps be running.
        - Dissociate and delete route table
        - Detatch and delete internet gateway
        - Delete subnet
        - Delete VPC
        """
        self.__dict__.update(self.describe())
        print(self.describe())
        if self.rt_id:
            rt = self.ec2.RouteTable(self.rt_id)
            rt_assoc_ids = [rtid['RouteTableAssociationId'] for rtid in rt.associations_attribute]
            logger.debug(f"deleting {len(rt_assoc_ids)} associations on route table '{self.rt_id}'...")
            for rtai in rt_assoc_ids:
                self.ec2.RouteTableAssociation(rtai).delete(DryRun=False)
            logger.debug(f"deleting route table '{self.rt_id}'...")
            rt.delete(DryRun=False)

        if self.igw_id:
            igw = self.ec2.InternetGateway(self.igw_id)
            logger.debug(f"detaching igw '{self.igw_id}' from '{self.vpc_id}'...")
            igw.detach_from_vpc(
                DryRun=False,
                VpcId=self.vpc_id
            )
            logger.debug(f"deleting igw '{self.igw_id}'...")
            igw.delete(DryRun=False)
        if self.subnet_id:
            subnet = self.ec2.Subnet(self.subnet_id)
            logger.debug(f"deleting subnet '{self.subnet_id}'...")
            subnet.delete(DryRun=False)
        if self.vpc_id:
            logger.debug(f"deleting vpc '{self.vpc_id}'...")
            vpc = self.ec2.Vpc(self.vpc_id)
            vpc.delete(DryRun=False)
        logger.debug("Done.")
