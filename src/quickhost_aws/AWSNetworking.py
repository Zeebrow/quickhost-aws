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

from quickhost import APP_CONST as QH_C

from .utilities import get_single_result_id, QuickhostUnauthorized, quickmemo, TagSpec, DefaultFilter, DefaultTag
from .AWSResource import AWSResourceBase

logger = logging.getLogger(__name__)


class AWSNetworking(AWSResourceBase):

    def __init__(self, profile, region):
        session = self._get_session(profile=profile, region=region)
        self.client = session.client('ec2')
        self.ec2 = session.resource('ec2')
        self.vpc_id = None
        self.igw_id = None
        self.subnet_id = None
        self.rt_id = None

    def create(self, vpc_cidr_block=QH_C.DEFAULT_VPC_CIDR, subnet_cidr_block=QH_C.DEFAULT_SUBNET_CIDR):
        self.__dict__.update(self.describe())
        ####################################################
        # vpc
        ####################################################
        vpc = None
        if not self.vpc_id:
            logger.debug("creating vpc...")
            vpc = self.ec2.create_vpc(
                CidrBlock=vpc_cidr_block,
                DryRun=False,
                TagSpecifications=[ TagSpec('vpc'), ]
            )
            vpc.wait_until_available()
            vpc.create_tags(Tags=[DefaultTag])
            self.vpc_id = vpc.id
            vpc.reload()
            logger.info("Created VPC: %s", self.vpc_id)
        else:
            logger.warning("Found existing vpc: %s", self.vpc_id)
            vpc = self.ec2.Vpc(self.vpc_id)

        ####################################################
        # igw
        ####################################################
        igw = None
        igw_status = 'Not OK'
        if not self.igw_id:
            logger.debug("creating igw...")
            igw_id = self.client.create_internet_gateway(
                DryRun=False,
                TagSpecifications=[ TagSpec('internet-gateway'), ]
            )
            self.igw_id = get_single_result_id("InternetGateway", igw_id, plural=False)
            igw = self.ec2.InternetGateway(self.igw_id)
            logger.debug("...attaching igw (%s) to vpc (%s)...", self.igw_id, self.vpc_id)
            igw.attach_to_vpc(DryRun=False, VpcId=self.vpc_id)
            igw.reload()
            logger.info("Created Internet Gateway: %s", self.igw_id)
        else:
            logger.debug("Have igw: %s", self.igw_id)
            igw_status = 'Check attachment'
            igw = self.ec2.InternetGateway(self.igw_id)
            # fixes attachment issue
            igw_attachments = igw.attachments
            num_attachments = len(igw_attachments)
            if num_attachments == 0:
                igw.attach_to_vpc(DryRun=False, VpcId=self.vpc_id)
                igw.reload()
            if num_attachments == 1 and igw_attachments[0]['VpcId'] == self.vpc_id:
                igw_status = "Attached to vpc {}".format(self.vpc_id)
            logger.warning("Found existing internet gateway with id: %s (%s)", self.igw_id, igw_status)

        ####################################################
        # subnet
        ####################################################
        subnet = None
        if not self.subnet_id:
            logger.debug("creating subnet...")
            subnet = vpc.create_subnet(
                CidrBlock=subnet_cidr_block,
                VpcId=self.vpc_id,
                DryRun=False,
                TagSpecifications=[ TagSpec('subnet'), ]
            )
            subnet.create_tags(Tags=[DefaultTag])
            self.subnet_id = subnet.id
            subnet.reload()
            logger.info("Created subnet: %s", self.subnet_id)
        else:
            logger.warning("Found existing subnet: %s", self.subnet_id)
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
                DryRun=False,
                TagSpecifications=[ TagSpec('route-table'), ]
            )
            logger.debug("creating route for igw (%s)..", self.igw_id)
            route_table.create_route(
                DestinationCidrBlock='0.0.0.0/0',
                DryRun=False,
                GatewayId=self.igw_id,
            )
            self.rt_id = route_table.id
            rt_ok = 'Check association'
            logger.debug("associating route table (%s) with subnet (%s)...", self.rt_id, self.subnet_id)
            route_table.associate_with_subnet(
                DryRun=False,
                SubnetId=self.subnet_id,
            )
            route_table.reload()
            rt_associations_attribute = route_table.associations_attribute
            if rt_associations_attribute[0]['SubnetId'] == self.subnet_id and rt_associations_attribute[0]['AssociationState']['State'] == "associated":
                rt_ok = "Associated with subnet {}".format(self.subnet_id)
            logger.info("Created Route Table. self.rt_id=%s (%s)", self.rt_id, rt_ok)
        else:
            rt_ok = 'Check association'
            route_table = self.ec2.RouteTable(self.rt_id)
            rt_associations_attribute = route_table.associations_attribute
            if len(rt_associations_attribute) == 0:
                route_table.associate_with_subnet(
                    DryRun=False,
                    SubnetId=self.subnet_id,
                )
                route_table.reload()
                rt_associations_attribute = route_table.associations_attribute
            if rt_associations_attribute[0]['SubnetId'] == self.subnet_id and rt_associations_attribute[0]['AssociationState']['State'] == "associated":
                rt_ok = "Associated with subnet {}".format(self.subnet_id)
            logger.warning("Found existing route table: %s (%s)", self.rt_id, rt_ok)

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
            existing_vpcs = self.client.describe_vpcs( Filters=[ DefaultFilter ],)
            vpc_id = get_single_result_id("Vpc", existing_vpcs)
            existing_subnets = self.client.describe_subnets( Filters=[ DefaultFilter ],)
            subnet_id = get_single_result_id("Subnet", existing_subnets)
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'UnauthorizedOperation' or code == 'AccessDenied':
                logger.critical("The user %s couldn't perform the operation '%s'.", self.caller_info['username'], e.operation_name)
                raise QuickhostUnauthorized(username=self.caller_info['username'], operation=e.operation_name)
        existing_igws = self.client.describe_internet_gateways( Filters=[ DefaultFilter ],)
        igw_id = get_single_result_id("InternetGateway", existing_igws)
        if igw_id is not None:
            igw = self.ec2.InternetGateway(igw_id)
            if len(igw.attachments) == 0:
                logger.warning("Internet Gateway '%s' is not attached to a vpc!", igw_id)
            else:
                # this would be rare
                if igw.attachments[0]['VpcId'] != vpc_id:
                    logger.error("Internet Gateway '%s' is not attached to the correct vpc!", igw_id)
        existing_rts = self.client.describe_route_tables(Filters=[ DefaultFilter ])
        rt_id = get_single_result_id("RouteTable", existing_rts)
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

        if self.rt_id:
            rt = self.ec2.RouteTable(self.rt_id)
            rt_assoc_ids = [rtid['RouteTableAssociationId'] for rtid in rt.associations_attribute]
            logger.debug("deleting %s associations on route table '%s'...", len(rt_assoc_ids), self.rt_id)
            for rtai in rt_assoc_ids:
                self.ec2.RouteTableAssociation(rtai).delete(DryRun=False)
            logger.debug("deleting route table '%s'...", self.rt_id)
            rt.delete(DryRun=False)

        if self.igw_id:
            igw = self.ec2.InternetGateway(self.igw_id)
            logger.debug("detaching igw '%s' from '%s'...", self.igw_id, self.vpc_id)
            igw.detach_from_vpc(
                DryRun=False,
                VpcId=self.vpc_id
            )
            logger.debug("deleting igw '%s'...", self.igw_id)
            igw.delete(DryRun=False)
        if self.subnet_id:
            subnet = self.ec2.Subnet(self.subnet_id)
            logger.debug("deleting subnet '%s'...", self.subnet_id)
            subnet.delete(DryRun=False)
        if self.vpc_id:
            logger.debug("deleting vpc '%s'...", self.vpc_id)
            vpc = self.ec2.Vpc(self.vpc_id)
            vpc.delete(DryRun=False)
        logger.debug("Done.")
