# Copyright (C) 2022 zeebrow
#
# This program is so cringe: you can redistribute it and/or modify
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

from typing import Tuple, List
import logging

import botocore.exceptions

from .utilities import QH_Tag
from .AWSResource import AWSResourceBase


logger = logging.getLogger(__name__)


class SG(AWSResourceBase):
    def __init__(self, app_name, profile, region, vpc_id):
        session = self._get_session(profile=profile, region=region)
        self.client = session.client('ec2')
        self.ec2 = session.resource('ec2')
        self.app_name = app_name
        self.vpc_id = vpc_id
        self.region = region
        self.profile = profile

    def get_security_group_id(self) -> str:
        """
        looks up security group id for a given app name, and returns it if it exists, None otherwise
        """
        dsg = None
        try:
            dsg = self.client.describe_security_groups(
                Filters=[
                    { 'Name': 'vpc-id', 'Values': [ self.vpc_id, ] },
                    { 'Name': 'group-name', 'Values': [ self.app_name, ] },
                ],
            )
            sgs = dsg['SecurityGroups']
            if len(sgs) == 1:
                return sgs[0]['GroupId']
            elif len(sgs) > 1:
                logger.error("Invalid filters used while retrieving the security group id for app '%s': Query returned multiple (%s) results", self.app_name, len(sgs))
                return None
            else:
                return None
        except botocore.exceptions.ClientError as e:
            logger.error("Unknown error while retrieving security group id for app '%s': %s", self.app_name, e)
            return None

    def create(self, cidrs, ports) -> bool:
        rtn = True
        try:
            sg = self.client.create_security_group(
                Description="Made by quickhost",
                GroupName=self.app_name,
                VpcId=self.vpc_id,
                TagSpecifications=[{
                    'ResourceType': 'security-group',
                    'Tags': [
                        { 'Key': 'Name', 'Value': self.app_name },
                        QH_Tag(self.app_name)
                    ]
                }],
                DryRun=False
            )
            self.sgid = sg['GroupId']
        except botocore.exceptions.ClientError as e:
            # @@@ need specific exception - I think the assumption here is we're
            # exclusively catching 'Already Exists' (hence the call to
            # self.get_security_group_id()) and boto3 doesn't say what is thrown
            # when. So I guess this will do for now
            logger.error("Unhandled botocore client exception (%s) while attempting to create security group: %s", e.response['Error']['Code'], e.response['Error']['Message'])
            self.sgid = self.get_security_group_id()
            rtn = False

        if not self._add_ingress(cidrs, ports):
            rtn = False

        return rtn

    def destroy(self) -> bool:
        try:
            sg_id = self.get_security_group_id()
            if not sg_id:
                logger.warning("No security group found to delete for app '%s'", self.app_name)
                return False

            self.client.delete_security_group(GroupId=sg_id)
            logger.debug("Deleted security group '%s'", sg_id)
            return True

        except botocore.exceptions.ClientError as e:
            logger.error("Unhandled botocore client exception (%s) while attempting to delete security group: %s", e.response['Error']['Code'], e.response['Error']['Message'])
            return False

    def _add_ingress(self, cidrs, ports) -> bool:
        try:
            perms = []
            for port in ports:
                perms.append({
                    'FromPort': int(port),
                    'IpProtocol': 'tcp',
                    'IpRanges': [ { 'CidrIp': cidr, 'Description': 'made with quickhosts' } for cidr in cidrs ],
                    'ToPort': int(port),
                })
            self.client.authorize_security_group_ingress(
                GroupId=self.sgid,
                IpPermissions=perms,
                DryRun=False
            )
            self.ports = ports
            self.cidrs = cidrs
            return True
        except botocore.exceptions.ClientError as e:
            # but you already found it. you have self.sgid so how can you not find it now?
            if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
                logger.error("No security group found for app '%s'", self.app_name)
                return False
            else:
                # might could be called when creating a security group, but one already exists, and _add_ingress() gets called on self.sgid at that point
                logger.error("(Security Group) Unhandled botocore client exception: (%s): %s", e.response['Error']['Code'], e.response['Error']['Message'])
                return False

    def describe(self):
        logger.debug("AWSSG.describe")
        # @@@ this should probably return the IpPermissions dict as-is, k.i.s.s.
        rtn = {
            'sgid': None,
            'ports': [],
            'cidrs': [],
            'ok': True,  # is this ever used?
        }

        try:
            self.sgid = None
            response = self.client.describe_security_groups(
                Filters=[
                    { 'Name': 'vpc-id', 'Values': [ self.vpc_id, ] },
                    { 'Name': 'group-name', 'Values': [ self.app_name, ] },
                ],
            )
            self.sgid = response['SecurityGroups'][0]['GroupId']
            rtn['sgid'] = response['SecurityGroups'][0]['GroupId']

            ports, cidrs, ingress_ok = self._describe_sg_ingress(dsg_ip_permissions=response['SecurityGroups'][0]['IpPermissions'])
            self.ports = ports
            self.cidrs = cidrs
            rtn['ports'] = ports
            rtn['cidrs'] = cidrs

            return rtn
        except IndexError:
            logger.debug("No security group with name %s found for region %s", self.app_name, self.region)
            return None
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
                self.sgid = None
                logger.error("No security group found for app '%s' (does the app exist?)", self.app_name)
                rtn['sgid'] = None
                rtn['ok'] = False
            else:
                logger.error("(Security Group) Unhandled botocore client exception: (%s): %s", e.response['Error']['Code'], e.response['Error']['Message'])
                rtn['sgid'] = None
                rtn['ok'] = False

                # @@@ uhhhh

    def _describe_sg_ingress(self, dsg_ip_permissions: dict) -> Tuple[List[str], List[str], bool]:
        # ??? there is no need for this function
        ports = []
        cidrs = []
        ok = True
        try:
            for p in dsg_ip_permissions:
                for ipr in p['IpRanges']:
                    cidrs.append(ipr['CidrIp'])
                if p['ToPort'] == p['FromPort']:
                    ports.append("{}/{}".format(
                        p['ToPort'],
                        p['IpProtocol']
                    ))
                else:
                    ports.append("{0}/{2}-{1}/{2}".format(
                        p['ToPort'],
                        p['FromPort'],
                        p['IpProtocol']
                    ))
        except Exception:
            ok = False

        return (ports, cidrs, ok)
