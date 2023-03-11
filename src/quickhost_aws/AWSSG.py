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

from typing import Tuple, List
import logging

import botocore.exceptions

from quickhost import store_test_data, scrub_datetime

from .utilities import QH_Tag, UNDEFINED
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

    def _load(self):
        pass

    def get_security_group_id(self) -> str:
        """
        returns security group id, or None if security group does not exist
        """
        dsg = None
        try:
            dsg = self.client.describe_security_groups(
                Filters=[
                    { 'Name': 'vpc-id', 'Values': [ self.vpc_id, ] },
                    { 'Name': 'group-name', 'Values': [ self.app_name, ] },
                ],
            )
            # @@@ could be None
            return dsg['SecurityGroups'][0]['GroupId']
        except IndexError:
            return None
        except botocore.exceptions.ClientError as e:
            # @@@ huh
            print(e)
            print(e['Error'])
            print(e['Code'])
            logger.debug(f"Could not get sg for app '{self.app_name}':\n{e}")
            return

    def create(self, cidrs, ports, dry_run=False) -> bool:
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
                DryRun=dry_run
            )
            self.sgid = sg['GroupId']
            store_test_data(resource='AWSSG', action='create_security_group', response_data=sg)
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Security Group already exists for '{self.app_name}':\n{e}")
            self.sgid = self.get_security_group_id()
            rtn = False

        if not self._add_ingress(cidrs, ports):
            rtn = False

        return rtn

    def destroy(self) -> bool:
        try:
            sg_id = self.get_security_group_id()
            if not sg_id:
                logger.warning(f"No security group found for app '{self.app_name}'")
                return False
            # @@@ this returns None. Might want to confirm deletion.
            self.client.delete_security_group(GroupId=sg_id)
            logger.info(f"deleting security group '{sg_id}'")
            return True
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
                logger.warning(f"No security group found for app '{self.app_name}', skipping...")
                return False
            else:
                logger.error(f"(Security Group) Unhandled botocore client exception: ({e.response['Error']['Code']}): {e.response['Error']['Message']}")
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
            response = self.client.authorize_security_group_ingress(
                GroupId=self.sgid,
                IpPermissions=perms,
                DryRun=False
            )
            store_test_data(resource='AWSSG', action='authorize_security_group_ingress', response_data=scrub_datetime(response))
            self.ports = ports
            self.cidrs = cidrs
            return True
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
                logger.error(f"No security group found for app '{self.app_name}'")
                return False
            else:
                logger.error(f"(Security Group) Unhandled botocore client exception: ({e.response['Error']['Code']}): {e.response['Error']['Message']}")
                return False

    def describe(self):
        logger.debug("AWSSG.describe")
        rtn = {
            'sgid': UNDEFINED,  # giving this a try
            'ports': [],
            'cidrs': [],
            'ok': True,
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

            store_test_data(resource='AWSSG', action='describe_security_groups', response_data=scrub_datetime(response))
            return rtn
        except IndexError:
            logger.debug("No security group with name {} found for region {}".format(self.app_name, self.region))
            return None
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
                self.sgid = None
                logger.error(f"No security group found for app '{self.app_name}' (does the app exist?)")
                rtn['sgid'] = None
                rtn['ok'] = False
            else:
                logger.error(f"(Security Group) Unhandled botocore client exception: ({e.response['Error']['Code']}): {e.response['Error']['Message']}")
                rtn['sgid'] = None
                rtn['ok'] = False

                # @@@ uhhhh

    def _describe_sg_ingress(self, dsg_ip_permissions: dict) -> Tuple[List[str], List[str], bool]:
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
