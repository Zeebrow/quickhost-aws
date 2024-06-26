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

import typing as t
import time
import logging
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass

from botocore.exceptions import ClientError
import boto3

import quickhost
from quickhost import APP_CONST as QHC

from .constants import AWSConstants
from .AWSResource import AWSResourceBase

logger = logging.getLogger(__name__)


@dataclass
class HostsDescribe(dict):
    app_name: str
    ami: str
    security_group: str
    instance_id: str
    instance_type: str
    public_ip: str
    private_ip: str
    subnet_id: str
    vpc_id: str
    state: str
    platform: str
    uptime_hrs: str


class AWSHost(AWSResourceBase):
    """
    Class for AWS host operations.
    """

    def __init__(self, app_name, profile, region):
        session = self._get_session(profile=profile, region=region)
        self.region = region
        self.client = session.client('ec2')
        self.ec2 = session.resource('ec2')
        self.app_name = app_name
        self.host_count = None

    def create(self, num_hosts, instance_type, sgid, subnet_id, userdata, key_name, _os, ssh_key_filepath, disk_size=None):
        rtn = {
            "region": self.region,
            "num_hosts": num_hosts,
            "instance_type": instance_type,
            "sgid": sgid,
            "subnet_id": subnet_id,
            "userdata": userdata,
            "key_name": key_name,
            "os": _os,
        }

        latest_image = self.get_latest_image(_os)
        image_id = latest_image['image_id']
        rtn['image_id'] = image_id

        self.host_count = num_hosts
        rtn['num_hosts'] = num_hosts
# @@@ this is the only place get_host_count is used, can we get rid of this and call self.describe() up top like all the other kids?
        if self.get_host_count() > 0:
            logger.error("Hosts for app '%s' already exist", self.app_name)
            return None
        run_instances_params = {
            'ImageId': image_id,
            'InstanceType': instance_type,
            'KeyName': key_name,
            'Monitoring': { 'Enabled': False },
            'MaxCount': int(num_hosts),
            'MinCount': 1,
            'DisableApiTermination': False,
            'DryRun': False,
            'InstanceInitiatedShutdownBehavior': 'terminate',
            'NetworkInterfaces': [
                {
                    'AssociatePublicIpAddress': True,
                    'DeviceIndex': 0,
                    'SubnetId': subnet_id,
                    'Groups': [ sgid ],
                }
            ],
            'TagSpecifications': [
                { 'ResourceType': 'instance', 'Tags': [
                    { 'Key': QHC.DEFAULT_APP_NAME, 'Value': self.app_name },
                    { 'Key': "Name", 'Value': self.app_name },
                ]},
                { 'ResourceType': 'volume', 'Tags': [
                    { 'Key': QHC.DEFAULT_APP_NAME, 'Value': self.app_name },
                ]},
            ],
        }

        if userdata:
            run_instances_params['UserData'] = self.get_userdata(userdata)

        if disk_size is not None:
            if disk_size < latest_image['ami_disk_size']:
                logger.warning("Requested dist size of %s GiB is smaller than the ami disk size (%s), using ami disk size instead.", disk_size, latest_image['disk_size'])
                tgt_disk_size = latest_image['ami_disk_size']
            else:
                tgt_disk_size = disk_size
        else:
            tgt_disk_size = latest_image['ami_disk_size']
        rtn['disk_size'] = tgt_disk_size

        self.client.run_instances(
            **run_instances_params,
            BlockDeviceMappings=[
                {
                    'DeviceName': latest_image['device_name'],
                    'Ebs': { 'VolumeSize': tgt_disk_size, },
                }
            ])

        self.wait_for_hosts_to_start(num_hosts)

        # @@@ move to function in AWSApp
        ssh_strings = []
        app_insts_thingy = self._get_app_instances()
        for i in app_insts_thingy:
            inst = self._parse_host_output(i)
            logger.debug("match %s", _os)
            if _os == "ubuntu":
                ssh_strings.append(f"ssh -i {ssh_key_filepath} ubuntu@{inst.public_ip}")
            elif _os in ["amazon-linux-2", "al2023"]:
                ssh_strings.append(f"ssh -i {ssh_key_filepath} ec2-user@{inst.public_ip}")
            elif _os == "windows":
                ssh_strings.append(f"*{inst.public_ip}")
            elif _os == "windows-core":
                ssh_strings.append(f"*{inst.public_ip}")
            else:
                logger.warning("invalid os '%s'", _os)
        [ print(f"host {i}) {ssh}") for i, ssh in enumerate(ssh_strings) ]
        return rtn

    def describe(self) -> t.List[HostsDescribe]:
        instances = []
        try:
            app_hosts = self.client.describe_instances(
                Filters=[
                    { 'Name': f"tag:{QHC.DEFAULT_APP_NAME}", 'Values': [ self.app_name,] },
                    { 'Name': 'instance-state-name', 'Values': ['running', 'pending'] },
                ],
                DryRun=False,
                MaxResults=10,
            )
            for r in app_hosts['Reservations']:
                for host in r['Instances']:
                    if host['State']['Name'] in ['running', 'pending']:
                        instances.append(self._parse_host_output(host=host))
        except ClientError as e:
            logger.error("(Security Group) Unhandled botocore client exception: (%s): %s", e.response['Error']['Code'], e.response['Error']['Message'])
            raise e
        if len(instances) == 0:
            return []
        else:
            return instances

    def destroy(self) -> bool:
        tgt_instances = self.get_instance_ids('running')
        logger.debug("destroying instnaces: %s", tgt_instances)
        if len(tgt_instances) == 0:
            logger.debug("No instances found for app '%s'", self.app_name)
            return True
        try:
            self.client.terminate_instances(InstanceIds=tgt_instances)
        except ClientError as e:
            logger.error(e)
            return False
        return self.wait_for_hosts_to_terminate(tgt_instance_ids=tgt_instances)

    @classmethod
    def get_all_running_apps(self, region) -> t.Optional[t.List[t.Any]]:
        """
        Search for all EC2 instances in the region, with a tag Name of 'quickhost', collect the tags' values into a list, and return it.
        """
        session = boto3.session.Session(profile_name=AWSConstants.DEFAULT_IAM_USER, region_name=region)
        client = session.client('ec2')

        all_running_hosts = client.describe_instances(
            Filters=[
                { 'Name': 'tag-key', 'Values': [QHC.DEFAULT_APP_NAME] },
                { 'Name': 'instance-state-name', 'Values': ['running'] },
            ],
            DryRun=False,
            MaxResults=101,
        )
        app_names = []
        for r in all_running_hosts['Reservations']:
            for host in r['Instances']:
                for tag in host['Tags']:
                    if tag['Key'] == 'Name':
                        app_names.append(tag['Value'])
        if len(app_names) == 0:
            logger.debug("no running apps found.")
            return None
        else:
            app_name_count = defaultdict(int)
            for app_name in app_names:
                app_name_count[app_name] += 1
            _rtn = []
            for k, v in app_name_count.items():
                if v > 1:
                    _rtn.append("{} ({})".format(k, v))
                else:
                    _rtn.append(k)
            logger.debug("%s running apps found.", len(_rtn))
            return _rtn

    def _get_app_instances(self):
        """
        TODO: WHy is this optional??
        NOTE: to get 'describe' data, feed the output of this into self._parse_host_output()
        """
        app_instances = []
        all_hosts = self.client.describe_instances(
            Filters=[
                { 'Name': f"tag:{QHC.DEFAULT_APP_NAME}", 'Values': [ self.app_name, ] },
                { 'Name': 'instance-state-name', 'Values': ['running'] },
            ],
            DryRun=False,
            MaxResults=10,
        )
        instance_ids = []
        for r in all_hosts['Reservations']:
            for host in r['Instances']:
                # app_instances.append(quickhost.scrub_datetime(host))
                app_instances.append(host)
                inst = self._parse_host_output(host=host)
                instance_ids.append(inst.instance_id)
        else:
            return app_instances

    def get_instance_ids(self, *states) -> t.List[str]:
        """Given the app_name, returns the instance id off all instances with a State of 'running'"""
        logger.debug("states=%s", states)
        app_instances = []
        all_hosts = self.client.describe_instances(
            Filters=[
                { 'Name': f"tag:{QHC.DEFAULT_APP_NAME}", 'Values': [ self.app_name, ] },
                { 'Name': 'instance-state-name', 'Values': list(states) },
            ],
            DryRun=False,
            MaxResults=10,
        )
        # fishy
        instance_ids = []
        for r in all_hosts['Reservations']:
            for host in r['Instances']:
                if host['State']['Name'] in states:
                    # app_instances.append(quickhost.scrub_datetime(host))
                    app_instances.append(host)
                    inst = self._parse_host_output(host=host)
                    instance_ids.append(inst.instance_id)
        return instance_ids

    def get_latest_image(self, os='amazon-linux-2'):
        """
        NOTE: (us-east-1, 12/19/2022) Free tier eligible customers can get up to 30 GB of
        EBS General Purpose (SSD) or Magnetic storage
        """
        filterset = [
            new_image_filter('state', 'available'),
            new_image_filter('architecture', 'x86_64'),
        ]
        if os == 'al2023':
            filterset.append(new_image_filter('name', 'al2023-ami-2023.*-kernel-6.?-x86_64'))
        elif os == 'amazon-linux-2':
            # e.g. amzn2-ami-hvm-2.0.20230307.0-x86_64-gp2
            filterset.append(new_image_filter('name', 'amzn2-ami-hvm-2.0.*-x86_64-gp2'))
        elif os == 'ubuntu':
            filterset.append(new_image_filter('name', '*ubuntu*22.04*'))
        elif os == 'windows':
            filterset.append(new_image_filter('name', 'Windows_Server-2022-English-Full-Base*'))
        elif os == 'windows-core':
            filterset.append(new_image_filter('name', 'Windows_Server-2022-English-Core-Base*'))
        else:
            raise Exception(f"no such image type '{os}'")
        response = self.client.describe_images(
            Filters=filterset,
            IncludeDeprecated=False,
            DryRun=False
        )
        sortedimages = sorted(response['Images'], key=lambda x: datetime.strptime(x['CreationDate'], '%Y-%m-%dT%H:%M:%S.%fZ'))
        return {
            "image_id": sortedimages[-1]['ImageId'],
            "ami_disk_size": sortedimages[-1]['BlockDeviceMappings'][0]['Ebs']['VolumeSize'],
            "device_name": sortedimages[-1]['BlockDeviceMappings'][0]['DeviceName'],
        }

    def _parse_host_output(self, host: dict, none_val=None) -> HostsDescribe:
        """
        Marshal the output of boto3's "ec2.describe_instances()" Reservations.Instances into a python class.
        If a property cannot be retrieved, it will be None.
        """

        if isinstance(host.get('LaunchTime'), datetime):
            uptime_hrs = (datetime.utcnow() - host.get('LaunchTime').replace(tzinfo=None)).total_seconds() // 3600
        elif isinstance(host.get('LaunchTime'), str):
            # got host dict from scrub_datetime
            logger.debug("WARNING: got str in LaunchTime field during describe()")
            uptime_hrs = (datetime.utcnow() - datetime.strptime(host.get('LaunchTime'), "%Y-%M-%d %H:%m:%S").replace(tzinfo=None)).total_seconds() // 3600
        else:
            logger.warning("Could not resolve LaunchTime (type: %s) from host response.", type(host.get('LaunchTime')))
            uptime_hrs = 'n/a'

        return HostsDescribe(
            app_name=self.app_name,
            state=host['State']['Name'],
            uptime_hrs=uptime_hrs,
            platform=host.get('PlatformDetails'),
            public_ip=host.get('PublicIpAddress'),
            private_ip=host.get('PrivateIpAddress'),
            ami=host.get('ImageId'),
            security_group=host.get('SecurityGroups')[0]['GroupId'],  # @@@ you can do better
            instance_id=host.get('InstanceId'),
            instance_type=host.get('InstanceType'),
            subnet_id=host.get('SubnetId'),
            vpc_id=host.get('VpcId'),
        )

    def get_userdata(self, filename: str):
        data = None
        with open(filename, 'r') as ud:
            data = ud.read()
        return data

    def get_host_count(self):
        app_hosts = quickhost.scrub_datetime(self.client.describe_instances(
            Filters=[
                { 'Name': f"tag:{QHC.DEFAULT_APP_NAME}", 'Values': [ self.app_name, ] },
                { 'Name': 'instance-state-name', 'Values': ['running'] },
            ],
            DryRun=False,
            MaxResults=10,
        ))
        count = 0
        for r in app_hosts['Reservations']:
            logger.debug("got %s instances", len(r['Instances']))
            for host in r['Instances']:
                if host['State']['Name'] == 'running':
                    count += 1
        return count

    def wait_for_hosts_to_terminate(self, tgt_instance_ids):
        """blocks until polling describe_instances() produces a lost of hosts whose State.Name is 'terminated'"""
        print(f"===================Waiting on hosts for '{self.app_name}'=========================")
        ready_hosts = []
        waiting_on_hosts = []
        other_hosts = []
        tgt_count = len(tgt_instance_ids)
        while True:
            app_hosts = quickhost.scrub_datetime(self.client.describe_instances(
                Filters=[
                    { 'Name': f"tag:{QHC.DEFAULT_APP_NAME}", 'Values': [ self.app_name, ] },
                    { 'Name': 'instance-state-name', 'Values': ['running', 'terminated', 'shutting-down'] },
                ],
                DryRun=False,
                MaxResults=10,
            ))
            for r in app_hosts['Reservations']:
                for host in r['Instances']:
                    if host['InstanceId'] in tgt_instance_ids:
                        if host['State']['Name'] == 'terminated':
                            if not (host['InstanceId'] in ready_hosts):
                                ready_hosts.append(host['InstanceId'])
                        elif host['State']['Name'] == 'shutting-down':
                            if not (host['InstanceId'] in waiting_on_hosts):
                                waiting_on_hosts.append(host['InstanceId'])
                        else:
                            if not (host['InstanceId'] in other_hosts):
                                other_hosts.append(host['InstanceId'])
            print(f"""other: {other_hosts} ({len(ready_hosts)}/{tgt_count}) Ready: {ready_hosts} Waiting: {waiting_on_hosts}\r""", end='')
            if len(ready_hosts) == tgt_count:
                print()
                return True
            time.sleep(1)

    def wait_for_hosts_to_start(self, tgt_count):
        """blocks until polling describe_instances() produces a lost of hosts whose State.Name is 'running'"""
        print(f"===================Waiting on hosts for '{self.app_name}'=========================")
        ready_hosts = []
        waiting_on_hosts = []
        other_hosts = []
        while True:
            if len(ready_hosts) == int(tgt_count):
                print()
                return True
            app_hosts = quickhost.scrub_datetime(self.client.describe_instances(
                Filters=[
                    { 'Name': f"tag:{QHC.DEFAULT_APP_NAME}", 'Values': [self.app_name,] },
                    { 'Name': 'instance-state-name', 'Values': ['running', 'pending'] },
                ],
                DryRun=False,
                MaxResults=10,
            ))
            for r in app_hosts['Reservations']:
                for host in r['Instances']:
                    if host['State']['Name'] == 'running':
                        if not (host['InstanceId'] in ready_hosts):
                            if host['InstanceId'] in waiting_on_hosts:  # should always be True
                                ready_hosts.append(host['InstanceId'])
                                waiting_on_hosts.remove(host['InstanceId'])
                    elif host['State']['Name'] == 'pending':
                        if not (host['InstanceId'] in waiting_on_hosts):
                            waiting_on_hosts.append(host['InstanceId'])
                    else:
                        if not (host['InstanceId'] in other_hosts):
                            logger.debug("HERE BUG")
                            other_hosts.append(host['InstanceId'])
            print("other: {} ({}/{}) Ready: {} Waiting: ({}): {}\r".format(
                other_hosts, len(ready_hosts), tgt_count, ready_hosts, len(waiting_on_hosts), waiting_on_hosts
            ), end='')
            time.sleep(1)


def new_image_filter(name: str, values: t.Union[t.List, str]):
    if (isinstance(values, str)):
        return {'Name': name, 'Values': [values]}
    elif (isinstance(values, list)):
        return {'Name': name, 'Values': values}
    else:
        raise Exception(f"invalid type '{type(values)}' in filter expression")
