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
import os
from pathlib import Path
from textwrap import dedent
import sys

import boto3

from quickhost import QHExit, CliResponse, AppBase

from .AWSResource import AWSResourceBase
from .AWSIam import Iam
from .AWSSG import SG
from .AWSHost import AWSHost
from .AWSKeypair import KP
from .AWSNetworking import AWSNetworking
from .constants import AWSConstants
from .utilities import QuickhostUnauthorized, Arn, QuickhostAWSException, get_my_public_ip, _print_dict

logger = logging.getLogger(__name__)


class AWSApp(AppBase, AWSResourceBase):
    """
    AWSApp
    Implements quickhost.AppBase

    As parameters are gathered, they are stored as attributes.
    """
    plugin_name = 'aws'

    def __init__(self, app_name):
        self.app_name = app_name
        self.userdata = None
        self.ssh_key_filepath = None
        self.ami = None
        self.num_hosts = None
        self.instance_type = None
        self.userdata = None
        self.ports = []
        self.cidrs = []
        self.vpc_id = None
        self.subnet_id = None
        self.sgid = None

    def load_default_config(self, cache_ok=True, region=AWSConstants.DEFAULT_REGION, profile=AWSConstants.DEFAULT_IAM_USER):
        logger.debug("load default config")
        try:
            networking = AWSNetworking(
                region=region,
                profile=profile
            )
        except QuickhostAWSException as e:
            sys.stderr.write("{}\nHave you run 'quickhost aws init' yet?\n".format(e))
            raise SystemExit(2)

        networking_params = networking.describe(use_cache=cache_ok)
        logger.debug("networking params: %s", networking_params)
        session: boto3.Session = boto3.session.Session(profile_name=profile, region_name=region)
        sts_client = session.client('sts')

        caller_info = sts_client.get_caller_identity()
        _ = caller_info.pop('ResponseMetadata')
        self.vpc_id = networking_params['vpc_id']
        self.subnet_id = networking_params['subnet_id']
        calling_user_arn = Arn(caller_info['Arn'])
        self.user = calling_user_arn.resource
        self.account = calling_user_arn.account
        return networking_params

    def plugin_destroy(self, plugin_destroy_args) -> CliResponse:
        """"""
        logger.info("Destroy plugin '%s'", self.plugin_name)
        logger.debug("plugin destroy args %s", plugin_destroy_args)
        params = {
            "app_name": "uninstall-quickhost-aws",
            "region": AWSConstants.DEFAULT_REGION,
            "profile": plugin_destroy_args['profile'],
        }
        session = self._get_session(region=params['region'], profile=params['profile'])
        sts = session.client('sts')
        whoami = sts.get_caller_identity()
        whoami['username'] = self._get_user_name_from_arn(whoami['Arn'])
        whoami['region'] = session.region_name
        whoami['profile'] = session.profile_name
        user_name = whoami['Arn'].split(":")[5].split("/")[-1]
        user_id = whoami['UserId']
        account = whoami['Account']
        inp = input("About to destroy quickhost and all associated apps using:\nuser:\t\t{} ({})\naccount:\t{}\n\nContinue? (y/n) ".format(
            user_name, user_id, account))
        logger.info("Uninstalling plugin '%s'", self.plugin_name)
        if not inp.lower() in ('y', 'yes'):
            logger.debug(inp)
            return CliResponse(None, 'aborted', QHExit.ABORTED)

        logger.info("destroying remaining apps")
        AWSApp.destroy_all(yes=True)

        logger.info("destroying networking")
        AWSNetworking(
            app_name=params['app_name'],
            region=params['region'],
            profile=params['profile']
        ).destroy()

        logger.info("destroying iam resources")
        Iam(
            region=params['region'],
            profile=params['profile']
        ).destroy()
        logger.info("done destroying all plugin resources")

        return CliResponse("Finished removing AWS resources from account '{}' in {}".format(
            account, params['region']), None, QHExit.OK)

    def plugin_init(self, init_args: dict) -> CliResponse:
        """
        Setup the following:
        - IAM user/group/policies/credentials
        - .aws/config and .aws/credentials files
        - VPC/Subnet/Routing/networking per-region
        must be run as an admin-like user
        """
        logger.debug('run init')
        logger.debug("init args %s", init_args)
        finished_with_errors = False
        params = {
            "region": init_args['region'],
            "profile": init_args['profile'],
        }
        session = self._get_session(region=params['region'], profile=params['profile'])
        sts = session.client('sts')
        whoami = sts.get_caller_identity()
        whoami['username'] = self._get_user_name_from_arn(whoami['Arn'])
        whoami['region'] = session.region_name
        whoami['profile'] = session.profile_name
        user_name = whoami['Arn'].split(":")[5].split("/")[-1]
        confirmation_line = dedent(f"""\
            Initializing quickhost with the following parameters:
            Target account:     {whoami['Account']}
            Home Region:        {init_args['region']}
            Calling user:       {user_name}
            Calling profile:    {whoami['profile']}
        """)
        print(confirmation_line)
        inp = input("Continue? (y/N) ")
        if not inp.lower() in ['yes', 'y']:
            return CliResponse(None, 'aborted', QHExit.ABORTED)
        qh_iam = Iam(**params)
        try:
            created_iam_resources = qh_iam.create()
            for k, v in created_iam_resources.items():
                logger.info("%s = %s", k, v)
        except QuickhostUnauthorized as e:
            finished_with_errors = True
            logger.error("Failed to create initial IAM resources: %s", e)
            return CliResponse(None, "Failed to create initial IAM resources using the profile '%s'. Are you allowed to?" % user_name, 1)

        networking_params = AWSNetworking(
            profile=init_args['profile'],
            region=init_args['region'],
        )
        try:
            created_networking_resources = networking_params.create()
            for k, v in created_networking_resources.items():
                logger.info("%s = ", k, v)
        except Exception as e:
            finished_with_errors = True
            logger.error(e, exc_info=True)

        if finished_with_errors:  # @@@
            return CliResponse('finished init with errors', "<placeholder>", QHExit.GENERAL_FAILURE)
        else:
            return CliResponse('Done', None, QHExit.OK)

    def describe(self, args: dict) -> CliResponse:
        logger.debug('describe')
        logger.debug("describe args %s", args)
        params = args
        params['profile'] = AWSConstants.DEFAULT_IAM_USER

        hosts = AWSHost(
            app_name=self.app_name,
            region=params['region'],
            profile=params['profile'],
        )
        hosts_describe = hosts.describe()
        logger.debug("hosts_describe=%s", hosts_describe)
        if len(hosts_describe) == 0:
            logger.warning("No hosts found for app '%s'", self.app_name)
            return CliResponse(None, f"No hosts found for app '{self.app_name}'", 1)

        kp = KP(
            app_name=self.app_name,
            region=params['region'],
            profile=params['profile'],
        )
        kp_describe = kp.describe()
        logger.debug("kp_describe=%s", kp_describe)
        for h in hosts_describe:
            h['ssh_key_filepath'] = kp_describe['ssh_key_filepath']

        passwords = {}
        if len(hosts_describe) != 0:
            for h in hosts_describe:
                if h.platform in ['Windows',]:
                    if params['show_password']:
                        passwords[h.instance_id] = kp.windows_get_password(h.instance_id)
                    else:
                        passwords[h.instance_id] = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
            for h in hosts_describe:
                for inst_id, pw in passwords.items():
                    if inst_id == h.instance_id:
                        h.password = pw

        if params['verbosity'] > 0:
            networking_params = self.load_default_config(
                region=params['region']
            )

            iam_vals = Iam(
                region=params['region'],
                profile=params['profile'],
            ).describe()
            logger.debug("iam_vals=%s", iam_vals)
            iam_print = {}

            iam_print['credentials check'] = 'ok' if iam_vals['credentials']['credentials-exist'] else 'not ok'
            iam_print['your_region'] = iam_vals['credentials']['default-region'] or '???'
            iam_print['user_arn'] = iam_vals['iam-user']['arn']
            iam_print['group_arn'] = iam_vals['iam-group']['arn']

            sg = SG(
                app_name=self.app_name,
                region=params['region'],
                profile=params['profile'],
                vpc_id=self.vpc_id,
            )
            sg_describe = sg.describe()
            logger.debug("sg_describe=%s", sg_describe)

            # no logging below this line
            _print_dict({
                'account': self.account,
                'invoking user': '/'.join(self.user.split('/')[1:])
            }, heading="you are")
            _print_dict(networking_params, heading="app-global params")
            _print_dict(iam_print, heading='IAM')
            _print_dict(sg_describe, heading='security groups')
            _print_dict(kp_describe, heading='key pair')

        for i, h in enumerate(hosts_describe):
            _print_dict(h.__dict__, heading=f"host {i}")
            sys.stdout.write("\033[32m{}\033[0m".format('ssh:') + "\n")
            print(f"ssh -i {kp_describe['ssh_key_filepath']} ec2-user@{h.public_ip}")
            print()
            sys.stdout.write("\033[32m{}\033[0m".format('ansible inventory entry:') + "\n")
            print(dedent(f"""\
                [{h.app_name}]
                {h.public_ip}
                [{h.app_name}:vars]
                ansible_user=ec2_user
                ansible_ssh_private_key_file={kp_describe['ssh_key_filepath']}
            """))
        return CliResponse('Done', None, QHExit.OK)

    @classmethod
    def list_all(self):
        return CliResponse(_print_dict({
            "apps": AWSHost(
                app_name="list-all",
                profile=AWSConstants.DEFAULT_IAM_USER,  # @@@
                region=AWSConstants.DEFAULT_REGION,  # @@@
            ).get_all_running_apps(region=AWSConstants.DEFAULT_REGION)  # @@@
            # ...
        }, heading='all aws apps'), None, QHExit.OK)

    @classmethod
    def destroy_all(cls, yes=False):
        logger.info("Destroy all %s apps", cls.plugin_name)
        if not yes:
            print("You are about to remove all apps associated with the {} plugin.".format(cls.plugin_name))
            are_you_sure = input("Are you sure? (y/N): ")
            if are_you_sure not in ["y", "Y", "yes", "YES"]:
                logger.info("aborted")
                return CliResponse("Aborted", '', 0)

        apps = AWSHost(
            app_name="destroy-all",
            profile=AWSConstants.DEFAULT_IAM_USER,
            region=AWSConstants.DEFAULT_REGION,
        ).get_all_running_apps(region=AWSConstants.DEFAULT_REGION)
        if apps is None:
            return CliResponse("Nothing to destroy.", None, QHExit.OK)

        logger.info("Destroying %s apps", len(apps))
        for a in apps:
            app = AWSApp(a.split(" ")[0])  # ???
            app.destroy(args={
                "h": False,
                "profile": AWSConstants.DEFAULT_IAM_USER,
                "region": AWSConstants.DEFAULT_REGION,
                "yes": True
            })
            logger.info("Destroyed app '%s'", app.app_name)

        return CliResponse("Destroyed {} apps".format(len(apps)), None, QHExit.OK)

    def create(self, args: dict) -> CliResponse:
        logger.debug('make')
        logger.debug("make args %s", args)
        stdout = ""
        stderr = ""

        params = self._parse_make(args)
        _print_dict({k: v for k, v in sorted(params.items())}, f'create app: {self.app_name}')
        print()
        prompt_continue = input(f"Proceed creating '{self.app_name}' with these parameters? (y/N): ")
        if prompt_continue.lower() not in ['y', 'yes']:
            stderr = "aborted"
            return CliResponse(stdout, stderr, QHExit.ABORTED)

        self.load_default_config(region=params['region'])
        profile = AWSConstants.DEFAULT_IAM_USER
        kp = KP(app_name=self.app_name, region=params['region'], profile=profile)
        sg = SG(app_name=self.app_name, region=params['region'], profile=profile, vpc_id=self.vpc_id)
        host = AWSHost(app_name=self.app_name, region=params['region'], profile=profile)
        if host.describe() != []:
            logger.error("app named '%s' already exists", self.app_name)
            return CliResponse(None, f"app named '{self.app_name}' already exists", QHExit.ABORTED)

        kp_created = kp.create(ssh_key_filepath=params['ssh_key_filepath'])
        sg_created = sg.create(
            ports=params['ports'],
            cidrs=params['cidrs'],
        )
        hosts_created = host.create(
            subnet_id=self.subnet_id,
            num_hosts=params['host_count'],
            _os=params['os'],
            instance_type=params['instance_type'],
            sgid=sg.sgid,
            key_name=kp_created['key_name'],
            disk_size=params['disk_size'],
            userdata=params['userdata'],
            ssh_key_filepath=params['ssh_key_filepath'],
        )
        if kp_created and hosts_created is not None and sg_created:
            return CliResponse('Done', None, QHExit.OK)
        else:
            return CliResponse('finished creating hosts with warnings', "kp_created={}, hosts_created={}, sg_created={}".format(
                kp_created, hosts_created, sg_created
            ), QHExit.GENERAL_FAILURE)

    def update(self, args: dict) -> CliResponse:
        raise Exception("TODO")

    def destroy(self, args: dict) -> CliResponse:
        logger.debug("destroy")
        logger.debug("destroy args %s", args)
        params = args
        params['profile'] = 'quickhost-user'

        hosts = AWSHost(
            region=params['region'],
            app_name=self.app_name,
            profile='quickhost-user'
        )
        hosts_describe = hosts.describe()
        if len(hosts_describe) == 0:
            return CliResponse(None, f"no hosts running for app '{self.app_name}'", 1)
        for h in hosts_describe:
            _print_dict(h.__dict__, heading=self.app_name, underline_char='!!')
        if 'yes' not in params.keys():
            prompt_continue = input(f"Proceed destroying app '{self.app_name}'? (y/N)")
            if prompt_continue.lower() not in ['y', 'yes']:
                return CliResponse(None, "aborted", QHExit.ABORTED)

        self.load_default_config(region=params['region'])
        kp_destroyed = KP(
            app_name=self.app_name,
            region=params['region'],
            profile=params['profile']
        ).destroy()
        hosts_destroyed = hosts.destroy()
        sg_destroyed = SG(
            app_name=self.app_name,
            region=params['region'],
            profile=params['profile'],
            vpc_id=self.vpc_id,
        ).destroy()
        if kp_destroyed and hosts_destroyed and sg_destroyed:
            return CliResponse('Done', '', QHExit.OK)
        else:
            return CliResponse('finished destroying hosts with errors', "kp_destroyed={}, hosts_destroyed={}, sg_destroyed={}".format(
                kp_destroyed, hosts_destroyed, sg_destroyed
            ), QHExit.GENERAL_FAILURE)

    def _parse_make(self, input_args: dict):
        """
        Make sure the arguments used to call create() are acceptable

        2023-03-01: always include the caller's public IPv4 address in whitelisted IP addresses, even when additional cidrs are specified with --ip.
        """
        make_params = {}
        flags = input_args.keys()
        # ports ingress
        if 'port' in flags:
            _ports = list(dict.fromkeys(input_args['port']))  # get rid of duplicates
            ports = []
            for p in _ports:
                try:
                    ports.append(str(p))
                except ValueError:
                    raise RuntimeError("port numbers must be digits")
            make_params['ports'] = ports

        # set defaults based on os
        # NOTE: specifying a port on the command line will override defaults
        # this is not documented, but is desired behavior
        else:
            if input_args['os'] in AWSConstants.WindowsOSTypes:
                make_params['ports'] = [3389]
            else:
                make_params['ports'] = [22]

        # cidrs ingress
        # always add public ip
        make_params['cidrs'] = []
        make_params['cidrs'].append(get_my_public_ip())
        if input_args['ip'] is not None:
            for i in input_args['ip']:
                if len(i.split('/')) == 1:
                    logger.warning("Assuming /32 cidr for ip '%s'", i)
                    make_params['cidrs'].append(i + "/32")
                else:
                    make_params['cidrs'].append(i)
        # userdata
        if input_args['userdata'] is not None:
            if not Path(input_args['userdata']).exists():
                raise RuntimeError(f"path to userdata '{input_args['userdata']}' does not exist!")
        make_params['userdata'] = input_args['userdata']

        # ec2 key pem file
        make_params['ssh_key_filepath'] = self.new_ssh_key_filepath(input_args['ssh_key_filepath'])
        logger.debug("Will create new private key at '%s'", make_params['ssh_key_filepath'])

        # the rest
        if 'host_count' in flags:
            make_params['host_count'] = int(input_args['host_count'])
        if 'instance_type' in flags:
            make_params['instance_type'] = input_args['instance_type']
        if 'region' in flags:
            make_params['region'] = input_args['region']
        if 'os' in flags:
            make_params['os'] = input_args['os']
        if 'disk_size' in flags:
            make_params['disk_size'] = int(input_args['disk_size'])
        else:
            make_params['disk_size'] = None

        return make_params

    def new_ssh_key_filepath(self, directory: str):
        if directory is None:
            _kfname = Path(os.path.expanduser("~")) / ".ssh" / f"quickhost-{self.app_name}.pem"
            return str(_kfname.absolute())
        else:
            _keypath = Path(directory)
            if _keypath.is_dir():
                _kfname = _keypath / f"quickhost-{self.app_name}.pem"
                return str(_kfname.absolute())
            else:
                logger.error('The ssh key filepath you entered is not a directory: %s', _keypath.absolute())
                print('The ssh key filepath you entered is not a directory: {}'.format(_keypath.absolute()))
                raise SystemExit(1)
