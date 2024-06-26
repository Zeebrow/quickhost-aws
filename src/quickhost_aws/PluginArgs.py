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

from argparse import SUPPRESS, ArgumentParser
import logging
from dataclasses import dataclass
import typing as t

from quickhost import ParserBase
from .constants import AWSConstants

logger = logging.getLogger(__name__)


class AWSParser(ParserBase):

    def add_subparsers(self, parser: ArgumentParser) -> None:
        """
        Create a subparser for each action, and attach argparse arguments.
        Setup each action's parser with argparse arguments.
        """
        subp = parser.add_subparsers(dest='aws')
        init_parser = subp.add_parser("init")
        make_parser = subp.add_parser("make")
        describe_parser = subp.add_parser("describe")
        update_parser = subp.add_parser("update")
        destroy_parser = subp.add_parser("destroy")
        subp.add_parser("list-all")
        destroy_all_parser = subp.add_parser("destroy-all")
        destroy_plugin_parser = subp.add_parser("destroy-plugin")
        self.add_init_parser_arguments(init_parser)
        self.add_make_parser_arguments(make_parser)
        self.add_describe_parser_arguments(describe_parser)
        self.add_update_parser_arguments(update_parser)
        self.add_destroy_parser_arguments(destroy_parser)
        self.add_destroy_all_parser_arguments(destroy_all_parser)
        self.add_destroy_plugin_parser_arguments(destroy_plugin_parser)

    def add_destroy_all_parser_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "-y", "--yes",
            action='store_true',
            help="Force deletion without prompting for confirmation")
        parser.add_argument(
            "--region",
            required=False,
            action='store',
            choices=AWSConstants.AVAILABLE_REGIONS,
            default=AWSConstants.DEFAULT_REGION,
            help="AWS region in which to destroy quickhost apps")

    def add_init_parser_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--admin-profile",
            required=True,
            action='store',
            help="Profile of an admin-like AWS user which will create initial quickhost resources")
        parser.add_argument(
            "--region",
            required=False,
            action='store',
            choices=AWSConstants.AVAILABLE_REGIONS,
            default=AWSConstants.DEFAULT_REGION,
            help="AWS region used to create quickhost resources")

    def add_destroy_plugin_parser_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "-y",
            "--yes",
            action='store_true',
            help="Force deletion without prompting for confirmation")
        parser.add_argument(
            "--admin-profile",
            required=False,
            action='store',
            default=AWSConstants.DEFAULT_IAM_USER,
            help="Profile of an admin AWS account used to destroy all quickhost resources in AWS")

    def add_make_parser_arguments(self, parser: ArgumentParser) -> None:
        """arguments for `make`"""
        parser.add_argument(
            "app_name",
            default=SUPPRESS,
            help="Name of the app being created")
        parser.add_argument(
            "-c",
            "--host-count",
            required=False,
            default=1,
            help="number of hosts to create")
        parser.add_argument(
            "--ssh-key-filepath",
            required=False,
            default=None,
            help="directory in which to save ssh private key material (default is ~/.ssh/, named <app_name>.pem)")
        parser.add_argument(
            "-p", "--port",
            required=False,
            type=int,
            action='append',
            # want SUPRESS, bc 22 is always added as a port
            default=SUPPRESS,
            help="open tcp port to all hosts in app (*nix default is 22, Windows 3389)")
        # @@@ untested
        parser.add_argument(
            "--ip",
            required=False,
            action='append',
            help="""
            Whitelist additional IPv4 CIDRs for connecting to the hosts.
            All ports specified with '--port' apply to all CIDRs specified here.
            If a CIDR is not supplied with the IP address, it is assumed to be /32.
            """)
        parser.add_argument(
            "--instance-type",
            required=False,
            default="t2.micro",
            help="Set the type of instance to launch")
        parser.add_argument(
            "-u", "--userdata",
            required=False,
            default=None,
            help="Path to optional userdata file to run on the hosts before after the host has launched")
        parser.add_argument(
            "--region",
            required=False,
            choices=AWSConstants.AVAILABLE_REGIONS,
            default=AWSConstants.DEFAULT_REGION,
            help="Region in which to launch the host")
        parser.add_argument(
            "--os",
            required=False,
            default='amazon-linux-2',
            help="The OS to run on the host ('-core' means no GUI)",
            choices=[
                "al2023",
                "amazon-linux-2",
                "ubuntu",
                "windows",
                "windows-core",
            ])
        parser.add_argument(
            "-s", "--disk-size",
            required=False,
            type=int,
            default=SUPPRESS,
            help="(UNTESTED) Size in GiB of root volume (30 or less qualifies for free tier)")

    def add_describe_parser_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "app_name",
            default=SUPPRESS,
            help="Name of the app to describe")
        parser.add_argument(
            "--region",
            required=False,
            choices=AWSConstants.AVAILABLE_REGIONS,
            default=AWSConstants.DEFAULT_REGION,
            help="Region in which the app resides")
        parser.add_argument(
            "--show-password",
            required=False,
            action='store_true',
            help="For Windows instances, show the Administrator password in plaintext")

    def add_update_parser_arguments(self, parser: ArgumentParser) -> None:
        pass

    def add_destroy_parser_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "app_name",
            default=SUPPRESS,
            help="Name of the app to destroy")
        parser.add_argument(
            "-r", "--region",
            required=False,
            default=AWSConstants.DEFAULT_REGION,
            help="Region containing the app to destroy")


@dataclass
class DestroyArgs:
    app_name: str
    profile: str
    region: t.Optional[str] = None


@dataclass
class PluginDestroyArgs:
    app_name: str  # supressed
    profile: str = AWSConstants.DEFAULT_IAM_USER
    region: t.Optional[str] = AWSConstants.DEFAULT_REGION


@dataclass
class MakeArgs:
    app_name: str  # supressed
    host_count: int
    port: t.Optional[t.List[int]]  # supressed
    ip: t.Optional[str]
    vpc_id: t.Optional[str] = None  # supressed
    subnet_id: t.Optional[str] = None  # supressed
    ssh_key_filepath: t.Optional[str] = None
    instance_type: t.Optional[str] = None
    user_data: t.Optional[str] = None
    disk_size: t.Optional[int] = None  # supressed


@dataclass
class DescribeArgs:
    app_name: str
    region: t.Optional[str] = AWSConstants.DEFAULT_REGION
    show_password: bool = False


@dataclass
class DestroyAllArgs:
    yes: bool = False
    profile: str = AWSConstants.DEFAULT_IAM_USER


@dataclass
class InitArgs:
    admin_profile: str = AWSConstants.DEFAULT_IAM_USER
    region: str = AWSConstants.DEFAULT_REGION


@dataclass
class DestroyPluginArgs:
    admin_profile: str
    yes: bool = False
