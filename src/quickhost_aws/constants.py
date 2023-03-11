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

class AWSConstants:
    DEFAULT_HOST_OS = 'amazon-linux-2'
    DEFAULT_IAM_USER = 'quickhost-user'
    DEFAULT_IAM_GROUP = f"{DEFAULT_IAM_USER}s"
    DEFAULT_REGION = 'us-east-1'
    AVAILABLE_REGIONS = [
        'eu-north-1',
        'ap-south-1',
        'eu-west-3',
        'eu-west-2',
        'eu-west-1',
        'ap-northeast-3',
        'ap-northeast-2',
        'ap-northeast-1',
        'sa-east-1',
        'ca-central-1',
        'ap-southeast-1',
        'ap-southeast-2',
        'eu-central-1',
        'us-east-1',
        'us-east-2',
        'us-west-1',
        'us-west-2'
    ]

    # use to determine default open port
    WindowsOSTypes = [
        "windows",
        "windows-core",
    ]

#################################################################################
# FREE TIER NOTES (in the constants file of all places)
#################################################################################

###############
# from ec2 console: us-east-1 12/19/2022
# {'ImageId': 'ami-0be29bafdaad782db', 'Name': 'Windows_Server-2022-English-Full-Base-2022.12.14'}

# NOTE: (us-east-1, 12/19/2022) Free tier eligible customers can get up to 30 GB of
# EBS General Purpose (SSD) or Magnetic storage

# Free tier: In your first year includes 750 hours of t2.micro (or t3.micro in the
# Regions in which t2.micro is unavailable) instance usage on free tier AMIs per
# month, 30 GiB of EBS storage, 2 million IOs, 1 GB of snapshots, and 100 GB of
# bandwidth to the internet
###############
