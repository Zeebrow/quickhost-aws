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

import boto3

from .constants import AWSConstants

logger = logging.getLogger(__name__)


class AWSResourceBase:
    """
    Base class to consolidate session objects
    """

    def _get_session(self, profile=AWSConstants.DEFAULT_IAM_USER, region=AWSConstants.DEFAULT_REGION) -> boto3.Session:
        session = boto3.session.Session(profile_name=profile, region_name=region)
        return session

    def get_caller_info(self, profile, region):
        session = self._get_session(profile=profile, region=region)
        sts = session.client('sts')
        whoami = sts.get_caller_identity()
        whoami['username'] = self._get_user_name_from_arn(whoami['Arn'])
        whoami['region'] = session.region_name
        whoami['profile'] = session.profile_name
        whoami.pop('ResponseMetadata')

        if self._get_user_name_from_arn(whoami['Arn']) != AWSConstants.DEFAULT_IAM_USER:
            logger.warning(f"You're about to do stuff with the non-quickhost user {whoami['Arn']}")
        return whoami

    # def get_client(self, resource, profile, region):
    #     session = self._get_session(profile=profile, region=region)
    #     sts = session.client('sts')
    #     whoami = sts.get_caller_identity()
    #     whoami['username'] = self._get_user_name_from_arn(whoami['Arn'])
    #     whoami['region'] = session.region_name
    #     whoami['profile'] = session.profile_name
    #     _ = whoami.pop('ResponseMetadata')

    #     if self._get_user_name_from_arn(whoami['Arn']) != AWSConstants.DEFAULT_IAM_USER:
    #         logger.warning(f"You're about to do stuff with the non-quickhost user {whoami['Arn']}")
    #     return (whoami, session.client(resource))

    # @@@ out-of-place
    def _get_user_name_from_arn(self, arn: str):
        return arn.split(":")[5].split("/")[-1]
