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
import json
from pathlib import Path
import os
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

from botocore.exceptions import ClientError

from quickhost import APP_CONST as C
from quickhost import store_test_data, scrub_datetime

from .utilities import get_single_result_id, handle_client_error
from .AWSResource import AWSResourceBase

logger = logging.getLogger(__name__)


class KP(AWSResourceBase):
    """
    CRUD for ssh keys.
    """
    def __init__(self, app_name, profile, region):
        session = self._get_session(profile=profile, region=region)
        self.client = session.client('ec2')
        self.ec2 = session.resource('ec2')
        self.app_name = app_name

    def get_key_id(self) -> str:
        try:
            existing_key = self.client.describe_key_pairs(
                KeyNames=[
                    self.app_name
                ],
                DryRun=False,
                IncludePublicKey=True
            )
        except ClientError:
            return None
        return get_single_result_id(resource=existing_key, resource_type='KeyPair', plural=True)

    def _create_ssh_key_file(self, key_material: str, ssh_key_filepath) -> None:
        """
        Create ssh key .pem file or raise
        """
        tgt_file = Path(ssh_key_filepath) # will be absolute filepath from AWSApp._parse_make (get rid of Path)
        if tgt_file.exists():
            logger.critical("Existing keyfile found at '{}' - refusing to overwrite!".format(ssh_key_filepath))
            raise SystemExit(1)
        try:
            with tgt_file.open('w') as pemf:
                pemf.writelines(key_material)
                os.chmod(tgt_file.absolute(), 0o600)
            logger.debug(f"saved private key to file '{ssh_key_filepath}'")
        except Exception as e:
            logger.critical(f"Exception creating ssh keyfile: {e}", exc_info=True)
            raise SystemExit(1)


    def create(self, ssh_key_filepath=None) -> bool:
        """Make a new ec2 keypair named for app"""

        # ew
        # There will never be an existing keypair
        # This is (yet another) textbook example oa premature optimization
        existing_key_pair = self.describe()

        if existing_key_pair['key_id'] is not None:
            # NOTE: You can't retreive key material unless you are creating the key
            logger.error("EC2 key pair already exists in AWS (id={}, fingerprint={}, region={})".format(
                existing_key_pair['key_id'], existing_key_pair['key_fingerprint'], '@@@ uhhhh this is important...'))
            raise SystemExit(1)
        else:
            new_key = self.client.create_key_pair(
                KeyName=self.app_name,
                DryRun=False,
                KeyType='rsa',
                TagSpecifications=[
                    {
                        'ResourceType': 'key-pair',
                        'Tags': [
                            { 'Key': C.DEFAULT_APP_NAME, 'Value': self.app_name }, 
                            { 'Key': 'ssh_key_filepath', 'Value': ssh_key_filepath }, 
                        ]
                    },
                ],
            )
            self._create_ssh_key_file(new_key['KeyMaterial'], ssh_key_filepath)
            new_key_id = new_key['KeyPairId']
            new_key_fp = new_key['KeyFingerprint']
            del new_key

            return {
                'key_name': self.app_name,
                'key_filepath': ssh_key_filepath,
                'key_id': new_key_id,
                'key_fingerprint': new_key_fp,
            }

    def describe(self):
        rtn = {
            'key_id': None,
            'key_fingerprint': None,
            'ssh_key_filepath': None
        }
        try:
            existing_key = self.client.describe_key_pairs(
                KeyNames=[ self.app_name ],
                DryRun=False,
                IncludePublicKey=True
            )
            
            rtn['key_id'] = existing_key['KeyPairs'][0]['KeyPairId']
            rtn['key_fingerprint'] = existing_key['KeyPairs'][0]['KeyFingerprint']
            for t in existing_key['KeyPairs'][0]['Tags']:
                if t['Key'] == 'ssh_key_filepath':
                    rtn['ssh_key_filepath'] = t['Value']
            logger.debug("Describe keypairs: {}".format(rtn))
            # store_test_data(resource='AWSKeypair', action='describe_key_pairs', response_data=scrub_datetime(existing_key))
            return rtn
        except ClientError as e:
            code = e.__dict__['response']['Error']['Code']
            if code == 'InvalidKeyPair.NotFound':
                logger.debug(f"({code}): {e.operation_name}")
                rtn['key_id'] = None
                rtn['key_fingerprint'] = None
                return rtn
            else:
                logger.error(f"(Key Pair) Unhandled botocore client exception: ({code}): {e}")
                return rtn

    def windows_get_password(self, instance_id):
        """Return the unencrypted password for the Adminstrator user"""
        response = self.client.get_password_data(InstanceId=instance_id)
        pw_data = response['PasswordData']
        if pw_data == "":
            logger.error("Could not retrieve password data. It is possible that the password has not been generated and will be available within the next 15 minutes. You may retrieve the password with main.py aws describe {} --show-password".format(self.app_name))
            return "Try again later"

        with open(f"{self.app_name}.pem", 'rb') as pemf:
            privkey = serialization.load_pem_private_key(
                pemf.read(),
                password=None
            )
        return privkey.decrypt(
            base64.b64decode(pw_data),
            padding.PKCS1v15()
        ).decode('utf-8')

    def destroy(self) -> bool:
        key = self.describe()  # this should be passed into destroy but I'm le tired (and unpaid)
        try:
            if key['key_id'] is not None:
                del_key = self.client.delete_key_pair(
                    KeyPairId=key['key_id'],
                    DryRun=False
                )
                logger.debug("deleted EC2 key pair: {}".format(key['key_id']))
                store_test_data(resource='AWSKeyPair', action='delete_key_pair', response_data=del_key)
            else:
                logger.warning(f"No EC2 key pair for app '{self.app_name}' to delete")

            if key['ssh_key_filepath'] is not None:
                ssh_key_file = Path(key['ssh_key_filepath'])
                if ssh_key_file.exists():
                    ssh_key_file.unlink()
                    logger.debug(f"removed keyfile '{ssh_key_file.name}'")
                    return True
                else:
                    logger.warning(f"No ssh private key file to remove at '{ssh_key_file.absolute()}'")
                    return False
        except ClientError as e:
            handle_client_error(e)
            logger.error("failed to delete keypair for app '{}' (id={}): {}".format(self.app_name, key['key_id'], e))
            return False

    def update(self):
        """Not implemented"""
        pass


if __name__ == '__main__':
    import boto3
    c = boto3.client('ec2')
    kp = KP(client=c, app_name='asdf', ssh_key_filepath='.', dry_run=False )
    # print(json.dumps(kp.get_key_pair(),indent=2))
    # print(kp.destroy())
    # print(json.dumps(kp.create(),indent=2))
    print()
    print(json.dumps(kp.describe(), indent=2))
