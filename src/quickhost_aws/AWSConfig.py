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

from dataclasses import dataclass
from typing import NewType, List

"""
These are utility functions, types, etc.
This module should only import from the standard library.
"""

Region = NewType('Region', str)
Port = NewType('Port', int)
Cidr = NewType('Cidr', str)


@dataclass
class AWSHostConfig:
    app_name: str
    region: Region
    host_count: int


@dataclass
class AWSSgConfig:
    app_name: str
    region: Region
    vpc_id: str
    ports: List[Port]
    cidrs: List[Cidr]
