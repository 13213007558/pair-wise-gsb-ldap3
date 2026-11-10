"""
"""

# Created on 2026.11.10
#
# Author: Giovanni Cannata
#
# Copyright 2013 - 2025 Giovanni Cannata
#
# This file is part of ldap3.
#
# ldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ldap3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

from ..operation.search import parse_filter, compile_filter
from .controls import build_control


def assertion_control(search_filter, criticality=True):
    """Create an assertion control for a request, as per RFC 4528.
    When passed as a control to the controls parameter of an operation, the
    server performs the operation only if the assertion filter evaluates to
    TRUE against the target entry, otherwise the whole operation fails with
    assertionFailed (122). The filter is evaluated before any change is made.
    """
    compiled_filter = compile_filter(parse_filter(search_filter, None, True, False, None, False).elements[0])
    return build_control('1.3.6.1.1.12', criticality, compiled_filter)
