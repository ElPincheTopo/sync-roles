"""sync_roles - Database role synchronization library.

A Python library for declaratively managing database users and their permissions.
Currently supports PostgreSQL with planned support for ClickHouse.
"""

from sync_roles.core import drop_unused_roles
from sync_roles.core import sync_roles
from sync_roles.models import DatabaseConnect
from sync_roles.models import Login
from sync_roles.models import Privilege
from sync_roles.models import RoleMembership
from sync_roles.models import SchemaCreate
from sync_roles.models import SchemaOwnership
from sync_roles.models import SchemaUsage
from sync_roles.models import TableSelect

__all__ = [
    'DatabaseConnect',
    'Login',
    'Privilege',
    'RoleMembership',
    'SchemaCreate',
    'SchemaOwnership',
    'SchemaUsage',
    'TableSelect',
    'drop_unused_roles',
    'sync_roles',
]
