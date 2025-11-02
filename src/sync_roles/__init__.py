"""Sync Roles package."""

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

SELECT = Privilege.SELECT
INSERT = Privilege.INSERT
UPDATE = Privilege.UPDATE
DELETE = Privilege.DELETE
TRUNCATE = Privilege.TRUNCATE
REFERENCES = Privilege.REFERENCES
TRIGGER = Privilege.TRIGGER
CREATE = Privilege.CREATE
CONNECT = Privilege.CONNECT
TEMPORARY = Privilege.TEMPORARY
EXECUTE = Privilege.EXECUTE
USAGE = Privilege.USAGE
SET = Privilege.SET
ALTER_SYSTEM = Privilege.ALTER_SYSTEM
