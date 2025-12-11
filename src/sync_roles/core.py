"""Core orchestration logic for role synchronization.

This module contains the database-agnostic logic for syncing roles.
It uses the adapter pattern to delegate database-specific operations.
"""

import logging
import re
from collections.abc import Iterable
from typing import cast

from sync_roles.adapters.base import DatabaseAdapter
from sync_roles.adapters.postgres import PostgresAdapter
from sync_roles.models import DatabaseConnect
from sync_roles.models import DbObjectType
from sync_roles.models import Grant
from sync_roles.models import GrantOperation
from sync_roles.models import GrantOperationType
from sync_roles.models import Login
from sync_roles.models import Privilege
from sync_roles.models import PrivilegeRecord
from sync_roles.models import SchemaCreate
from sync_roles.models import SchemaOwnership
from sync_roles.models import SchemaUsage
from sync_roles.models import TableSelect

log = logging.getLogger(__name__)


def sync_roles(
    conn,
    role_name: str,
    grants: tuple[Grant, ...] = (),
    preserve_existing_grants_in_schemas: tuple[str, ...] = (),
    lock_key: int = 1,
):
    """Synchronize a database role's existence, memberships, logins, ownerships and ACLs.

    This function inspects the current state of the specified role in the connected
    database and applies changes so that the role matches the requested set of grants.

    Parameters
    ----------
    conn : SQLAlchemy Connection
        A SQLAlchemy connection with an engine of dialect `postgresql+psycopg` or
        `postgresql+psycopg2`. For SQLAlchemy < 2 `future=True` must be passed
        to its create_engine function.
    role_name : str
        The name of the role to synchronize.
    grants : tuple of grants
        A tuple of grants of all permissions that the role specified by the `role_name`
        should have. Anything not in this list will be automatically revoked.
    preserve_existing_grants_in_schemas : tuple of str
        A tuple of schema names. For each schema name `sync_roles` will leave any
        existing privileges granted on anything in the schema to `role_name` intact.
        This is useful in situations when the contents of the schemas are managed
        separately, outside of calls to `sync_roles`.

       A schema name being listed in `preserve_existing_grants_in_schemas` does
       not affect management of permissions on the the schema itself. In order
       for `role_name` to have privileges on these, they will have to be passed
       in via the `grants` parameter.
    lock_key : int
        The key for the advisory lock taken before changes are made. (defaults to 1).

    Returns:
    -------
    None

    Raises:
    ------
    ValueError
        If invalid input is provided (for example, more than one Login object in grants).
    RuntimeError
        If an available name for a helper ACL role cannot be found when creating helper roles.
    """
    log.info(f'Running sync_roles for {role_name!r}')
    _validate_grants(grants)
    adapter = _get_adapter(conn)
    with adapter.transaction():
        # NOTE: Instead of returning grants, return operations so we can include
        # the create role and schema ops at this stage. In phase 2 do extra
        # processing, which for postgres is the ACL stuff but might be different
        # in other DBs.
        valid_grants = _remove_invalid_grants(adapter, set(grants))
        proposed_permissions = _build_proposed_permissions(adapter, role_name, valid_grants)
        existing_permissions = adapter.get_existing_permissions(role_name, preserve_existing_grants_in_schemas)

        to_grant = proposed_permissions - existing_permissions
        to_revoke = existing_permissions - proposed_permissions
        role_to_create = not adapter.role_exists(role_name)

        if not to_grant and not to_revoke and not role_to_create:
            log.info('Existing state matches requested state. Exit.')
            return

        adapter.lock(lock_key)
        existing_permissions = adapter.get_existing_permissions(role_name, preserve_existing_grants_in_schemas)

        # calculate changes
        to_grant = proposed_permissions - existing_permissions
        to_revoke = existing_permissions - proposed_permissions

        # If both, grant and revoke for login only keep the grant as that overrides
        # the revoke and preserves the user password if the new grant has no password.
        grant_has = any(p for p in to_grant if p.privilege == Privilege.LOGIN)
        revoke_has = any(p for p in to_revoke if p.privilege == Privilege.LOGIN)
        if grant_has and revoke_has:
            to_revoke = {p for p in to_revoke if p.privilege != Privilege.LOGIN}

        # calculate create operations
        changes = _generate_creates(adapter, role_name, *to_grant)
        changes.extend(GrantOperation(GrantOperationType.REVOKE, permission) for permission in to_revoke)
        changes.extend(GrantOperation(GrantOperationType.GRANT, p) for p in to_grant)

        owners = _generate_owners(adapter, role_name, *to_grant, *to_revoke)
        owners.discard((adapter.get_current_user(),))
        # if role_to_create:
        #     owners.discard((role_name,))  # noqa: ERA001

        # Sort changes before applying them
        sorted_changes = sorted(changes, key=_sort_grant_operations)

        with adapter.temporary_grant_of(owners):
            for change in sorted_changes:
                log.info(f'Applying {change}')
                adapter.grant(change)


def drop_unused_roles(conn, lock_key: int = 1):
    """Drop ACL roles that are no longer in use."""
    adapter = _get_adapter(conn)

    adapter.drop_unused_roles(lock_key)


def _get_adapter(conn) -> DatabaseAdapter:
    """Factory function to get the appropriate adapter."""
    dialect = conn.engine.dialect.name

    adapters: dict[str, type[DatabaseAdapter]] = {
        'postgresql': PostgresAdapter,
    }

    adapter_class = adapters.get(dialect)
    if not adapter_class:
        raise ValueError(f'Unsupported database dialect: {dialect}')

    return adapter_class(conn)


def _validate_grants(grants: Iterable[Grant]):
    """Validate the grants provided.

    Remove any grants that are invalid and raise errors if necessary. Grants can
    be invalid for various reasons, such as having more than one Login object or
    referencing a database that doesn't exist.

    Args:
        adapter (DatabaseAdapter): The database adapter to use for validation.
        grants (tuple): Tuple of grant objects.

    Raises:
        ValueError: if invalid grants are found.
    """
    # Input validation
    if count := sum(1 for grant in grants if isinstance(grant, Login)) > 1:
        raise ValueError(f'At most 1 Login object can be passed via the grants parameter. Got {count}.')


def _remove_invalid_grants(adapter: DatabaseAdapter, grants: set[Grant]) -> set[Grant]:
    """Validate the grants provided.

    Remove any grants that are invalid and raise errors if necessary. Grants can
    be invalid for various reasons, such as referencing a database that doesn't
    exist.

    Args:
        adapter (DatabaseAdapter): The database adapter to use for validation.
        grants (set[Grant]): Set of grant objects.

    Returns:
        set[Grant]: The grants without any that were removed because of non-existing
            databases or schemas.
    """
    db_grants = {grant for grant in grants if isinstance(grant, DatabaseConnect)}
    existing_dbs = set(adapter.get_databases(*(grant.database_name for grant in db_grants)))
    db_grants_to_ignore = {g for g in db_grants if g.database_name not in existing_dbs}

    schema_grants = {grant for grant in grants if isinstance(grant, SchemaUsage | SchemaCreate)}
    existing_schemas = set(adapter.get_schemas(*(grant.schema_name for grant in schema_grants)))
    ownership_schemas = {grant.schema_name for grant in grants if isinstance(grant, SchemaOwnership)}
    schema_grants_to_ignore = {g for g in schema_grants if g.schema_name not in existing_schemas | ownership_schemas}

    implied_schema_grants: set[SchemaCreate | SchemaUsage] = set()
    for grant in (grant for grant in grants if isinstance(grant, SchemaOwnership)):
        implied_schema_grants.add(SchemaCreate(grant.schema_name, direct=True))
        implied_schema_grants.add(SchemaUsage(grant.schema_name, direct=True))

    table_grants = {g for g in grants if isinstance(g, TableSelect)}
    existing_schemas = set(adapter.get_schemas(*(grant.schema_name for grant in table_grants)))
    expanded_tb_grants = _expand_table_regexp(adapter, {g for g in table_grants if g.schema_name in existing_schemas})
    existing_tables = set(adapter.get_tables(*((g.schema_name, cast(str, g.table_name)) for g in expanded_tb_grants)))
    table_grants_to_ignore = {g for g in expanded_tb_grants if (g.schema_name, g.table_name) not in existing_tables}

    if db_grants_to_ignore or schema_grants_to_ignore or table_grants_to_ignore:
        log.warning(
            'Some grants are being ignored due to non-existing databases, schemas, '
            f'or tables: {db_grants_to_ignore | schema_grants_to_ignore | table_grants_to_ignore}',
        )

    grants -= db_grants_to_ignore
    grants -= schema_grants_to_ignore
    grants |= implied_schema_grants
    grants -= table_grants  # remove all table grants and then add the ones we keep
    grants |= expanded_tb_grants - table_grants_to_ignore

    return grants


def _expand_table_regexp(adapter: DatabaseAdapter, grants: set[TableSelect]) -> set[TableSelect]:
    """For any Table grants, expand the regexp into the matching table names.

    Args:
        adapter (DatabaseAdapter): The database adapter to use for validation.
        grants (set[Grant]): Set of grant objects.

    Returns:
        set[Grant]: The grants but replacing the Table grants that use regexp with
            grants that contain the actual table names that match the regexp.
    """
    table_selects_regex_name = {grant for grant in grants if isinstance(grant.table_name, re.Pattern)}
    expanded_grants = {
        TableSelect(grant.schema_name, table_name, direct=grant.direct)
        for grant in table_selects_regex_name
        for table_name in adapter.tables_in_schema_matching_regex(grant.schema_name, grant.table_name)
    }
    if table_selects_regex_name:
        log.debug(
            f'Replaced Table grants that use regular expressions with their matching tables.'
            f'Regexp grants: {table_selects_regex_name}, grants for matching tables: {expanded_grants}',
        )
    table_grants = grants - table_selects_regex_name
    table_grants |= expanded_grants
    return table_grants


def _build_proposed_permissions(
    adapter: DatabaseAdapter,
    role_name: str,
    grants: Iterable[Grant],
) -> set[PrivilegeRecord]:
    permissions: set[PrivilegeRecord] = set()
    for grant in grants:
        permissions.update(adapter.build_proposed_permission(role_name, grant))
    return permissions


def _generate_creates(adapter: DatabaseAdapter, role_name: str, *privileges: PrivilegeRecord):
    schema_privileges = [
        privilege
        for privilege in privileges
        if privilege.object_type == DbObjectType.SCHEMA and privilege.privilege == Privilege.OWN
    ]
    existing_schemas = adapter.get_schemas(*(cast(str, privilege.object_name) for privilege in schema_privileges))

    schemas = [
        GrantOperation(GrantOperationType.CREATE, p)
        for p in schema_privileges
        if cast(str, p.object_name) not in existing_schemas
    ]

    role_privileges = [privilege for privilege in privileges if privilege.privilege == Privilege.ROLE_MEMBERSHIP]

    existing_roles = adapter.get_roles(
        role_name,
        *(cast(str, privilege.object_name) for privilege in role_privileges),
    )

    roles = [
        GrantOperation(GrantOperationType.CREATE, p)
        for p in role_privileges
        if cast(str, p.object_name) not in existing_roles
    ]

    if adapter.role_exists(role_name) is False:
        adapter.grant(
            GrantOperation(
                GrantOperationType.CREATE,
                PrivilegeRecord(DbObjectType.ROLE, role_name, Privilege.ROLE_MEMBERSHIP),
            ),
        )

    return [*schemas, *roles]


def _generate_owners(adapter: DatabaseAdapter, role_name: str, *privileges: PrivilegeRecord):
    database_owners = adapter.get_db_owners(
        *(cast(str, p.object_name) for p in privileges if p.object_type == DbObjectType.DATABASE),
    )
    schemas = [cast(str, p.object_name) for p in privileges if p.object_type == DbObjectType.SCHEMA]
    schema_owners = adapter.get_schema_owners(*schemas)
    tables = [cast(tuple[str, str], p.object_name) for p in privileges if p.object_type == DbObjectType.TABLE]
    table_owners = adapter.get_table_owners(*tables)
    table_schema_owners = adapter.get_schema_owners(*(schema for schema, _ in tables))

    return {
        *database_owners,
        *schema_owners,
        *table_owners,
        *table_schema_owners,
        *([(role_name,)] if schemas else []),
    }


def _sort_grant_operations(op: GrantOperation) -> tuple:
    """Create a sort key for GrantOperation2 objects.

    Sort order:
    1. Operation Type: REVOKE, CREATE, GRANT
    2. For GRANTs, Object Type: cluster, schema, role
    3. For GRANTs on schemas, Privilege: OWN, CREATE, USAGE
    """
    op_type_key, obj_type_key, priv_key = 0, 0, 0

    op_type_order = {GrantOperationType.REVOKE: 0, GrantOperationType.CREATE: 1, GrantOperationType.GRANT: 2}
    op_type_key = op_type_order.get(op.type_, 99)

    if op.type_ == GrantOperationType.GRANT:
        obj_type_order = {DbObjectType.DATABASE: 0, DbObjectType.SCHEMA: 1, DbObjectType.ROLE: 2}
        obj_type_key = obj_type_order.get(op.privilege.object_type, 99)

    if op.privilege.object_type == DbObjectType.SCHEMA:
        schema_priv_order = {Privilege.OWN: 0, Privilege.CREATE: 1, Privilege.USAGE: 2}
        priv_key = schema_priv_order.get(op.privilege.privilege, 99)

    return (op_type_key, obj_type_key, priv_key)
