"""Core orchestration logic for role synchronization.

This module contains the database-agnostic logic for syncing roles.
It uses the adapter pattern to delegate database-specific operations.
"""

import logging
import re
from collections.abc import Iterable
from datetime import datetime
from typing import cast

from sync_roles.adapters.base import DatabaseAdapter
from sync_roles.adapters.postgres import PostgresAdapter
from sync_roles.models import KNOWN_PRIVILEGES
from sync_roles.models import SCHEMA
from sync_roles.models import TABLE_LIKE
from sync_roles.models import DatabaseConnect
from sync_roles.models import Grant
from sync_roles.models import GrantOperation
from sync_roles.models import GrantOperationType
from sync_roles.models import Login
from sync_roles.models import Privilege
from sync_roles.models import RoleMembership
from sync_roles.models import SchemaCreate
from sync_roles.models import SchemaGrant
from sync_roles.models import SchemaOwnership
from sync_roles.models import SchemaUsage
from sync_roles.models import TableSelect

log = logging.getLogger(__name__)


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
    _validate_grants(grants)
    adapter = _get_adapter(conn)

    with adapter.transaction():
        # NOTE: Instead of returning grants, return operations so we can include
        # the create role and schema ops at this stage. In phase 2 do extra
        # processing, which for postgres is the ACL stuff but might be different
        # in other DBs.
        valid_grants = _remove_invalid_grants(adapter, set(grants))
        state = _get_current_state(adapter, valid_grants)

        role_to_create = not adapter.get_role_exists(role_name)
        db_oid = adapter.get_database_oid()

        # Phase 2: Compare states and plan what to do
        changes = _compare_and_plan(
            adapter,
            role_name,
            role_to_create,
            preserve_existing_grants_in_schemas,
            state,
            db_oid,
        )

        # Phase 3: Exit if nothing needs to be done
        if _check_early_exit(role_to_create, changes):
            return

        # Phase 4: Lock and re-check
        role_to_create, current_user, changes = _lock_and_recheck(
            adapter,
            role_name,
            lock_key,
            preserve_existing_grants_in_schemas,
            state,
            db_oid,
        )

        # Phase 5: Apply changes
        _apply_changes(
            adapter,
            role_name,
            changes,
            state,
            current_user,
            set(adapter.get_schemas(*(grant.schema_name for grant in valid_grants if isinstance(grant, SchemaGrant)))),
            db_oid,
            preserve_existing_grants_in_schemas,
        )


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


def _get_current_state(
    adapter: DatabaseAdapter,
    grants: set[Grant],
):
    """Phase 1: Get current state without lock.

    Returns a dictionary containing:
    - Filtered grants by type
    - Names of entities that exist
    - Whether the role needs to be created
    """
    # Split grants by their type
    schema_usages_indirect = tuple(grant for grant in grants if isinstance(grant, SchemaUsage) and not grant.direct)
    schema_usages_direct = tuple(grant for grant in grants if isinstance(grant, SchemaUsage) and grant.direct)
    schema_creates_indirect = tuple(grant for grant in grants if isinstance(grant, SchemaCreate) and not grant.direct)
    schema_creates_direct = tuple(grant for grant in grants if isinstance(grant, SchemaCreate) and grant.direct)
    schema_ownerships = tuple(grant for grant in grants if isinstance(grant, SchemaOwnership))
    table_selects_indirect = tuple(grant for grant in grants if isinstance(grant, TableSelect) and not grant.direct)
    table_selects_direct = tuple(grant for grant in grants if isinstance(grant, TableSelect) and grant.direct)
    role_memberships = tuple(grant for grant in grants if isinstance(grant, RoleMembership))
    database_connects = tuple(grant for grant in grants if isinstance(grant, DatabaseConnect))
    logins = tuple(grant for grant in grants if isinstance(grant, Login))

    return {
        'logins': logins,
        'database_connects': database_connects,
        'schema_usages_indirect': schema_usages_indirect,
        'schema_usages_direct': schema_usages_direct,
        'schema_creates_indirect': schema_creates_indirect,
        'schema_creates_direct': schema_creates_direct,
        'schema_ownerships': schema_ownerships,
        'table_selects_indirect': table_selects_indirect,
        'table_selects_direct': table_selects_direct,
        'role_memberships': role_memberships,
        'tables_that_exist': tuple(
            adapter.get_tables(
                *((g.schema_name, cast(str, g.table_name)) for g in {*table_selects_indirect, *table_selects_direct}),
            ),
        ),
    }


def _compare_and_plan(
    adapter: DatabaseAdapter,
    role_name: str,
    role_to_create: bool,
    preserve_existing_grants_in_schemas: tuple[str, ...],
    state: dict,
    db_oid: str,
):
    """Phase 2: Compare states and plan what to do.

    Returns a dictionary of changes to be made.
    """
    # Get all existing permissions
    existing_permissions = (
        adapter.get_existing_permissions(role_name, preserve_existing_grants_in_schemas) if not role_to_create else []
    )

    # Prepare names for ACL role lookups
    all_database_connect_names = tuple(grant.database_name for grant in state['database_connects'])
    all_schema_usage_indirect_names = tuple(grant.schema_name for grant in state['schema_usages_indirect'])
    all_schema_create_indirect_names = tuple(grant.schema_name for grant in state['schema_creates_indirect'])
    all_table_select_indirect_names = tuple(
        (grant.schema_name, grant.table_name) for grant in state['table_selects_indirect']
    )

    # Compare and determine changes
    return _determine_changes(
        existing_permissions=existing_permissions,
        table_selects_direct=state['table_selects_direct'],
        schema_usages_direct=state['schema_usages_direct'],
        schema_creates_direct=state['schema_creates_direct'],
        schema_ownerships=state['schema_ownerships'],
        role_memberships=state['role_memberships'],
        database_connects=state['database_connects'],
        schema_usages_indirect=state['schema_usages_indirect'],
        schema_creates_indirect=state['schema_creates_indirect'],
        table_selects_indirect=state['table_selects_indirect'],
        logins=state['logins'],
        db_oid=db_oid,
        adapter=adapter,
        all_database_connect_names=all_database_connect_names,
        all_schema_usage_indirect_names=all_schema_usage_indirect_names,
        all_schema_create_indirect_names=all_schema_create_indirect_names,
        all_table_select_indirect_names=all_table_select_indirect_names,
    )


def _check_early_exit(role_to_create: bool, changes: dict) -> bool:
    """Phase 3: Check if we can exit early (nothing needs to be done).

    Returns True if we should exit early, False otherwise.
    """
    return (
        not role_to_create
        and not changes['database_connect_roles_to_create']
        and not changes['schema_usage_roles_to_create']
        and not changes['schema_create_roles_to_create']
        and not changes['table_select_roles_to_create']
        and not changes['database_connect_memberships_to_grant']
        and not changes['schema_usage_memberships_to_grant']
        and not changes['table_select_memberships_to_grant']
        and not changes['role_memberships_to_grant']
        and not changes['memberships_to_revoke']
        and not changes['logins_to_grant']
        and not changes['logins_to_revoke']
        and not changes['schema_ownerships_to_revoke']
        and not changes['schema_ownerships_to_grant']
        and not changes['acl_table_permissions_to_grant']
        and not changes['acl_schema_permissions_to_grant']
        and not changes['acl_table_permissions_to_revoke']
        and not changes['acl_schema_permissions_to_revoke']
    )


def _lock_and_recheck(
    adapter: DatabaseAdapter,
    role_name: str,
    lock_key: int,
    preserve_existing_grants_in_schemas: tuple[str, ...],
    state: dict,
    db_oid: str,
) -> tuple[bool, str, dict]:
    """Phase 4: Lock and re-check state.

    Returns a tuple of (role_to_create, current_user, changes).
    """
    adapter.lock(lock_key)

    # Make the role if we need to
    role_to_create = not adapter.get_role_exists(role_name)
    if role_to_create:
        adapter.create_role(role_name)

    # The current user - if we need to change ownership or grant directly on an object
    # we need to check if the current user is the owner, and grant the owner to the user if not
    current_user = adapter.get_current_user()

    # Get all existing permissions again (post-lock)
    existing_permissions = adapter.get_existing_permissions(role_name, preserve_existing_grants_in_schemas)

    # Prepare names for ACL role lookups
    all_database_connect_names = tuple(grant.database_name for grant in state['database_connects'])
    all_schema_usage_indirect_names = tuple(grant.schema_name for grant in state['schema_usages_indirect'])
    all_schema_create_indirect_names = tuple(grant.schema_name for grant in state['schema_creates_indirect'])
    all_table_select_indirect_names = tuple(
        (grant.schema_name, grant.table_name) for grant in state['table_selects_indirect']
    )

    # Re-determine changes (using the same helper function)
    changes = _determine_changes(
        existing_permissions=existing_permissions,
        table_selects_direct=state['table_selects_direct'],
        schema_usages_direct=state['schema_usages_direct'],
        schema_creates_direct=state['schema_creates_direct'],
        schema_ownerships=state['schema_ownerships'],
        role_memberships=state['role_memberships'],
        database_connects=state['database_connects'],
        schema_usages_indirect=state['schema_usages_indirect'],
        schema_creates_indirect=state['schema_creates_indirect'],
        table_selects_indirect=state['table_selects_indirect'],
        logins=state['logins'],
        db_oid=db_oid,
        adapter=adapter,
        all_database_connect_names=all_database_connect_names,
        all_schema_usage_indirect_names=all_schema_usage_indirect_names,
        all_schema_create_indirect_names=all_schema_create_indirect_names,
        all_table_select_indirect_names=all_table_select_indirect_names,
    )

    return role_to_create, current_user, changes


def _apply_changes(
    adapter: DatabaseAdapter,
    role_name: str,
    changes: dict,
    state: dict,
    current_user: str,
    schemas_that_exist: set,
    db_oid: str,
    preserve_existing_grants_in_schemas: tuple[str, ...],
):
    """Phase 5: Apply all changes."""
    # Get SQL helpers from adapter
    sql_grants = adapter.get_sql_grants()
    sql_object_types = adapter.get_sql_object_types()

    # Gather all changes to be made to objects - the current user must be owner of them
    tables_needing_ownerships = (
        changes['table_select_roles_to_create']
        + tuple((perm[1], perm[2]) for perm in changes['acl_table_permissions_to_revoke'])
        + tuple((perm[1], perm[2]) for perm in changes['acl_table_permissions_to_grant'])
    )
    schemas_needing_ownership = (
        tuple(schema_ownership.schema_name for schema_ownership in changes['schema_ownerships_to_revoke'])
        + tuple(schema_ownership.schema_name for schema_ownership in changes['schema_ownerships_to_grant'])
        + tuple(perm[1] for perm in changes['acl_schema_permissions_to_revoke'])
        + tuple(perm[1] for perm in changes['acl_schema_permissions_to_grant'])
        + changes['schema_usage_roles_to_create']
        + tuple(schema_name for schema_name, table_name in tables_needing_ownerships)
    )
    databases_needing_ownerships = changes['database_connect_roles_to_create']

    database_owners = adapter.get_owners('pg_database', 'datdba', 'datname', databases_needing_ownerships)
    schema_owners = adapter.get_owners('pg_namespace', 'nspowner', 'nspname', schemas_needing_ownership)
    table_owners = adapter.get_owners_in_schema(
        'pg_class',
        'relowner',
        'relnamespace',
        'relname',
        tables_needing_ownerships,
    )

    # ... and the main role we're dealing with if necessary (only needed if giving ownership)
    role_if_needed = {(role_name,)} if changes['schema_ownerships_to_grant'] else set()

    # ... and temporarily grant the current user them
    all_owners = role_if_needed | set(database_owners) | set(schema_owners) | set(table_owners)
    roles_to_grant = tuple(all_owners - {(current_user,)})

    with adapter.temporary_grant_of(roles_to_grant):
        # Grant or revoke schema ownerships
        for schema_ownership in changes['schema_ownerships_to_revoke']:
            adapter.revoke_ownership(sql_object_types[SchemaUsage], role_name, schema_ownership.schema_name)
        for schema_ownership in changes['schema_ownerships_to_grant']:
            if schema_ownership.schema_name not in schemas_that_exist:
                adapter.create_schema(schema_ownership.schema_name)
            adapter.grant_ownership(sql_object_types[SchemaUsage], role_name, schema_ownership.schema_name)

        # Create all ACL roles using helper function
        database_connect_roles, schema_usage_roles, schema_create_roles, table_select_roles = _create_acl_roles(
            adapter,
            changes,
            sql_grants,
            sql_object_types,
            db_oid,
        )

        # Re-check existing permissions because granting ownership by default gives the owner full permissions
        existing_permissions = adapter.get_existing_permissions(role_name, preserve_existing_grants_in_schemas)

        # Re-calculate ACL permissions after ownership changes
        acl_changes = _determine_acl_changes(
            existing_permissions=existing_permissions,
            table_selects_direct=state['table_selects_direct'],
            schema_usages_direct=state['schema_usages_direct'],
            schema_creates_direct=state['schema_creates_direct'],
        )

        # Revoke direct permissions on tables and schemas
        for perm in acl_changes['acl_table_permissions_to_revoke']:
            adapter.grant(
                GrantOperation(
                    type_=GrantOperationType.REVOKE,
                    privilege=Privilege[perm[0]],
                    grant=None,
                    object_type='TABLE',
                    object_name=(perm[1], perm[2]),
                    role_name=role_name,
                ),
            )
        for perm in acl_changes['acl_schema_permissions_to_revoke']:
            adapter.grant(
                GrantOperation(
                    type_=GrantOperationType.REVOKE,
                    privilege=Privilege[perm[0]],
                    grant=None,
                    object_type='SCHEMA',
                    object_name=(perm[1],),
                    role_name=role_name,
                ),
            )

        # Grant direct permissions on tables and schemas
        for perm in acl_changes['acl_table_permissions_to_grant']:
            adapter.grant(
                GrantOperation(
                    type_=GrantOperationType.GRANT,
                    privilege=Privilege[perm[0]],
                    grant=None,
                    object_type='TABLE',
                    object_name=(perm[1], perm[2]),
                    role_name=role_name,
                ),
            )
        for perm in acl_changes['acl_schema_permissions_to_grant']:
            adapter.grant(
                GrantOperation(
                    type_=GrantOperationType.GRANT,
                    privilege=Privilege[perm[0]],
                    grant=None,
                    object_type='SCHEMA',
                    object_name=(perm[1],),
                    role_name=role_name,
                ),
            )

    # Grant login if we need to
    existing_permissions = adapter.get_existing_permissions(role_name, preserve_existing_grants_in_schemas)
    login_row = next(
        (perm for perm in existing_permissions if perm['on'] == 'cluster' and perm['privilege_type'] == 'LOGIN'),
        None,
    )
    can_login = login_row is not None
    valid_until = (
        datetime.strptime(login_row['name_1'], '%Y-%m-%dT%H:%M:%S.%f%z')
        if login_row is not None and login_row['name_1'] is not None
        else None
    )
    logins_to_grant = state['logins'] and (
        not can_login or valid_until != state['logins'][0].valid_until or state['logins'][0].password is not None
    )
    logins_to_revoke = not state['logins'] and can_login

    if logins_to_grant:
        adapter.grant_login(role_name, state['logins'][0])
    if logins_to_revoke:
        adapter.revoke_login(role_name)

    # Grant memberships if we need to
    memberships = {
        perm['name_1'] for perm in existing_permissions if perm['on'] == 'role' and perm['privilege_type'] == 'MEMBER'
    }
    database_connect_memberships_to_grant = tuple(
        role for role in database_connect_roles.values() if role not in memberships
    )
    table_select_memberships_to_grant = tuple(role for role in table_select_roles.values() if role not in memberships)
    schema_usage_memberships_to_grant = tuple(role for role in schema_usage_roles.values() if role not in memberships)
    schema_create_memberships_to_grant = tuple(role for role in schema_create_roles.values() if role not in memberships)
    role_memberships_to_grant = tuple(
        role_membership for role_membership in state['role_memberships'] if role_membership.role_name not in memberships
    )

    for membership in role_memberships_to_grant:
        if not adapter.get_role_exists(membership.role_name):
            adapter.create_role(membership.role_name)

    adapter.grant_memberships(
        database_connect_memberships_to_grant
        + schema_usage_memberships_to_grant
        + schema_create_memberships_to_grant
        + table_select_memberships_to_grant
        + tuple(membership.role_name for membership in state['role_memberships']),
        role_name,
    )

    # Revoke memberships if we need to
    memberships_to_revoke = (
        memberships
        - {role_membership.role_name for role_membership in state['role_memberships']}
        - set(database_connect_roles.values())
        - set(schema_usage_roles.values())
        - set(schema_create_roles.values())
        - set(table_select_roles.values())
    )
    adapter.revoke_memberships(memberships_to_revoke, role_name)


def _create_acl_roles(
    adapter: DatabaseAdapter,
    changes: dict,
    sql_grants: dict,
    sql_object_types: dict,
    db_oid: str,
) -> tuple[dict, dict, dict, dict]:
    """Create ACL roles for database connects, schema usage/create, and table select.

    Returns tuple of (database_connect_roles, schema_usage_roles, schema_create_roles, table_select_roles).
    """
    acl_role_configs = [
        {
            'roles_dict': changes['database_connect_roles'],
            'to_create': changes['database_connect_roles_to_create'],
            'role_prefix': '_pgsr_global_database_connect_',
            'privilege': Privilege.CONNECT,
            'object_type': DatabaseConnect,
        },
        {
            'roles_dict': changes['schema_usage_roles'],
            'to_create': changes['schema_usage_roles_to_create'],
            'role_prefix': f'_pgsr_local_{db_oid}_schema_usage_',
            'privilege': Privilege.USAGE,
            'object_type': SchemaUsage,
        },
        {
            'roles_dict': changes['schema_create_roles'],
            'to_create': changes['schema_create_roles_to_create'],
            'role_prefix': f'_pgsr_local_{db_oid}_schema_create_',
            'privilege': Privilege.CREATE,
            'object_type': SchemaCreate,
        },
        {
            'roles_dict': changes['table_select_roles'],
            'to_create': changes['table_select_roles_to_create'],
            'role_prefix': f'_pgsr_local_{db_oid}_table_select_',
            'privilege': Privilege.SELECT,
            'object_type': TableSelect,
        },
    ]

    for config in acl_role_configs:
        for entity_name in config['to_create']:
            acl_role = adapter.get_available_acl_role(config['role_prefix'])
            adapter.create_role(acl_role)
            # Convert entity_name to tuple format expected by adapter.grant
            entity_tuple = entity_name if isinstance(entity_name, tuple) else (entity_name,)
            adapter.grant(
                GrantOperation(
                    type_=GrantOperationType.GRANT,
                    privilege=config['privilege'],
                    grant=None,
                    object_type=sql_object_types[config['object_type']],
                    object_name=entity_tuple,
                    role_name=acl_role,
                ),
            )

            config['roles_dict'][entity_name] = acl_role

    return (
        changes['database_connect_roles'],
        changes['schema_usage_roles'],
        changes['schema_create_roles'],
        changes['table_select_roles'],
    )


def _determine_changes(
    existing_permissions,
    table_selects_direct,
    schema_usages_direct,
    schema_creates_direct,
    schema_ownerships,
    role_memberships,
    database_connects,
    schema_usages_indirect,
    schema_creates_indirect,
    table_selects_indirect,
    logins,
    db_oid,
    adapter,
    all_database_connect_names,
    all_schema_usage_indirect_names,
    all_schema_create_indirect_names,
    all_table_select_indirect_names,
):
    """Determine what changes need to be made.

    This helper function avoids code duplication between the initial check and post-lock recheck.
    """
    # ACL permissions on tables and schemas
    acl_changes = _determine_acl_changes(
        existing_permissions,
        table_selects_direct,
        schema_usages_direct,
        schema_creates_direct,
    )

    # ACL-equivalent roles
    database_connect_roles = adapter.get_acl_roles(
        'CONNECT',
        'pg_database',
        'datname',
        'datacl',
        '\\_pgsr\\_global\\_database\\_connect\\_%',
        all_database_connect_names,
    )
    database_connect_roles_to_create = _keys_with_none_value(database_connect_roles)

    schema_usage_roles = adapter.get_acl_roles(
        'USAGE',
        'pg_namespace',
        'nspname',
        'nspacl',
        f'\\_pgsr\\_local\\_{db_oid}_\\schema\\_usage\\_%',
        all_schema_usage_indirect_names,
    )
    schema_usage_roles_to_create = _keys_with_none_value(schema_usage_roles)

    schema_create_roles = adapter.get_acl_roles(
        'CREATE',
        'pg_namespace',
        'nspname',
        'nspacl',
        f'\\_pgsr\\_local\\_{db_oid}_\\schema\\_create\\_%',
        all_schema_create_indirect_names,
    )
    schema_create_roles_to_create = _keys_with_none_value(schema_create_roles)

    table_select_roles = adapter.get_acl_roles_in_schema(
        'SELECT',
        'pg_class',
        'relname',
        'relacl',
        'relnamespace',
        f'\\_pgsr\\_local\\_{db_oid}_\\table\\_select\\_%',
        all_table_select_indirect_names,
    )
    table_select_roles_to_create = _keys_with_none_value(table_select_roles)

    # Ownerships to grant and revoke
    schema_ownerships_that_exist = tuple(
        SchemaOwnership(perm['name_1'])
        for perm in existing_permissions
        if perm['on'] == 'schema' and perm['privilege_type'] == 'OWNER'
    )
    schema_ownerships_to_revoke = tuple(
        schema_ownership
        for schema_ownership in schema_ownerships_that_exist
        if schema_ownership not in schema_ownerships
    )
    schema_ownerships_to_grant = tuple(
        schema_ownership
        for schema_ownership in schema_ownerships
        if schema_ownership not in schema_ownerships_that_exist
    )

    # And any memberships of the database connect roles or explicitly requested role memberships
    memberships = {
        perm['name_1'] for perm in existing_permissions if perm['on'] == 'role' and perm['privilege_type'] == 'MEMBER'
    }
    database_connect_memberships_to_grant = tuple(
        role for role in database_connect_roles.values() if role not in memberships
    )
    schema_usage_memberships_to_grant = tuple(role for role in schema_usage_roles.values() if role not in memberships)
    schema_create_memberships_to_grant = tuple(role for role in schema_create_roles.values() if role not in memberships)
    table_select_memberships_to_grant = tuple(role for role in table_select_roles.values() if role not in memberships)
    role_memberships_to_grant = tuple(
        role_membership for role_membership in role_memberships if role_membership.role_name not in memberships
    )

    # And if the role can login / its login status is to be changed
    login_row = next(
        (perm for perm in existing_permissions if perm['on'] == 'cluster' and perm['privilege_type'] == 'LOGIN'),
        None,
    )
    can_login = login_row is not None
    valid_until = (
        datetime.strptime(login_row['name_1'], '%Y-%m-%dT%H:%M:%S.%f%z')
        if login_row is not None and login_row['name_1'] is not None
        else None
    )
    logins_to_grant = logins and (
        not can_login or valid_until != logins[0].valid_until or logins[0].password is not None
    )
    logins_to_revoke = not logins and can_login

    # And any memberships to revoke
    memberships_to_revoke = (
        memberships
        - {role_membership.role_name for role_membership in role_memberships}
        - set(database_connect_roles.values())
        - set(table_select_roles.values())
        - set(schema_usage_roles.values())
        - set(schema_create_roles.values())
    )

    return {
        'database_connect_roles': database_connect_roles,
        'database_connect_roles_to_create': database_connect_roles_to_create,
        'schema_usage_roles': schema_usage_roles,
        'schema_usage_roles_to_create': schema_usage_roles_to_create,
        'schema_create_roles': schema_create_roles,
        'schema_create_roles_to_create': schema_create_roles_to_create,
        'table_select_roles': table_select_roles,
        'table_select_roles_to_create': table_select_roles_to_create,
        'database_connect_memberships_to_grant': database_connect_memberships_to_grant,
        'schema_usage_memberships_to_grant': schema_usage_memberships_to_grant,
        'table_select_memberships_to_grant': table_select_memberships_to_grant,
        'role_memberships_to_grant': role_memberships_to_grant,
        'memberships_to_revoke': memberships_to_revoke,
        'logins_to_grant': logins_to_grant,
        'logins_to_revoke': logins_to_revoke,
        'schema_ownerships_to_revoke': schema_ownerships_to_revoke,
        'schema_ownerships_to_grant': schema_ownerships_to_grant,
        'acl_table_permissions_to_grant': acl_changes['acl_table_permissions_to_grant'],
        'acl_schema_permissions_to_grant': acl_changes['acl_schema_permissions_to_grant'],
        'acl_table_permissions_to_revoke': acl_changes['acl_table_permissions_to_revoke'],
        'acl_schema_permissions_to_revoke': acl_changes['acl_schema_permissions_to_revoke'],
    }


def _determine_acl_changes(existing_permissions, table_selects_direct, schema_usages_direct, schema_creates_direct):
    """Determine what ACL changes need to be made.

    This helper function is used in multiple places to avoid duplication.
    """

    def get_acl_rows(permissions, matching_on):
        return tuple(
            row for row in permissions if row['on'] in matching_on and row['privilege_type'] in KNOWN_PRIVILEGES
        )

    # Real ACL permissions on tables
    acl_table_permissions_tuples = tuple(
        (row['privilege_type'], row['name_1'], row['name_2']) for row in get_acl_rows(existing_permissions, TABLE_LIKE)
    )
    acl_table_permissions_set = set(acl_table_permissions_tuples)
    table_selects_direct_tuples = tuple(
        ('SELECT', table_select.schema_name, table_select.table_name) for table_select in table_selects_direct
    )
    table_selects_direct_set = set(table_selects_direct_tuples)
    acl_table_permissions_to_revoke = tuple(
        row for row in acl_table_permissions_tuples if row not in table_selects_direct_set
    )
    acl_table_permissions_to_grant = tuple(
        row for row in table_selects_direct_tuples if row not in acl_table_permissions_set
    )

    # Real ACL permissions on schemas
    acl_schema_permissions_tuples = tuple(
        (row['privilege_type'], row['name_1']) for row in get_acl_rows(existing_permissions, SCHEMA)
    )
    acl_schema_permissions_set = set(acl_schema_permissions_tuples)
    schema_direct_tuples = tuple(('USAGE', schema_usage.schema_name) for schema_usage in schema_usages_direct) + tuple(
        ('CREATE', schema_create.schema_name) for schema_create in schema_creates_direct
    )
    schema_direct_set = set(schema_direct_tuples)
    acl_schema_permissions_to_revoke = tuple(
        row for row in acl_schema_permissions_tuples if row not in schema_direct_tuples
    )
    acl_schema_permissions_to_grant = tuple(
        row for row in schema_direct_tuples if row not in acl_schema_permissions_set
    )

    return {
        'acl_table_permissions_to_revoke': acl_table_permissions_to_revoke,
        'acl_table_permissions_to_grant': acl_table_permissions_to_grant,
        'acl_schema_permissions_to_revoke': acl_schema_permissions_to_revoke,
        'acl_schema_permissions_to_grant': acl_schema_permissions_to_grant,
    }


def _keys_with_none_value(d):
    """Return tuple of keys from dictionary where value is None."""
    return tuple(key for key, value in d.items() if value is None)


def _without_duplicates_preserve_order(seq):
    """Remove duplicates from sequence while preserving order."""
    # https://stackoverflow.com/a/480227/1319998
    seen = set()
    seen_add = seen.add
    return tuple(x for x in seq if not (x in seen or seen_add(x)))


def drop_unused_roles(conn, lock_key: int = 1):
    """Drop ACL roles that are no longer in use."""
    adapter = _get_adapter(conn)

    adapter.drop_unused_roles(lock_key)
