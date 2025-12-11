"""PostgreSQL adapter for sync_roles.

Implements PostgreSQL-specific operations for role synchronization.
"""

import logging
import re
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import replace
from functools import lru_cache
from types import ModuleType
from typing import cast
from uuid import uuid4

import sqlalchemy as sa

from sync_roles.adapters.base import DatabaseAdapter
from sync_roles.models import IN_SCHEMA
from sync_roles.models import TABLE_LIKE
from sync_roles.models import DatabaseConnect
from sync_roles.models import DbObjectType
from sync_roles.models import Grant
from sync_roles.models import GrantOperation
from sync_roles.models import GrantOperationType
from sync_roles.models import Login
from sync_roles.models import Privilege
from sync_roles.models import PrivilegeRecord
from sync_roles.models import SchemaCreate
from sync_roles.models import SchemaUsage
from sync_roles.models import TableSelect

sql2: ModuleType | None
sql3: ModuleType | None

try:
    from psycopg2 import sql as sql2
except ImportError:
    sql2 = None

try:
    from psycopg import sql as sql3
except ImportError:
    sql3 = None


log = logging.getLogger(__name__)


# SQL queries for PostgreSQL
_EXISTING_PERMISSIONS_SQL = """
-- Cluster permissions not "on" anything else
SELECT
  'database' AS on,
  CASE WHEN privilege_type = 'LOGIN' AND rolvaliduntil IS NOT NULL THEN to_char(rolvaliduntil AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US+00:00') END AS name_1,
  NULL AS name_2,
  NULL AS name_3,
  privilege_type
FROM pg_roles, unnest(
  CASE WHEN rolcanlogin THEN ARRAY['LOGIN'] ELSE ARRAY[]::text[] END
    || CASE WHEN rolsuper THEN ARRAY['SUPERUSER'] ELSE ARRAY[]::text[] END
    || CASE WHEN rolcreaterole THEN ARRAY['CREATE ROLE'] ELSE ARRAY[]::text[] END
    || CASE WHEN rolcreatedb THEN ARRAY['CREATE DATABASE'] ELSE ARRAY[]::text[] END
) AS p(privilege_type)
WHERE oid = quote_ident({role_name})::regrole

UNION ALL

-- Direct role memberships
SELECT 'role' AS on, groups.rolname AS name_1, NULL AS name_2, NULL AS name_3, 'MEMBER' AS privilege_type
FROM pg_auth_members mg
INNER JOIN pg_roles groups ON groups.oid = mg.roleid
INNER JOIN pg_roles members ON members.oid = mg.member
WHERE members.rolname = {role_name}

UNION ALL

-- ACL or owned-by dependencies of the role - global or in the currently connected database
(
  WITH owned_or_acl AS (
    SELECT
      refobjid,  -- The referenced object: the role in this case
      classid,   -- The pg_class oid that the dependant object is in
      objid,     -- The oid of the dependant object in the table specified by classid
      deptype,   -- The dependency type: o==is owner, and might have acl, a==has acl and not owner
      objsubid   -- The 1-indexed column index for table column permissions. 0 otherwise.
    FROM pg_shdepend
    WHERE refobjid = quote_ident({role_name})::regrole
    AND refclassid='pg_catalog.pg_authid'::regclass
    AND deptype IN ('a', 'o')
    AND (dbid = 0 OR dbid = (SELECT oid FROM pg_database WHERE datname = current_database()))
  ),

  relkind_mapping(relkind, type) AS (
    VALUES
      ('r', 'table'),
      ('v', 'view'),
      ('m', 'materialized view'),
      ('f', 'foreign table'),
      ('p', 'partitioned table'),
      ('S', 'sequence')
  )

  -- Schema ownership
  SELECT 'schema' AS on, nspname AS name_1, NULL AS name_2, NULL AS name_3, 'OWNER' AS privilege_type
  FROM pg_namespace n
  INNER JOIN owned_or_acl a ON a.objid = n.oid
  WHERE classid = 'pg_namespace'::regclass AND deptype = 'o'

  UNION ALL

  -- Schema privileges
  SELECT 'schema' AS on, nspname AS name_1, NULL AS name_2, NULL AS name_3, privilege_type
  FROM pg_namespace n
  INNER JOIN owned_or_acl a ON a.objid = n.oid
  CROSS JOIN aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner)))
  WHERE classid = 'pg_namespace'::regclass AND grantee = refobjid

  UNION ALL

  -- Table(-like) privileges
  SELECT r.type AS on, nspname AS name_1, relname AS name_2, NULL AS name_3, privilege_type
  FROM pg_class c
  INNER JOIN pg_namespace n ON n.oid = c.relnamespace
  INNER JOIN owned_or_acl a ON a.objid = c.oid
  CROSS JOIN aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner)))
  INNER JOIN relkind_mapping r ON r.relkind = c.relkind
  WHERE classid = 'pg_class'::regclass AND grantee = refobjid AND objsubid = 0
)
"""  # noqa: E501

_UNUSED_ROLES_SQL = """
SELECT
  r.rolname
FROM
  pg_roles r
LEFT JOIN
  (
    SELECT
      grantee
    FROM
      pg_class, aclexplode(relacl)
    WHERE
      grantee::regrole::text LIKE '\\_pgsr\\_local\\_%\\_table\\_select\\_%'
  ) in_use_roles ON in_use_roles.grantee = r.oid
WHERE
  r.rolname LIKE '\\_pgsr\\_local\\_%\\_table\\_select\\_%' AND grantee IS NULL

UNION ALL

SELECT
  r.rolname
FROM
  pg_roles r
LEFT JOIN
  (
    SELECT
      grantee
    FROM
      pg_namespace, aclexplode(nspacl)
    WHERE
      grantee::regrole::text LIKE '\\_pgsr\\_%\\_schema\\_usage\\_%'
  ) in_use_roles ON in_use_roles.grantee = r.oid
WHERE
  r.rolname LIKE '\\_pgsr\\_%\\_schema\\_usage\\_%' AND grantee IS NULL

UNION ALL

SELECT
  r.rolname
FROM
  pg_roles r
LEFT JOIN
  (
    SELECT
      grantee
    FROM
      pg_namespace, aclexplode(nspacl)
    WHERE
      grantee::regrole::text LIKE '\\_pgsr\\_%\\_schema\\_create\\_%'
  ) in_use_roles ON in_use_roles.grantee = r.oid
WHERE
  r.rolname LIKE '\\_pgsr\\_%\\_schema\\_create\\_%' AND grantee IS NULL

UNION ALL

SELECT
  r.rolname
FROM
  pg_roles r
LEFT JOIN
  (
    SELECT
      grantee
    FROM
      pg_database, aclexplode(datacl)
    WHERE
      grantee::regrole::text LIKE '%\\_pgsr\\_%\\_database\\_connect\\_%'
  ) in_use_roles ON in_use_roles.grantee = r.oid
WHERE
  r.rolname LIKE '%\\_pgsr\\_%\\_database\\_connect\\_%' AND grantee IS NULL

ORDER BY
  1
"""


class PostgresAdapter(DatabaseAdapter):
    """PostgreSQL-specific implementation of DatabaseAdapter."""

    def __init__(self, conn):
        """Initialize the PostgreSQL adapter.

        Args:
            conn: SQLAlchemy connection object
        """
        super().__init__(conn)

        # Choose the correct library for dynamically constructing SQL based on the underlying
        # engine of the SQLAlchemy connection
        self.sql = {
            'psycopg2': sql2,
            'psycopg': sql3,
        }[conn.engine.driver]

        # Prepare SQL constants for privileges and object types
        self._sql_grants: dict[Privilege, self.sql.SQL] = {
            Privilege.SELECT: self.sql.SQL('SELECT'),
            Privilege.INSERT: self.sql.SQL('INSERT'),
            Privilege.UPDATE: self.sql.SQL('UPDATE'),
            Privilege.DELETE: self.sql.SQL('DELETE'),
            Privilege.TRUNCATE: self.sql.SQL('TRUNCATE'),
            Privilege.REFERENCES: self.sql.SQL('REFERENCES'),
            Privilege.TRIGGER: self.sql.SQL('TRIGGER'),
            Privilege.CREATE: self.sql.SQL('CREATE'),
            Privilege.CONNECT: self.sql.SQL('CONNECT'),
            Privilege.TEMPORARY: self.sql.SQL('TEMPORARY'),
            Privilege.EXECUTE: self.sql.SQL('EXECUTE'),
            Privilege.USAGE: self.sql.SQL('USAGE'),
            Privilege.SET: self.sql.SQL('SET'),
            Privilege.ALTER_SYSTEM: self.sql.SQL('ALTER SYSTEM'),
        }

        self._sql_object_types: dict[type[Grant], str] = {
            TableSelect: 'TABLE',
            DatabaseConnect: 'DATABASE',
            SchemaUsage: 'SCHEMA',
            SchemaCreate: 'SCHEMA',
        }

    @property
    def _acl_role_templates(self) -> dict[str, str]:
        oid = self.get_database_oid()
        return {
            'DatabaseConnect': '_pgsr_global_database_connect_',
            'SchemaCreate': f'_pgsr_local_{oid}_schema_create_',
            'SchemaUsage': f'_pgsr_local_{oid}_schema_usage_',
            'TableSelect': f'_pgsr_local_{oid}_table_select_',
        }

    def _execute_sql(self, sql_obj):
        """Execute a SQL statement constructed with psycopg sql module.

        This avoids "argument 1 must be psycopg2.extensions.connection, not PGConnectionProxy"
        which can happen when elastic-apm wraps the connection object.
        """
        unwrapped_connection = getattr(
            self.conn.connection.driver_connection,
            '__wrapped__',
            self.conn.connection.driver_connection,
        )
        return self.conn.execute(sa.text(sql_obj.as_string(unwrapped_connection)))

    # ===== State Retrieval Methods =====

    def get_database_oid(self) -> int:
        """Get the current database's OID."""
        oid = self._execute_sql(
            self.sql.SQL("""
            SELECT oid FROM pg_database WHERE datname = current_database()
        """),
        ).fetchall()[0][0]

        return cast(int, oid)

    def role_exists(self, role_name: str) -> bool:
        """Check if a role exists."""
        exists = self._execute_sql(
            self.sql.SQL('SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {role_name})').format(
                role_name=self.sql.Literal(role_name),
            ),
        ).fetchall()[0][0]

        return cast(bool, exists)

    def get_roles(self, *role_names: str) -> Iterable[str]:
        """Check if a role exists.

        Args:
            role_names (tuple[str, ...]): The names of the roles to check.

        Returns:
            Iterable[str]: The names of the roles that exist.
        """
        if not role_names:
            return []
        roles = self._execute_sql(
            self.sql.SQL('SELECT rolname FROM pg_roles WHERE rolname IN ({role_names})').format(
                role_names=self.sql.SQL(',').join(self.sql.Literal(role) for role in role_names),
            ),
        ).fetchall()

        return tuple(row[0] for row in roles)

    def tables_in_schema_matching_regex(self, schema_name: str, table_name_regex: re.Pattern) -> tuple[str, ...]:
        """Find all tables in a schema matching a regex pattern."""
        # Inspired by https://dba.stackexchange.com/a/345153/37229 to avoid sequential scan on pg_class
        table_names = self._execute_sql(
            self.sql.SQL("""
            SELECT relname
            FROM pg_depend
            INNER JOIN pg_class ON pg_class.oid = pg_depend.objid
            WHERE pg_depend.refobjid = {schema_name}::regnamespace
              AND pg_depend.refclassid = 'pg_namespace'::regclass
              AND pg_depend.classid = 'pg_class'::regclass
              AND pg_class.relkind = ANY(ARRAY['p', 'r', 'v', 'm'])
            ORDER BY relname
        """).format(
                schema_name=self.sql.Literal(schema_name),
            ),
        ).fetchall()

        return tuple(table_name for (table_name,) in table_names if table_name_regex.match(table_name))

    def get_databases(self, *values_to_search_for: str) -> list[str]:
        """Find databases matching given names.

        Args:
            values_to_search_for: Values to search for

        Returns:
            List of matching rows
        """
        return self.get_existing('pg_database', 'datname', *values_to_search_for)

    def get_schemas(self, *values_to_search_for: str) -> list[str]:
        """Find schemas matching given names.

        Args:
            values_to_search_for: Values to search for

        Returns:
            List of matching rows
        """
        return self.get_existing('pg_namespace', 'nspname', *values_to_search_for)

    def get_tables(self, *values_to_search_for: tuple[str, str]) -> Iterable[tuple[str, str]]:
        """Find tables matching given names.

        Args:
            values_to_search_for (tuple[tuple[str, str]]): A tuple of (schema, table) pairs.
        """
        return self._get_existing_in_schema('pg_class', 'relnamespace', 'relname', *values_to_search_for)

    def get_existing(self, table_name: str, column_name: str, *values_to_search_for: str) -> list[str]:
        """Generic lookup in PostgreSQL catalog tables."""
        if not values_to_search_for:
            return []
        cols = self._execute_sql(
            self.sql.SQL(
                'SELECT {column_name} FROM {table_name} WHERE {column_name} IN ({values_to_search_for})',
            ).format(
                table_name=self.sql.Identifier(table_name),
                column_name=self.sql.Identifier(column_name),
                values_to_search_for=self.sql.SQL(',').join(self.sql.Literal(value) for value in values_to_search_for),
            ),
        ).fetchall()

        return [a[0] for a in cols]

    def _get_existing_in_schema(
        self,
        table_name: str,
        namespace_column_name: str,
        row_name_column_name: str,
        *values_to_search_for: tuple[str, str],
    ) -> Iterable[tuple[str, str]]:
        """Lookup objects in a schema context."""
        if not values_to_search_for:
            return []
        objects = self._execute_sql(
            self.sql.SQL("""
            SELECT nspname, {row_name_column_name}
            FROM {table_name} c
            INNER JOIN pg_namespace n ON n.oid = c.{namespace_column_name}
            WHERE (nspname, {row_name_column_name}) IN ({values_to_search_for})
        """).format(
                table_name=self.sql.Identifier(table_name),
                namespace_column_name=self.sql.Identifier(namespace_column_name),
                row_name_column_name=self.sql.Identifier(row_name_column_name),
                values_to_search_for=self.sql.SQL(',').join(
                    self.sql.SQL('({},{})').format(self.sql.Literal(schema_name), self.sql.Literal(row_name))
                    for (schema_name, row_name) in values_to_search_for
                ),
            ),
        ).fetchall()

        return cast(list, objects)

    def get_db_owners(self, *databases: str) -> Iterable[str]:
        """Get owner roles of database objects.

        Args:
            databases (Iterable[str]): The names of the databases to seach for.
        """
        return self._get_owners('pg_database', 'datdba', 'datname', databases)

    def get_schema_owners(self, *schemas: str) -> Iterable[str]:
        """Get owner roles of schema objects.

        Args:
            schemas (Iterable[str]): The names of the schemas to seach for.
        """
        return self._get_owners('pg_namespace', 'nspowner', 'nspname', schemas)

    def get_table_owners(self, *tables: tuple[str, str]) -> Iterable[str]:
        """Get owner roles of table objects.

        Args:
            tables (Iterable[tuple[str, str]]): Tuples of (schema, object) to search for.
        """
        return self._get_owners_in_schema('pg_class', 'relowner', 'relnamespace', 'relname', tables)

    def _get_owners(
        self,
        table_name: str,
        owner_column_name: str,
        name_column_name: str,
        values_to_search_for: Iterable[str],
    ) -> list:
        """Get owner roles of database objects."""
        if not values_to_search_for:
            return []
        owners = self._execute_sql(
            self.sql.SQL("""
            SELECT DISTINCT rolname
            FROM {table_name}
            INNER JOIN pg_roles r ON r.oid = {owner_column_name}
            WHERE {name_column_name} IN ({values_to_search_for})
        """).format(
                table_name=self.sql.Identifier(table_name),
                owner_column_name=self.sql.Identifier(owner_column_name),
                name_column_name=self.sql.Identifier(name_column_name),
                values_to_search_for=self.sql.SQL(',').join(self.sql.Literal(value) for value in values_to_search_for),
            ),
        ).fetchall()

        return cast(list, owners)

    def _get_owners_in_schema(
        self,
        table_name: str,
        owner_column_name: str,
        namespace_column_name: str,
        row_name_column_name: str,
        values_to_search_for: Iterable[tuple[str, str]],
    ) -> list:
        """Get owner roles of objects in schema context."""
        if not values_to_search_for:
            return []
        owners = self._execute_sql(
            self.sql.SQL("""
            SELECT DISTINCT rolname
            FROM {table_name} c
            INNER JOIN pg_namespace n ON n.oid = c.{namespace_column_name}
            INNER JOIN pg_roles r ON r.oid = {owner_column_name}
            WHERE (nspname, {row_name_column_name}) IN ({values_to_search_for})
        """).format(
                table_name=self.sql.Identifier(table_name),
                owner_column_name=self.sql.Identifier(owner_column_name),
                namespace_column_name=self.sql.Identifier(namespace_column_name),
                row_name_column_name=self.sql.Identifier(row_name_column_name),
                values_to_search_for=self.sql.SQL(',').join(
                    self.sql.SQL('({},{})').format(self.sql.Literal(schema_name), self.sql.Literal(row_name))
                    for (schema_name, row_name) in values_to_search_for
                ),
            ),
        ).fetchall()

        return cast(list, owners)

    def _get_acl_roles(
        self,
        privilege_type: str,
        table_name: str,
        row_name_column_name: str,
        acl_column_name: str,
        role_pattern: str,
        row_names: Iterable[str],
    ) -> dict:
        """Get ACL roles (intermediate roles) for indirect permissions."""
        row_name_role_names = (
            []
            if not row_names
            else self._execute_sql(
                self.sql.SQL("""
                SELECT row_names.name, grantee::regrole
                FROM (
                    VALUES {row_names}
                ) row_names(name)
                LEFT JOIN (
                    SELECT {row_name_column_name}, grantee
                    FROM {table_name}, aclexplode({acl_column_name})
                    WHERE grantee::regrole::text LIKE {role_pattern}
                    AND privilege_type = {privilege_type}
                ) grantees ON grantees.{row_name_column_name} = row_names.name
            """).format(
                    privilege_type=self.sql.Literal(privilege_type),
                    table_name=self.sql.Identifier(table_name),
                    row_name_column_name=self.sql.Identifier(row_name_column_name),
                    acl_column_name=self.sql.Identifier(acl_column_name),
                    role_pattern=self.sql.Literal(role_pattern),
                    row_names=self.sql.SQL(',').join(
                        self.sql.SQL('({})').format(self.sql.Literal(row_name)) for row_name in row_names
                    ),
                ),
            ).fetchall()
        )

        return dict(row_name_role_names)

    def _get_db_acl_roles(self, db_names: Iterable[str]):
        return self._get_acl_roles(
            'CONNECT',
            'pg_database',
            'datname',
            'datacl',
            '\\_pgsr\\_global\\_database\\_connect\\_%',
            db_names,
        )

    def _get_schema_usage_acl_roles(self, schema_names: Iterable[str]):
        db_oid = self.get_database_oid()
        return self._get_acl_roles(
            'USAGE',
            'pg_namespace',
            'nspname',
            'nspacl',
            f'\\_pgsr\\_local\\_{db_oid}_\\schema\\_usage\\_%',
            schema_names,
        )

    def _get_schema_create_acl_roles(self, schema_names: Iterable[str]):
        db_oid = self.get_database_oid()
        return self._get_acl_roles(
            'CREATE',
            'pg_namespace',
            'nspname',
            'nspacl',
            f'\\_pgsr\\_local\\_{db_oid}_\\schema\\_create\\_%',
            schema_names,
        )

    def _get_table_select_acl_roles(self, table_names: Iterable[tuple[str, str]]) -> dict[tuple[str, str], str]:
        db_oid = self.get_database_oid()
        return self._get_acl_roles_in_schema(
            'SELECT',
            'pg_class',
            'relname',
            'relacl',
            'relnamespace',
            f'\\_pgsr\\_local\\_{db_oid}_\\table\\_select\\_%',
            table_names,
        )

    def _get_acl_roles_in_schema(
        self,
        privilege_type: str,
        table_name: str,
        row_name_column_name: str,
        acl_column_name: str,
        namespace_oid_column_name: str,
        role_pattern: str,
        row_names: Iterable[tuple[str, str]],
    ) -> dict:
        """Get ACL roles for objects in schema context."""
        row_name_role_names = (
            []
            if not row_names
            else self._execute_sql(
                self.sql.SQL("""
                SELECT all_names.schema_name, all_names.row_name, grantee::regrole
                FROM (
                    VALUES {row_names}
                ) all_names(schema_name, row_name)
                LEFT JOIN (
                    SELECT nspname AS schema_name, {row_name_column_name} AS row_name, grantee
                    FROM {table_name}
                    INNER JOIN pg_namespace ON pg_namespace.oid = pg_class.{namespace_oid_column_name}
                    CROSS JOIN aclexplode({acl_column_name})
                    WHERE grantee::regrole::text LIKE {role_pattern}
                    AND privilege_type = {privilege_type}
                ) grantees ON grantees.schema_name = all_names.schema_name AND grantees.row_name = all_names.row_name
            """).format(
                    privilege_type=self.sql.Literal(privilege_type),
                    table_name=self.sql.Identifier(table_name),
                    row_name_column_name=self.sql.Identifier(row_name_column_name),
                    acl_column_name=self.sql.Identifier(acl_column_name),
                    namespace_oid_column_name=self.sql.Identifier(namespace_oid_column_name),
                    role_pattern=self.sql.Literal(role_pattern),
                    row_names=self.sql.SQL(',').join(
                        self.sql.SQL('({},{})').format(
                            self.sql.Literal(schema_name),
                            self.sql.Literal(row_name),
                        )
                        for (schema_name, row_name) in row_names
                    ),
                ),
            ).fetchall()
        )

        return {(schema_name, row_name): role_name for schema_name, row_name, role_name in row_name_role_names}

    def get_existing_permissions(
        self,
        role_name: str,
        preserve_existing_grants_in_schemas: tuple[str, ...],
    ) -> set[PrivilegeRecord]:
        """Return the `PrivilegeRecord`s representing existing permissions for a role.

        Args:
            role_name (str): The name of the role to check existing permissions for.
            preserve_existing_grants_in_schemas (tuple): Schemas in which existing grants should be preserved.

        Returns:
            set[PrivilegeRecord]: A set of existing privilege records.
        """

        def _obj_type(record: dict[str, str]) -> DbObjectType:
            if record['on'] in TABLE_LIKE:
                return DbObjectType.TABLE
            return {
                'database': DbObjectType.DATABASE,
                'schema': DbObjectType.SCHEMA,
                'table': DbObjectType.TABLE,
                'view': DbObjectType.TABLE,
                'role': DbObjectType.ROLE,
            }[record['on']]

        def _obj_name(record: dict[str, str]) -> str | tuple[str, str]:
            if record['name_2'] is None:
                if record['name_1'] is None:
                    return ''
                return record['name_1']
            return record['name_1'], record['name_2']

        def priv(priv: str) -> Privilege:
            match priv:
                case 'MEMBER':
                    return Privilege.ROLE_MEMBERSHIP
                case 'OWNER':
                    return Privilege.OWN
                case _:
                    return Privilege[priv]

        if not self.role_exists(role_name):
            return set()

        preserve_existing_grants_in_schemas_set = set(preserve_existing_grants_in_schemas)
        results = tuple(
            row._mapping
            for row in self._execute_sql(
                self.sql.SQL(_EXISTING_PERMISSIONS_SQL).format(role_name=self.sql.Literal(role_name)),
            ).fetchall()
        )
        return {
            PrivilegeRecord(_obj_type(row), _obj_name(row), priv(row['privilege_type']), role_name)
            for row in results
            if row['on'] not in IN_SCHEMA or row['name_1'] not in preserve_existing_grants_in_schemas_set
        }

    def build_proposed_permission(self, role_name: str, grant: Grant) -> set[PrivilegeRecord]:
        """Generate the proposed `PrivilegeRecord`s for a given grant.

        Calls the base implementation for direct permissions, and generates the intermediate
        role logic for indirect permissions.

        Args:
            role_name (str): The name of the role to grant permissions to.
            grant (Grant): The grant to generate permissions for.

        Returns:
            set[PrivilegeRecord]: A set of proposed privilege records.
        """
        if not isinstance(grant, DatabaseConnect | SchemaUsage | SchemaCreate | TableSelect) or (
            hasattr(grant, 'direct') and grant.direct is True
        ):
            return super().build_proposed_permission(role_name, grant)

        object_name: str | tuple[str, str]
        match grant:
            case DatabaseConnect():
                object_name = grant.database_name
                acl_role_name = self._get_db_acl_roles([grant.database_name]).get(grant.database_name)
            case SchemaUsage():
                object_name = grant.schema_name
                acl_role_name = self._get_schema_usage_acl_roles([object_name]).get(object_name)
            case SchemaCreate():
                object_name = grant.schema_name
                acl_role_name = self._get_schema_create_acl_roles([object_name]).get(object_name)
            case TableSelect():
                object_name = (grant.schema_name, cast(str, grant.table_name))
                acl_role_name = self._get_table_select_acl_roles([object_name]).get(object_name)
            case _:
                ValueError(f'Invalid grant type. Expected `SchemaUsage, SchemaCreate or TableSelect`, got {grant}.')

        privileges = []

        if not acl_role_name:
            acl_role_name = self._generate_acl_role_name(type(grant).__name__, object_name)
            privileges = [  # Create permission for new role
                replace(privilege, grantee=acl_role_name)
                for privilege in super().build_proposed_permission(role_name, grant)
            ]

        return {
            *privileges,
            PrivilegeRecord(DbObjectType.ROLE, acl_role_name, Privilege.ROLE_MEMBERSHIP, role_name),
        }

    @lru_cache  # noqa: B019
    def _generate_acl_role_name(self, object_type: str, object_name: str) -> str:
        """Generate a unique intermediate role name."""
        base_name = self._acl_role_templates[object_type]  # NOTE: Fix this
        for _ in range(10):
            role_name = f'{base_name}{uuid4().hex[:8]}'
            if not self.role_exists(role_name):
                return role_name
        raise RuntimeError('Unable to find available role name')

    def get_current_user(self) -> str:
        """Get the current database user."""
        return cast(str, self._execute_sql(self.sql.SQL('SELECT CURRENT_USER')).fetchall()[0][0])

    # ===== Transaction and Locking Methods =====

    @contextmanager
    def transaction(self):
        """Context manager for database transactions."""
        try:
            self.conn.begin()
            yield
        except Exception:
            self.conn.rollback()
            raise
        else:
            self.conn.commit()

    def lock(self, lock_key: int):
        """Acquire a PostgreSQL advisory lock."""
        self._execute_sql(
            self.sql.SQL('SELECT pg_advisory_xact_lock({lock_key})').format(lock_key=self.sql.Literal(lock_key)),
        )

    @contextmanager
    def temporary_grant_of(self, role_names: tuple):
        """Temporarily grant roles to current user.

        Expected to be called in a transaction context, so if an exception is thrown,
        it will roll back. The REVOKE is not in a finally: block because if there was an
        exception this will then cause another error.
        """
        log.debug(f'Temporarily granting roles {role_names} to CURRENT_USER')
        if role_names:
            self._execute_sql(
                self.sql.SQL('GRANT {role_names} TO CURRENT_USER').format(
                    role_names=self.sql.SQL(',').join(self.sql.Identifier(role_name) for (role_name,) in role_names),
                ),
            )
        yield
        log.debug(f'Revoking roles {role_names} from CURRENT_USER')
        if role_names:
            self._execute_sql(
                self.sql.SQL('REVOKE {role_names} FROM CURRENT_USER').format(
                    role_names=self.sql.SQL(',').join(self.sql.Identifier(role_name) for (role_name,) in role_names),
                ),
            )

    # ===== Permission Manipulation Methods =====

    def grant(self, grant_operation: GrantOperation):
        """Grant a privilege on an object to a role."""
        match grant_operation.type_:
            case GrantOperationType.CREATE:
                match grant_operation.privilege.privilege:
                    case Privilege.ROLE_MEMBERSHIP:
                        sql_obj = self.sql.SQL('CREATE ROLE {role_name};').format(
                            role_name=self.sql.Identifier(grant_operation.privilege.object_name),
                        )
                    case Privilege.OWN:
                        sql_obj = self.sql.SQL('CREATE SCHEMA {schema_name};').format(
                            schema_name=self.sql.Identifier(grant_operation.privilege.object_name),
                        )
                    case _:
                        raise Exception(
                            f'Unrecognised privilege type {grant_operation.type_!r} for grant: {grant_operation}',
                        )
            case _:
                match grant_operation.privilege.privilege:
                    case Privilege.OWN:
                        sql_obj = self._build_grant_ownership(grant_operation)
                    case Privilege.LOGIN:
                        sql_obj = self._build_grant_login(grant_operation)
                    case Privilege.ROLE_MEMBERSHIP:
                        sql_obj = self._build_grant_memberships(grant_operation)
                    case _:  # Regular privilege operations (SELECT, USAGE, CREATE, CONNECT, etc.)
                        sql_obj = self._build_grant(grant_operation)
        self._execute_sql(sql_obj)

    def _build_grant_ownership(self, grant_operation: GrantOperation) -> str:
        """Build SQL for object ownership operations."""
        is_grant = grant_operation.type_ == GrantOperationType.GRANT

        if is_grant:
            sql = self.sql.SQL(
                f'ALTER {grant_operation.privilege.object_type.name} {{object_name}} OWNER TO {{role_name}}',
            ).format(
                object_name=self.sql.Identifier(grant_operation.privilege.object_name),
                role_name=self.sql.Identifier(grant_operation.privilege.grantee) if is_grant else 'CURRENT_USER',
            )
        else:
            sql = self.sql.SQL(
                f'ALTER {grant_operation.privilege.object_type.name} {{object_name}} OWNER TO CURRENT_USER',
            ).format(object_name=self.sql.Identifier(grant_operation.privilege.object_name))
        return cast(str, sql)

    def _build_grant_login(self, grant_operation: GrantOperation) -> str:
        """Build SQL for role login operations."""
        is_grant = grant_operation.type_ == GrantOperationType.GRANT
        if is_grant:
            login = cast(Login, grant_operation.privilege.grant)
            valid_until = login.valid_until.isoformat() if login.valid_until else 'infinity'
            password_clause = (
                self.sql.SQL('PASSWORD {password}').format(password=self.sql.Literal(login.password))
                if login.password is not None
                else self.sql.SQL('')
            )

            sql = self.sql.SQL('ALTER ROLE {role_name} WITH LOGIN {password} VALID UNTIL {valid_until}').format(
                role_name=self.sql.Identifier(grant_operation.privilege.grantee),
                password=password_clause,
                valid_until=self.sql.Literal(valid_until),
            )
        else:
            sql = self.sql.SQL('ALTER ROLE {role_name} WITH NOLOGIN PASSWORD NULL').format(
                role_name=self.sql.Identifier(grant_operation.privilege.grantee),
            )
        return cast(str, sql)

    def _build_grant_memberships(self, grant_operation: GrantOperation) -> str:
        """Build SQL for role membership operations."""
        is_grant = grant_operation.type_ == GrantOperationType.GRANT
        to_or_from = 'TO' if is_grant else 'FROM'

        sql = self.sql.SQL(f'{grant_operation.type_.name} {{memberships}} {to_or_from} {{role_name}}').format(
            memberships=self.sql.Identifier(grant_operation.privilege.object_name),
            role_name=self.sql.Identifier(grant_operation.privilege.grantee),
        )
        return cast(str, sql)

    def _build_grant(self, grant_operation: GrantOperation) -> str:
        """Build SQL for regular privilege operations (SELECT, USAGE, CREATE, CONNECT, etc.)."""
        is_grant = grant_operation.type_ == GrantOperationType.GRANT
        to_or_from = 'TO' if is_grant else 'FROM'
        obj_name = (
            grant_operation.privilege.object_name
            if isinstance(grant_operation.privilege.object_name, tuple)
            else (grant_operation.privilege.object_name,)
        )

        sql = self.sql.SQL(
            f'{grant_operation.type_.name} {grant_operation.privilege.privilege.name} '
            f'ON {{object_type}} {{object_name}} {to_or_from} {{role_name}}',
        ).format(
            object_type=self.sql.SQL(grant_operation.privilege.object_type.name),
            object_name=self.sql.Identifier(*obj_name),
            role_name=self.sql.Identifier(grant_operation.privilege.grantee),
        )
        return cast(str, sql)

    # ===== Utility Methods =====

    def drop_unused_roles(self, lock_key: int = 1):
        """Drop unused intermediate roles.

        This function inspects the database for helper roles created by this
        application (roles with names matching the internal _pgsr_* patterns),
        and drops those which are not referenced by any ACL entries. It acquires
        an advisory lock specified by lock_key to avoid races, and runs inside a
        transaction.

        This is a PostgreSQL-specific operation that cleans up roles
        created by sync_roles that are no longer in use.

        Args:
            lock_key (int): Lock identifier for safe operation
        """
        log.info('Dropping unused roles...')

        with self.transaction():
            results = self._execute_sql(self.sql.SQL(_UNUSED_ROLES_SQL)).fetchall()

            if not results:
                log.info('No roles to drop')
                return

            self.lock(lock_key)

            for (role_name,) in results:
                log.info('Dropping role %s', role_name)
                self._execute_sql(
                    self.sql.SQL('DROP ROLE {role_name}').format(role_name=self.sql.Identifier(role_name)),
                )
