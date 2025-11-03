"""PostgreSQL adapter for sync_roles.

Implements PostgreSQL-specific operations for role synchronization.
"""

import logging
from contextlib import contextmanager
from typing import Any
from typing import cast
from uuid import uuid4

import sqlalchemy as sa

try:
    from psycopg2 import sql as sql2
except ImportError:
    sql2 = None

try:
    from psycopg import sql as sql3
except ImportError:
    sql3 = None

from sync_roles.adapters.base import DatabaseAdapter
from sync_roles.models import IN_SCHEMA
from sync_roles.models import DatabaseConnect
from sync_roles.models import GrantType
from sync_roles.models import Privilege
from sync_roles.models import SchemaCreate
from sync_roles.models import SchemaUsage
from sync_roles.models import TableSelect

logger = logging.getLogger(__name__)


# SQL queries for PostgreSQL
_EXISTING_PERMISSIONS_SQL = """
-- Cluster permissions not "on" anything else
SELECT
  'cluster' AS on,
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

        self._sql_object_types: dict[type[GrantType], self.sql.SQL] = {
            TableSelect: self.sql.SQL('TABLE'),
            DatabaseConnect: self.sql.SQL('DATABASE'),
            SchemaUsage: self.sql.SQL('SCHEMA'),
            SchemaCreate: self.sql.SQL('SCHEMA'),
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

    def get_role_exists(self, role_name: str) -> bool:
        """Check if a role exists."""
        exists = self._execute_sql(
            self.sql.SQL('SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {role_name})').format(
                role_name=self.sql.Literal(role_name),
            ),
        ).fetchall()[0][0]

        return cast(bool, exists)

    def tables_in_schema_matching_regex(self, schema_name: str, table_name_regex) -> tuple[str, ...]:
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

    def get_existing(self, table_name: str, column_name: str, values_to_search_for: tuple) -> list:
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

        return cast(list, cols)

    def get_existing_in_schema(
        self,
        table_name: str,
        namespace_column_name: str,
        row_name_column_name: str,
        values_to_search_for: tuple,
    ) -> list:
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

    def get_owners(
        self,
        table_name: str,
        owner_column_name: str,
        name_column_name: str,
        values_to_search_for: tuple,
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

    def get_owners_in_schema(
        self,
        table_name: str,
        owner_column_name: str,
        namespace_column_name: str,
        row_name_column_name: str,
        values_to_search_for: tuple,
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

    def get_acl_roles(
        self,
        privilege_type: str,
        table_name: str,
        row_name_column_name: str,
        acl_column_name: str,
        role_pattern: str,
        row_names: tuple,
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

    def get_acl_roles_in_schema(
        self,
        privilege_type: str,
        table_name: str,
        row_name_column_name: str,
        acl_column_name: str,
        namespace_oid_column_name: str,
        role_pattern: str,
        row_names: tuple,
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

    def get_existing_permissions(self, role_name: str, preserve_existing_grants_in_schemas: tuple) -> tuple:
        """Get all existing permissions for a role."""
        preserve_existing_grants_in_schemas_set = set(preserve_existing_grants_in_schemas)
        results = tuple(
            row._mapping
            for row in self._execute_sql(
                self.sql.SQL(_EXISTING_PERMISSIONS_SQL).format(role_name=self.sql.Literal(role_name)),
            ).fetchall()
        )
        return tuple(
            row
            for row in results
            if row['on'] not in IN_SCHEMA or row['name_1'] not in preserve_existing_grants_in_schemas_set
        )

    def get_available_acl_role(self, base: str) -> str:
        """Generate a unique intermediate role name."""
        for _ in range(10):
            role_name = base + uuid4().hex[:8]
            if not self.get_role_exists(role_name):
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
        logger.info('Temporarily granting roles %s to CURRENT_USER', role_names)
        if role_names:
            self._execute_sql(
                self.sql.SQL('GRANT {role_names} TO CURRENT_USER').format(
                    role_names=self.sql.SQL(',').join(self.sql.Identifier(role_name) for (role_name,) in role_names),
                ),
            )
        yield
        logger.info('Revoking roles %s from CURRENT_USER', role_names)
        if role_names:
            self._execute_sql(
                self.sql.SQL('REVOKE {role_names} FROM CURRENT_USER').format(
                    role_names=self.sql.SQL(',').join(self.sql.Identifier(role_name) for (role_name,) in role_names),
                ),
            )

    # ===== Permission Manipulation Methods =====

    def create_role(self, role_name: str):
        """Create a new role."""
        logger.info('Creating ROLE %s', role_name)
        self._execute_sql(self.sql.SQL('CREATE ROLE {role_name};').format(role_name=self.sql.Identifier(role_name)))

    def create_schema(self, schema_name: str):
        """Create a new schema."""
        logger.info('Creating SCHEMA %s', schema_name)
        self._execute_sql(
            self.sql.SQL('CREATE SCHEMA {schema_name};').format(schema_name=self.sql.Identifier(schema_name)),
        )

    def grant(self, grant_type: Any, object_type: Any, object_name: tuple, role_name: str):
        """Grant a privilege on an object to a role."""
        logger.info('Granting %s on %s %s to role %s', grant_type, object_type, object_name, role_name)
        self._execute_sql(
            self.sql.SQL('GRANT {grant_type} ON {object_type} {object_name} TO {role_name}').format(
                grant_type=grant_type,
                object_type=object_type,
                object_name=self.sql.Identifier(*object_name),
                role_name=self.sql.Identifier(role_name),
            ),
        )

    def revoke(self, grant_type: Any, object_type: Any, object_name: tuple, role_name: str):
        """Revoke a privilege on an object from a role."""
        logger.info('Revoking %s on %s %s from role %s', grant_type, object_type, object_name, role_name)
        self._execute_sql(
            self.sql.SQL('REVOKE {grant_type} ON {object_type} {object_name} FROM {role_name}').format(
                grant_type=grant_type,
                object_type=object_type,
                object_name=self.sql.Identifier(*object_name),
                role_name=self.sql.Identifier(role_name),
            ),
        )

    def grant_ownership(self, object_type: Any, role_name: str, object_name: str):
        """Grant ownership of an object to a role."""
        logger.info('Granting ownership of %s %s to role %s', object_type, object_name, role_name)
        self._execute_sql(
            self.sql.SQL('ALTER {object_type} {object_name} OWNER TO {role_name}').format(
                object_type=object_type,
                role_name=self.sql.Identifier(role_name),
                object_name=self.sql.Identifier(object_name),
            ),
        )

    def revoke_ownership(self, object_type: Any, role_name: str, object_name: str):
        """Revoke ownership of an object from a role."""
        logger.info('Revoking ownership of %s %s from role %s', object_type, object_name, role_name)
        self._execute_sql(
            self.sql.SQL('ALTER {object_type} {object_name} OWNER TO CURRENT_USER').format(
                object_type=object_type,
                object_name=self.sql.Identifier(object_name),
            ),
        )

    def grant_login(self, role_name: str, login: Any):
        """Grant LOGIN capability to a role."""
        logger.info('Granting LOGIN to role %s', role_name)
        self._execute_sql(
            self.sql.SQL('ALTER ROLE {role_name} WITH LOGIN {password} VALID UNTIL {valid_until}').format(
                role_name=self.sql.Identifier(role_name),
                password=self.sql.SQL('PASSWORD {password}').format(password=self.sql.Literal(login.password))
                if login.password is not None
                else self.sql.SQL(''),
                valid_until=self.sql.Literal(
                    login.valid_until.isoformat() if login.valid_until is not None else 'infinity',
                ),
            ),
        )

    def revoke_login(self, role_name: str):
        """Revoke LOGIN capability from a role."""
        logger.info('Revoking LOGIN from role %s', role_name)
        self._execute_sql(
            self.sql.SQL('ALTER ROLE {role_name} WITH NOLOGIN PASSWORD NULL').format(
                role_name=self.sql.Identifier(role_name),
            ),
        )

    def grant_memberships(self, memberships: tuple, role_name: str):
        """Grant role memberships."""
        if not memberships:
            logger.info('No memberships granted to %s', role_name)
            return
        logger.info('Granting memberships %s to role %s', memberships, role_name)
        self._execute_sql(
            self.sql.SQL('GRANT {memberships} TO {role_name}').format(
                memberships=self.sql.SQL(',').join(self.sql.Identifier(membership) for membership in memberships),
                role_name=self.sql.Identifier(role_name),
            ),
        )

    def revoke_memberships(self, memberships: set, role_name: str):
        """Revoke role memberships."""
        if not memberships:
            logger.info('No memberships revoked from %s', role_name)
            return
        logger.info('Revoking memberships %s from role %s', memberships, role_name)
        self._execute_sql(
            self.sql.SQL('REVOKE {memberships} FROM {role_name}').format(
                memberships=self.sql.SQL(',').join(self.sql.Identifier(membership) for membership in memberships),
                role_name=self.sql.Identifier(role_name),
            ),
        )

    # ===== Utility Methods =====

    def get_sql_grants(self) -> dict:
        """Get mapping of Privilege enum to SQL grant strings."""
        return self._sql_grants

    def get_sql_object_types(self) -> dict:
        """Get mapping of grant type classes to SQL object type strings."""
        return self._sql_object_types

    # ===== PostgreSQL-specific utility methods =====

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
        logger.info('Dropping unused roles...')

        with self.transaction():
            results = self._execute_sql(self.sql.SQL(_UNUSED_ROLES_SQL)).fetchall()

            if not results:
                logger.info('No roles to drop')
                return

            self.lock(lock_key)

            for (role_name,) in results:
                logger.info('Dropping role %s', role_name)
                self._execute_sql(
                    self.sql.SQL('DROP ROLE {role_name}').format(role_name=self.sql.Identifier(role_name)),
                )
