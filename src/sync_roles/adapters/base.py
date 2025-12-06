"""Abstract base class for database adapters.

Defines the interface that all database adapters must implement.
"""

from abc import ABC
from abc import abstractmethod
from collections.abc import Iterable
from contextlib import contextmanager
from datetime import UTC
from typing import ClassVar

from sync_roles.models import DatabaseConnect
from sync_roles.models import DbObjectType
from sync_roles.models import Grant
from sync_roles.models import GrantOperation
from sync_roles.models import Login
from sync_roles.models import Privilege
from sync_roles.models import PrivilegeRecord
from sync_roles.models import RoleMembership
from sync_roles.models import SchemaCreate
from sync_roles.models import SchemaOwnership
from sync_roles.models import SchemaUsage
from sync_roles.models import TableSelect


class DatabaseAdapter(ABC):
    """Abstract base class for database-specific operations.

    Each database adapter must implement methods for:
    - Querying current state
    - Executing SQL commands
    - Locking mechanisms
    - Permission management
    """

    _grant_to_obj_type_map: ClassVar[dict[type[Grant], DbObjectType]] = {
        DatabaseConnect: DbObjectType.DATABASE,
        SchemaUsage: DbObjectType.SCHEMA,
        SchemaCreate: DbObjectType.SCHEMA,
        SchemaOwnership: DbObjectType.SCHEMA,
        TableSelect: DbObjectType.TABLE,  # TODO: This could be any type of table-like object
        Login: DbObjectType.DATABASE,
        RoleMembership: DbObjectType.ROLE,
    }

    _grant_to_privilege_map: ClassVar[dict[type[Grant], Privilege]] = {
        DatabaseConnect: Privilege.CONNECT,
        SchemaUsage: Privilege.USAGE,
        SchemaCreate: Privilege.CREATE,
        SchemaOwnership: Privilege.OWN,
        TableSelect: Privilege.SELECT,
        Login: Privilege.LOGIN,
        RoleMembership: Privilege.ROLE_MEMBERSHIP,
    }

    def __init__(self, conn):
        """Initialize the adapter with a database connection.

        Args:
            conn: Database connection object (e.g., SQLAlchemy connection)
        """
        self.conn = conn

    # ===== State Retrieval Methods =====

    @abstractmethod
    def role_exists(self, role_name: str) -> bool:
        """Check if a role exists in the database.

        Args:
            role_name: Name of the role to check

        Returns:
            True if role exists, False otherwise
        """

    @abstractmethod
    def get_roles(self, *role_names: str) -> Iterable[str]:
        """Check if a role exists in the database.

        Args:
            role_names: Names of the roles to check

        Returns:
            True if role exists, False otherwise
        """

    @abstractmethod
    def tables_in_schema_matching_regex(self, schema_name: str, table_name_regex) -> tuple[str, ...]:
        """Find all tables in a schema matching a regex pattern.

        Args:
            schema_name: Name of the schema
            table_name_regex: Compiled regex pattern to match table names

        Returns:
            Tuple of table names matching the pattern
        """

    @abstractmethod
    def get_databases(self, *values_to_search_for: str) -> Iterable[str]:
        """Generic lookup in database catalog tables.

        Args:
            values_to_search_for: Values to search for

        Returns:
            List of matching rows
        """

    @abstractmethod
    def get_schemas(self, *values_to_search_for: str) -> Iterable[str]:
        """Generic lookup in database catalog tables.

        Args:
            values_to_search_for: Values to search for

        Returns:
            List of matching rows
        """

    @abstractmethod
    def get_tables(self, *values_to_search_for: tuple[str, str]) -> Iterable[tuple[str, str]]:
        """Find tables matching given names.

        Args:
            values_to_search_for (tuple[tuple[str, str]]): A tuple of (schema, table) pairs.
        """

    @abstractmethod
    def get_db_owners(self, *databases: str) -> Iterable[str]:
        """Get owner roles of database objects.

        Args:
            databases (Iterable[str]): The names of the databases to seach for.
        """

    @abstractmethod
    def get_schema_owners(self, *schemas: str) -> Iterable[str]:
        """Get owner roles of schema objects.

        Args:
            schemas (Iterable[str]): The names of the schemas to seach for.
        """

    @abstractmethod
    def get_table_owners(self, *tables: tuple[str, str]) -> Iterable[str]:
        """Get owner roles of table objects.

        Args:
            tables (Iterable[tuple[str, str]]): Tuples of (schema, object) to search for.
        """

    @abstractmethod
    def get_existing_permissions(
        self,
        role_name: str,
        preserve_existing_grants_in_schemas: tuple[str, ...],
    ) -> set[PrivilegeRecord]:
        """Generate the `PrivilegeRecord`s representing existing permissions for a given role.

        Args:
            role_name (str): The name of the role to check existing permissions for.
            preserve_existing_grants_in_schemas (tuple): Schemas in which existing grants should be preserved.

        Returns:
            set[PrivilegeRecord]: A set of existing privilege records.
        """

    def build_proposed_permission(self, role_name: str, grant: Grant) -> set[PrivilegeRecord]:
        """Generate the proposed `PrivilegeRecord`s for a given grant.

        Args:
            role_name (str): The name of the role to grant permissions to.
            grant (Grant): The grant to generate permissions for.

        Returns:
            set[PrivilegeRecord]: A set of proposed privilege records.
        """

        def obj_name(grant: Grant) -> str | tuple[str, str]:
            match grant:
                case Login():
                    if until := grant.valid_until:
                        if grant.valid_until.tzinfo is None:
                            until = grant.valid_until.replace(tzinfo=UTC)
                        valid_until = until.isoformat(timespec='microseconds')
                    else:
                        valid_until = ''
                    password = 'P' if grant.password else ''
                    return f'{valid_until}{password}'
                case TableSelect():
                    if not isinstance(grant.table_name, str):
                        raise ValueError(
                            f'Table name on Grant {grant} should be of type `str`, got `{grant.table_name}`',
                        )
                    return (grant.schema_name, grant.table_name)
                case DatabaseConnect():
                    return grant.database_name
                case RoleMembership():
                    return grant.role_name
                case _:  # Schema grants
                    return grant.schema_name

        return {
            PrivilegeRecord(
                self._grant_to_obj_type_map[type(grant)],
                obj_name(grant),
                self._grant_to_privilege_map[type(grant)],
                role_name,
                grant,
            ),
        }

    @abstractmethod
    def get_current_user(self) -> str:
        """Get the current database user.

        Returns:
            Current user name
        """

    # ===== Transaction and Locking Methods =====

    @abstractmethod
    @contextmanager
    def transaction(self):
        """Context manager for database transactions.

        Yields control and commits on success, rolls back on error.
        """

    @abstractmethod
    def lock(self, lock_key: int):
        """Acquire a database lock for safe concurrent operations.

        Args:
            lock_key: Lock identifier
        """

    @abstractmethod
    @contextmanager
    def temporary_grant_of(self, role_names: tuple):
        """Temporarily grant roles to current user.

        This is used when we need elevated privileges to perform operations
        (e.g., granting ownership). The roles are automatically revoked
        when exiting the context.

        Args:
            role_names: Tuple of (role_name,) tuples to grant
        """

    # ===== Permission Manipulation Methods =====

    @abstractmethod
    def grant(self, grant_operation: GrantOperation):
        """Grant or revoke a privilege on an object to a role.

        Args:
            grant_operation: GrantOperation object containing all necessary information
        """

    # ===== Utility Methods =====

    @abstractmethod
    def drop_unused_roles(self, lock_key: int = 1):
        """Drop ACL roles that are no longer in use.

        Args:
            lock_key (int): Lock identifier for safe operation
        """
