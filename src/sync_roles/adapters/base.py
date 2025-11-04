"""Abstract base class for database adapters.

Defines the interface that all database adapters must implement.
"""

from abc import ABC
from abc import abstractmethod
from collections.abc import Iterable
from contextlib import contextmanager
from typing import Any

from sync_roles.models import GrantOperation


class DatabaseAdapter(ABC):
    """Abstract base class for database-specific operations.

    Each database adapter must implement methods for:
    - Querying current state
    - Executing SQL commands
    - Locking mechanisms
    - Permission management
    """

    def __init__(self, conn):
        """Initialize the adapter with a database connection.

        Args:
            conn: Database connection object (e.g., SQLAlchemy connection)
        """
        self.conn = conn

    # ===== State Retrieval Methods =====

    @abstractmethod
    def get_database_oid(self) -> Any:
        """Get the current database's unique identifier.

        Returns:
            Database identifier (OID for PostgreSQL)
        """

    @abstractmethod
    def get_role_exists(self, role_name: str) -> bool:
        """Check if a role exists in the database.

        Args:
            role_name: Name of the role to check

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
    def get_existing(self, table_name: str, column_name: str, *values_to_search_for: str) -> list:
        """Generic lookup in database catalog tables.

        Args:
            table_name: Catalog table name (e.g., 'pg_database')
            column_name: Column name to search
            values_to_search_for: Values to search for

        Returns:
            List of matching rows
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
    def get_existing_in_schema(
        self,
        table_name: str,
        namespace_column_name: str,
        row_name_column_name: str,
        *values_to_search_for: tuple[str, str],
    ) -> Iterable[tuple[str, str]]:
        """Lookup objects in a schema context.

        Args:
            table_name: Catalog table name
            namespace_column_name: Column name for namespace/schema
            row_name_column_name: Column name for object name
            values_to_search_for: Tuples of (schema, object) to search for

        Returns:
            List of matching (schema, object) tuples
        """

    @abstractmethod
    def get_tables(self, *values_to_search_for: tuple[str, str]) -> Iterable[tuple[str, str]]:
        """Find tables matching given names.

        Args:
            values_to_search_for (tuple[tuple[str, str]]): A tuple of (schema, table) pairs.
        """

    @abstractmethod
    def get_owners(
        self,
        table_name: str,
        owner_column_name: str,
        name_column_name: str,
        values_to_search_for: tuple,
    ) -> list:
        """Get owner roles of database objects.

        Args:
            table_name: Catalog table name
            owner_column_name: Column name for owner OID
            name_column_name: Column name for object name
            values_to_search_for: Object names to search for

        Returns:
            List of owner role names
        """

    @abstractmethod
    def get_owners_in_schema(
        self,
        table_name: str,
        owner_column_name: str,
        namespace_column_name: str,
        row_name_column_name: str,
        values_to_search_for: tuple,
    ) -> list:
        """Get owner roles of objects in schema context.

        Args:
            table_name: Catalog table name
            owner_column_name: Column name for owner OID
            namespace_column_name: Column name for namespace
            row_name_column_name: Column name for object name
            values_to_search_for: Tuples of (schema, object) to search for

        Returns:
            List of owner role names
        """

    @abstractmethod
    def get_acl_roles(
        self,
        privilege_type: str,
        table_name: str,
        row_name_column_name: str,
        acl_column_name: str,
        role_pattern: str,
        row_names: tuple,
    ) -> dict:
        """Get ACL roles (intermediate roles) for indirect permissions.

        Args:
            privilege_type: Type of privilege (e.g., 'SELECT', 'USAGE')
            table_name: Catalog table name
            row_name_column_name: Column name for object name
            acl_column_name: Column name for ACL data
            role_pattern: SQL LIKE pattern for role names
            row_names: Object names to query

        Returns:
            Dictionary mapping object_name -> role_name (or None if no role)
        """

    @abstractmethod
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
        """Get ACL roles for objects in schema context.

        Args:
            privilege_type: Type of privilege
            table_name: Catalog table name
            row_name_column_name: Column name for object name
            acl_column_name: Column name for ACL data
            namespace_oid_column_name: Column name for namespace OID
            role_pattern: SQL LIKE pattern for role names
            row_names: Tuples of (schema, object) to query

        Returns:
            Dictionary mapping (schema, object) -> role_name (or None if no role)
        """

    @abstractmethod
    def get_existing_permissions(self, role_name: str, preserve_existing_grants_in_schemas: tuple) -> tuple:
        """Get all existing permissions for a role.

        This is the main state retrieval method that returns all permissions,
        memberships, and capabilities for a role.

        Args:
            role_name: Name of the role
            preserve_existing_grants_in_schemas: Schemas to exclude from results

        Returns:
            Tuple of permission dictionaries with keys: 'on', 'name_1', 'name_2', 'name_3', 'privilege_type'
        """

    @abstractmethod
    def get_available_acl_role(self, base: str) -> str:
        """Generate a unique intermediate role name.

        Args:
            base: Base name for the role (e.g., '_pgsr_global_database_connect_')

        Returns:
            Unique role name
        """

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
    def create_role(self, role_name: str):
        """Create a new role."""

    @abstractmethod
    def create_schema(self, schema_name: str):
        """Create a new schema."""

    @abstractmethod
    def grant(self, grant_operation: GrantOperation) -> str:
        """Grant or revoke a privilege on an object to a role.

        Args:
            grant_operation: GrantOperation object containing all necessary information
        """

    @abstractmethod
    def grant_ownership(self, object_type: Any, role_name: str, object_name: str):
        """Grant ownership of an object to a role."""

    @abstractmethod
    def revoke_ownership(self, object_type: Any, role_name: str, object_name: str):
        """Revoke ownership of an object from a role."""

    @abstractmethod
    def grant_login(self, role_name: str, login: Any):
        """Grant LOGIN capability to a role.

        Args:
            role_name: Role name
            login: Login object with password and valid_until
        """

    @abstractmethod
    def revoke_login(self, role_name: str):
        """Revoke LOGIN capability from a role."""

    @abstractmethod
    def grant_memberships(self, memberships: tuple, role_name: str):
        """Grant role memberships.

        Args:
            memberships: Tuple of role names to grant
            role_name: Role to grant memberships to
        """

    @abstractmethod
    def revoke_memberships(self, memberships: set, role_name: str):
        """Revoke role memberships.

        Args:
            memberships: Set of role names to revoke
            role_name: Role to revoke memberships from
        """

    # ===== Utility Methods =====

    @abstractmethod
    def get_sql_grants(self) -> dict:
        """Get mapping of Privilege enum to SQL grant strings.

        Returns:
            Dictionary mapping Privilege -> SQL representation
        """

    @abstractmethod
    def get_sql_object_types(self) -> dict:
        """Get mapping of grant type classes to SQL object type strings.

        Returns:
            Dictionary mapping grant type class -> SQL representation
        """

    @abstractmethod
    def drop_unused_roles(self, lock_key: int = 1):
        """Drop ACL roles that are no longer in use.

        Args:
            lock_key (int): Lock identifier for safe operation
        """
