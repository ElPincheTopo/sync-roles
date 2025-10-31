"""Database-agnostic grant models."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from re import Pattern


class Privilege(Enum):
    """Enumeration of database/object privileges.

    Each member denotes a specific privilege that can be granted to roles or users
    (e.g., on tables, schemas, functions, or the database). Members carry stable
    integer values used for compact storage and serialization.
    """

    SELECT = 1
    """Read/select rows from tables or views."""
    INSERT = 2
    """Insert new rows into tables."""
    UPDATE = 3
    """Update existing rows."""
    DELETE = 4
    """Delete rows."""
    TRUNCATE = 5
    """Remove all rows from a table quickly."""
    REFERENCES = 6
    """Grant foreign-key references to a table."""
    TRIGGER = 7
    """Create triggers on tables."""
    CREATE = 8
    """Create new objects (e.g., tables, schemas)."""
    CONNECT = 9
    """Connect to the database."""
    TEMPORARY = 10
    """Create temporary tables."""
    EXECUTE = 11
    """Execute functions or procedures."""
    USAGE = 12
    """Use an object (e.g., schema, sequence) without altering it."""
    SET = 13
    """Set certain run-time parameters for a role/session."""
    ALTER_SYSTEM = 14
    """Alter system-wide settings."""


@dataclass(frozen=True)
class DatabaseConnect:
    """Representation the target database for a connection.

    This lightweight class holds the logical name of a database that clients
    or connection factories can use to select which database to connect to.
    It does not perform any connection logic or validation itself.

    Attributes:
        database_name (str): The name or identifier of the database (e.g. "mydb").
            This should be set to the value expected by the underlying database
            driver or connection string. The class does not enforce any format
            or perform validation on this value.

    Example:
        >>> db = DatabaseConnect("production_db")
        >>> db.database_name
        'production_db'
    """

    database_name: str


@dataclass(frozen=True)
class SchemaUsage:
    """Representation of how a schema is used.

    This class describes a single usage of a schema by name and whether that
    usage is direct (explicit) or indirect (inherited/implicit). It is intended
    to be a lightweight data holder for components that need to track schema
    references.

    Attributes:
        schema_name (str): The name or identifier of the schema being referenced.
        direct (bool): Whether the usage is a direct (explicit) reference.
            Defaults to False for indirect or inferred usage.

    Example:
        >>> SchemaUsage(schema_name="user_profile", direct=True)
    """

    schema_name: str
    direct: bool = False


@dataclass(frozen=True)
class SchemaCreate:
    """Representation of a schema to be created.

    This lightweight dataclass describes a request to create a schema and whether
    that request is direct (explicit) or indirect (inferred). It is intended as
    a simple data holder used by sync_roles to determine which schemas should be
    created for a role.

    Attributes:
        schema_name (str): The name of the schema to create.
        direct (bool): Avoid using intermediate roles and grant the permission
            directly to the role. Defaults to False for indirect/inferred creation.
    """

    schema_name: str
    direct: bool = False


@dataclass(frozen=True)
class SchemaOwnership:
    """Representation of ownership of a schema.

    Attributes:
        schema_name (str): The name of the schema that is owned.
    """

    schema_name: str


@dataclass(frozen=True)
class TableSelect:
    """Representation of a table selection within a schema.

    This dataclass describes a table (or a set of tables matched by a regular
    expression) that should be considered for granting privileges. It is a
    lightweight data holder used by sync_roles() to represent either a single
    table name or a pattern matching multiple tables.

    Attributes:
        schema_name (str): Name of the schema containing the table(s).
        table_name (str | re.Pattern): Either an exact table name or a compiled
            regular expression to match multiple table names.
        direct (bool): Avoid using intermediate roles and grant the permission
            directly to the role. Defaults to False for indirect/inferred creation.
    """

    schema_name: str
    table_name: str | Pattern
    direct: bool = False


@dataclass(frozen=True)
class Login:
    """Representation of login credentials and their validity for a role.

    Attributes:
        valid_until (datetime | None): The UTC expiration time of the role's
            login, or None for no expiration.
        password (str | None): The password to set for the role, or None to
            leave the password unchanged or unset.
    """

    valid_until: datetime | None = None
    password: str | None = None


@dataclass(frozen=True)
class RoleMembership:
    """Representation of a role membership.

    Attributes:
        role_name (str): The name of the role that the membership refers to.
    """

    role_name: str
