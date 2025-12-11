"""Database-agnostic grant models."""

from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from enum import Enum
from enum import auto
from re import Pattern


class Privilege(Enum):
    """Enumeration of database/object privileges.

    Each member denotes a specific privilege that can be granted to roles or users
    (e.g., on tables, schemas, functions, or the database). Members carry stable
    integer values used for compact storage and serialization.
    """

    SELECT = auto()
    """Read/select rows from tables or views."""
    INSERT = auto()
    """Insert new rows into tables."""
    UPDATE = auto()
    """Update existing rows."""
    DELETE = auto()
    """Delete rows."""
    TRUNCATE = auto()
    """Remove all rows from a table quickly."""
    REFERENCES = auto()
    """Grant foreign-key references to a table."""
    TRIGGER = auto()
    """Create triggers on tables."""
    CREATE = auto()
    """Create new objects (e.g., tables, schemas)."""
    CONNECT = auto()
    """Connect to the database."""
    TEMPORARY = auto()
    """Create temporary tables."""
    EXECUTE = auto()
    """Execute functions or procedures."""
    USAGE = auto()
    """Use an object (e.g., schema, sequence) without altering it."""
    SET = auto()
    """Set certain run-time parameters for a role/session."""
    ALTER_SYSTEM = auto()
    """Alter system-wide settings."""
    OWN = auto()
    """Own an object, granting all privileges on it."""
    LOGIN = auto()
    """Log in to the database."""
    ROLE_MEMBERSHIP = auto()
    """Add a role membership."""
    MAINTAIN = auto()
    """Maintain permission."""


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
    password: str | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        """Custom repr to avoid exposing the password in logs."""
        password_repr = '*****' if self.password is not None else None

        return f'{self.__class__.__name__}(valid_until={self.valid_until!r}, password={password_repr!r})'


@dataclass(frozen=True)
class RoleMembership:
    """Representation of a role membership.

    Attributes:
        role_name (str): The name of the role that the membership refers to.
    """

    role_name: str


Grant = DatabaseConnect | SchemaUsage | SchemaCreate | SchemaOwnership | TableSelect | Login | RoleMembership
SchemaGrant = SchemaUsage | SchemaCreate | SchemaOwnership | TableSelect


class GrantOperationType(Enum):
    """Enumeration of grant operation types."""

    GRANT = auto()
    REVOKE = auto()
    CREATE = auto()


class DbObjectType(Enum):
    """Enumeration of database object types."""

    DATABASE = auto()
    SCHEMA = auto()
    TABLE = auto()
    ROLE = auto()


@dataclass(frozen=True)
class PrivilegeRecord:
    """Representation of a privilege granted to a role on a database object.

    Attributes:
        object_type (str): The type of the database object (e.g., 'table', 'schema').
        object_name (str | tuple[str, str] | None): The name of the object.
            For schema-scoped objects, this is a tuple of (schema, object).
            For database-level objects, this is a string.
        privilege (Privilege | None): The specific privilege granted.
        grantee (str | None): The name of the role or user that has been granted the privilege.
        grant (Grant | None): The original Grant object that led to this privilege record.
    """

    object_type: DbObjectType
    object_name: str | tuple[str, str]
    privilege: Privilege
    grantee: str | None = None
    grant: Grant | None = field(default=None, compare=False)


@dataclass(frozen=True)
class GrantOperation:
    """Representation of a grant operation to be performed.

    Attributes:
        type_ (GrantOperationType): The type of operation (GRANT, REVOKE, CREATE).
        privilege (PrivilegeRecord): The privilege record associated with the operation.
    """

    type_: GrantOperationType
    privilege: PrivilegeRecord


KNOWN_PRIVILEGES = {privilege.name for privilege in Privilege}

TABLE_LIKE = {
    'table',
    'view',
    'materialized view',
    'foreign table',
    'partitioned table',
    'sequence',
}

SCHEMA = {
    'schema',
}

IN_SCHEMA = {
    # Table-like things
    'table',
    'view',
    'materialized view',
    'foreign table',
    'partitioned table',
    'sequence',
    # Type-like things
    'base type',
    'composite type',
    'enum type',
    'pseudo type',
    'range type',
    'multirange type',
    'domain'
    # Function-like things
    'function',
    'procedure',
    'aggregate function',
    'window function',
}
