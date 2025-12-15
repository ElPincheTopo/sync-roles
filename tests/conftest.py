import uuid

import pytest
import sqlalchemy as sa

try:
    # psycopg2
    import psycopg2  # noqa: F401

    engine_type = 'postgresql+psycopg2'
except ImportError:
    # psycopg3
    import psycopg  # noqa: F401

    engine_type = 'postgresql+psycopg'

engine_future = {'future': True} if tuple(int(v) for v in sa.__version__.split('.')) < (2, 0, 0) else {}

# By 4000 roles having permission to something, we get "row is too big" errors, so it's a good
# number to test on to make sure we don't hit that issue
ROLES_PER_TEST = 4000

# The default/root database that comes with the PostgreSQL Docker image
ROOT_DATABASE_NAME = 'postgres'

# We make and drop a database in each test to keep them isolated
TEST_DATABASE_NAME = 'pg_sync_roles_test'
TEST_BASE_ROLE = 'test_pgsr_base_role'


@pytest.fixture
def root_engine():
    return sa.create_engine(f'{engine_type}://postgres:postgres@127.0.0.1:5432/{ROOT_DATABASE_NAME}', **engine_future)


@pytest.fixture
def test_engine(root_engine):
    syncing_user = f'test_syncing_user_{uuid.uuid4().hex}'

    def drop_database_if_exists(conn):
        # Recent versions of PostgreSQL have a `WITH (force)` option to DROP DATABASE which kills
        # conections, but we run tests on older versions that don't support this.
        conn.execute(
            sa.text(f"""
            SELECT pg_terminate_backend(pg_stat_activity.pid)
            FROM pg_stat_activity
            WHERE pg_stat_activity.datname = '{TEST_DATABASE_NAME}'
            AND pid != pg_backend_pid();
        """),
        )
        conn.execute(sa.text(f'DROP DATABASE IF EXISTS {TEST_DATABASE_NAME}'))
        memberships = conn.execute(
            sa.text("""
            SELECT roleid::regrole, member::regrole
            FROM pg_auth_members
            WHERE member::regrole::text LIKE 'test\\_%' OR member::text LIKE '\\_pgsr\\_%'
        """),
        ).fetchall()
        for role, member in memberships:
            conn.execute(sa.text(f'REVOKE {role} FROM {member} CASCADE'))

        roles = conn.execute(
            sa.text("""
            SELECT rolname FROM pg_roles WHERE rolname LIKE 'test\\_%' OR rolname LIKE '\\_pgsr\\_%'
        """),
        ).fetchall()
        for (role,) in roles:
            conn.execute(sa.text(f'REVOKE ALL PRIVILEGES ON DATABASE {ROOT_DATABASE_NAME} FROM {role}'))
            conn.execute(sa.text(f'DROP ROLE {role}'))

    with root_engine.connect() as conn:
        conn.execution_options(isolation_level='AUTOCOMMIT')
        drop_database_if_exists(conn)
        conn.execute(sa.text(f'CREATE DATABASE {TEST_DATABASE_NAME}'))
        conn.execute(sa.text(f'REVOKE CONNECT ON DATABASE {TEST_DATABASE_NAME} FROM PUBLIC'))

    with root_engine.begin() as conn:
        conn.execute(sa.text(f"CREATE ROLE {syncing_user} WITH CREATEROLE LOGIN PASSWORD 'password'"))
        conn.execute(sa.text(f'ALTER DATABASE {TEST_DATABASE_NAME} OWNER TO {syncing_user}'))

    # The NullPool prevents default connection pooling, which interfers with tests that
    # terminate connections
    yield sa.create_engine(
        f'{engine_type}://{syncing_user}:password@127.0.0.1:5432/{TEST_DATABASE_NAME}',
        poolclass=sa.pool.NullPool,
        **engine_future,
    )

    with root_engine.connect() as conn:
        conn.execution_options(isolation_level='AUTOCOMMIT')
        drop_database_if_exists(conn)


@pytest.fixture
def test_table(root_engine, test_engine):
    schema_name = f'test_schema_{uuid.uuid4().hex}'
    table_name = f'test_table_{uuid.uuid4().hex}'

    with test_engine.begin() as conn:
        conn.execute(sa.text(f'CREATE SCHEMA {schema_name}'))
        conn.execute(sa.text(f'CREATE TABLE {schema_name}.{table_name} (id int)'))

    yield schema_name, table_name

    with root_engine.begin() as conn:
        conn.execute(sa.text(f'DROP TABLE IF EXISTS {schema_name}.{table_name}'))
        conn.execute(sa.text(f'DROP SCHEMA IF EXISTS {schema_name}'))


@pytest.fixture
def create_test_table(root_engine, test_engine):
    schema_table_names = []

    def _create_test_table(schema_name, table_name):
        schema_table_names.append((schema_name, table_name))

        with test_engine.begin() as conn:
            conn.execute(sa.text(f'CREATE SCHEMA IF NOT EXISTS {schema_name}'))
            conn.execute(sa.text(f'CREATE TABLE {schema_name}.{table_name} (id int)'))

    yield _create_test_table

    with root_engine.begin() as conn:
        for schema_name, table_name in schema_table_names:
            conn.execute(sa.text(f'DROP TABLE IF EXISTS {schema_name}.{table_name}'))
            conn.execute(sa.text(f'DROP SCHEMA IF EXISTS {schema_name}'))


@pytest.fixture
def test_view(test_engine, test_table):
    schema_name, table_name = test_table

    view_name = f'test_view_{uuid.uuid4().hex}'

    with test_engine.begin() as conn:
        conn.execute(sa.text(f'CREATE VIEW {schema_name}.{view_name} AS SELECT * FROM {schema_name}.{table_name}'))

    yield schema_name, view_name

    with test_engine.begin() as conn:
        conn.execute(sa.text(f'DROP VIEW IF EXISTS {schema_name}.{view_name}'))


@pytest.fixture
def test_sequence(test_engine, test_table):
    schema_name, _ = test_table

    sequence_name = f'test_sequence_{uuid.uuid4().hex}'

    with test_engine.begin() as conn:
        conn.execute(sa.text(f'CREATE SEQUENCE {schema_name}.{sequence_name} START 101;'))

    yield schema_name, sequence_name

    with test_engine.begin() as conn:
        conn.execute(sa.text(f'DROP SEQUENCE IF EXISTS {schema_name}.{sequence_name}'))


@pytest.fixture
def test_sqlite_engine():
    engine = sa.create_engine('sqlite:///:memory:', **engine_future)
    yield engine
    engine.dispose()
