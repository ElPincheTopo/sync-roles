import re
import zoneinfo
from datetime import UTC
from datetime import datetime

import pytest

from sync_roles import Login
from sync_roles.adapters.postgres import PostgresAdapter
from sync_roles.models import DatabaseConnect
from sync_roles.models import DbObjectType
from sync_roles.models import Grant
from sync_roles.models import GrantOperation
from sync_roles.models import GrantOperationType
from sync_roles.models import Privilege
from sync_roles.models import PrivilegeRecord
from sync_roles.models import RoleMembership
from sync_roles.models import SchemaCreate
from sync_roles.models import SchemaOwnership
from sync_roles.models import SchemaUsage
from sync_roles.models import TableSelect

NZ_TZ = zoneinfo.ZoneInfo('Pacific/Auckland')


@pytest.mark.parametrize(
    ('grant', 'type_', 'name', 'privilege'),
    [
        (Login(), DbObjectType.DATABASE, '', Privilege.LOGIN),
        (
            Login(valid_until=datetime(2000, 1, 1)),
            DbObjectType.DATABASE,
            '2000-01-01T00:00:00.000000+00:00',
            Privilege.LOGIN,
        ),
        (
            Login(valid_until=datetime(2000, 1, 1, tzinfo=UTC)),
            DbObjectType.DATABASE,
            '2000-01-01T00:00:00.000000+00:00',
            Privilege.LOGIN,
        ),
        (
            Login(valid_until=datetime(2000, 1, 1, tzinfo=NZ_TZ)),
            DbObjectType.DATABASE,
            '2000-01-01T00:00:00.000000+13:00',
            Privilege.LOGIN,
        ),
        (Login(password='some-password'), DbObjectType.DATABASE, 'P', Privilege.LOGIN),
        (
            Login(valid_until=datetime(2000, 1, 1), password='some-password'),
            DbObjectType.DATABASE,
            '2000-01-01T00:00:00.000000+00:00P',
            Privilege.LOGIN,
        ),
        (
            Login(valid_until=datetime(2000, 1, 1, tzinfo=UTC), password='some-password'),
            DbObjectType.DATABASE,
            '2000-01-01T00:00:00.000000+00:00P',
            Privilege.LOGIN,
        ),
        (
            Login(valid_until=datetime(2000, 1, 1, tzinfo=NZ_TZ), password='some-password'),
            DbObjectType.DATABASE,
            '2000-01-01T00:00:00.000000+13:00P',
            Privilege.LOGIN,
        ),
        (
            RoleMembership(role_name='some-role'),
            DbObjectType.ROLE,
            'some-role',
            Privilege.ROLE_MEMBERSHIP,
        ),
        (
            SchemaOwnership(schema_name='public'),
            DbObjectType.SCHEMA,
            'public',
            Privilege.OWN,
        ),
        (
            SchemaUsage(schema_name='public', direct=True),
            DbObjectType.SCHEMA,
            'public',
            Privilege.USAGE,
        ),
        (
            SchemaCreate(schema_name='public', direct=True),
            DbObjectType.SCHEMA,
            'public',
            Privilege.CREATE,
        ),
        (
            TableSelect(schema_name='public', table_name='employees', direct=True),
            DbObjectType.TABLE,
            ('public', 'employees'),
            Privilege.SELECT,
        ),
    ],
)
def test_build_proposed_permission_in_base_adapter(
    test_engine,
    grant: Grant,
    type_: DbObjectType,
    name: str,
    privilege: Privilege,
) -> None:
    user = 'tun'
    with test_engine.connect() as conn:
        adapter = PostgresAdapter(conn)
        assert adapter.build_proposed_permission(user, grant) == {PrivilegeRecord(type_, name, privilege, user, grant)}


@pytest.mark.parametrize(
    ('grant', 'type_', 'name', 'privilege'),
    [
        (
            DatabaseConnect(database_name='some_database'),
            DbObjectType.DATABASE,
            'some_database',
            Privilege.CONNECT,
        ),
        (
            SchemaUsage(schema_name='public', direct=False),
            DbObjectType.SCHEMA,
            'public',
            Privilege.USAGE,
        ),
        (
            SchemaCreate(schema_name='public', direct=False),
            DbObjectType.SCHEMA,
            'public',
            Privilege.CREATE,
        ),
        (
            TableSelect(schema_name='public', table_name='a_table', direct=False),
            DbObjectType.TABLE,
            ('public', 'a_table'),
            Privilege.SELECT,
        ),
    ],
)
def test_build_proposed_permission_in_postgres_adapter(
    test_engine,
    grant: Grant,
    type_: DbObjectType,
    name: str,
    privilege: Privilege,
) -> None:
    user = 'tun'
    with test_engine.connect() as conn:
        adapter = PostgresAdapter(conn)
        result = adapter.build_proposed_permission(user, grant)
        assert len(result) == 2

        result1 = next(p for p in result if p.object_type == type_)
        result2 = next(p for p in result if p.object_type == DbObjectType.ROLE)

        assert result1.object_type == type_
        assert result1.object_name == name
        assert result1.privilege == privilege
        assert result1.grantee != user
        assert isinstance(result1.grantee, str)
        assert re.match(r'_pgsr_(?:local|global)(?:_(?:[0-9]+))?_(?:[0-9a-z_]+)_(?:[0-9a-z]+)', result1.grantee)
        assert result1.grant == grant

        assert result2.object_type == DbObjectType.ROLE
        assert isinstance(result2.object_name, str)
        assert re.match(r'_pgsr_(?:local|global)(?:_(?:[0-9]+))?_(?:[0-9a-z_]+)_(?:[0-9a-z]+)', result2.object_name)
        assert result2.privilege == Privilege.ROLE_MEMBERSHIP
        assert result2.grantee == user
        assert result2.grant is None

        assert result1.grantee == result2.object_name


def test_grant_raises(test_engine) -> None:
    msg = (
        'Unrecognised privilege type <GrantOperationType.CREATE: 3> for grant: '
        'GrantOperation(type_=<GrantOperationType.CREATE: 3>, privilege=PrivilegeRecord('
        "object_type=<DbObjectType.DATABASE: 1>, object_name='a_database', privilege=<Privilege.CONNECT: 9>, "
        "grantee='tun', grant=None))"
    )
    with test_engine.connect() as conn:
        adapter = PostgresAdapter(conn)
        with pytest.raises(ValueError, match=re.escape(msg)):
            adapter.grant(
                GrantOperation(
                    GrantOperationType.CREATE,
                    PrivilegeRecord(DbObjectType.DATABASE, 'a_database', Privilege.CONNECT, 'tun', None),
                ),
            )


def test_get_roles_with_no_role_names(test_engine) -> None:
    with test_engine.connect() as conn:
        adapter = PostgresAdapter(conn)
        assert adapter.get_roles() == []
