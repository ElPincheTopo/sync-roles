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
        (
            DatabaseConnect(database_name='some_database'),
            DbObjectType.DATABASE,
            'some_database',
            Privilege.CONNECT,
        ),
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
def test_build_proposed_permission(
    test_engine,
    grant: Grant,
    type_: DbObjectType,
    name: str,
    privilege: Privilege,
) -> None:
    user = 'tun'
    with test_engine.connect() as conn:
        adapter = PostgresAdapter(conn)
        assert super(PostgresAdapter, adapter).build_proposed_permission(user, grant) == {
            PrivilegeRecord(type_, name, privilege, user, grant),
        }


@pytest.mark.parametrize('direct', [True, False])
def test_build_proposed_permission_for_table_select_raises(test_engine, direct: bool) -> None:
    msg = (
        "Table name on Grant TableSelect(schema_name='public', table_name=re.compile('emp.*'), "
        f"direct={direct}) should be of type `str`, got `re.compile('emp.*')`"
    )
    with test_engine.connect() as conn:
        adapter = PostgresAdapter(conn)
        with pytest.raises(ValueError, match=re.escape(msg)):
            super(PostgresAdapter, adapter).build_proposed_permission(
                'tun',
                TableSelect(schema_name='public', table_name=re.compile(r'emp.*'), direct=direct),
            )
