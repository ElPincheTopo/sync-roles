import pytest

from sync_roles.core import _get_adapter


def test_get_adapter_raises(test_sqlite_engine) -> None:
    with pytest.raises(ValueError, match='Unsupported database dialect: sqlite'):
        _get_adapter(test_sqlite_engine)
