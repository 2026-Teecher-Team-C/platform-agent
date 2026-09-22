import os
import re
import stat
import sys

import pytest

from agent.platform import create_spool_file, prepare_spool_dir

UUID_TMP = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp$")
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX 권한 비트")


@pytest.fixture
def spool_dir(tmp_path):
    return prepare_spool_dir(tmp_path / "spool")


def create(spool_dir):
    spool_file = create_spool_file(spool_dir)
    os.close(spool_file.fd)
    return spool_file.path


def test_스풀_파일_이름은_UUID_tmp다(spool_dir):
    assert UUID_TMP.match(create(spool_dir).name)


def test_스풀_파일은_매번_새_이름으로_만든다(spool_dir):
    assert create(spool_dir) != create(spool_dir)


@posix_only
def test_스풀_파일은_0600이고_실행_비트가_없다(spool_dir):
    mode = stat.S_IMODE(create(spool_dir).stat().st_mode)

    assert mode == 0o600
    assert not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@posix_only
def test_스풀_디렉터리는_소유자만_접근한다(spool_dir):
    assert stat.S_IMODE(spool_dir.stat().st_mode) == 0o700


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS Spotlight")
def test_macOS_스풀_디렉터리는_Spotlight_색인에서_제외된다(spool_dir):
    assert (spool_dir / ".metadata_never_index").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Search")
def test_Windows_스풀_파일은_색인_제외_속성을_가진다(spool_dir):
    from agent.platform.windows import FILE_ATTRIBUTE_NOT_CONTENT_INDEXED

    path = create(spool_dir)

    assert spool_dir.stat().st_file_attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
    assert path.stat().st_file_attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
