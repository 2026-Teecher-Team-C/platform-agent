"""OS에 의존하는 코드는 이 패키지에만 둔다. 나머지 에이전트 코드는 OS를 모른다.

스풀 파일은 어떤 자동 파서(인덱서·썸네일러·백신)도 처리 대상으로 판단하지 않아야 한다
(설계 문서 7장 — CVE-2010-2568, CVE-2017-11421, CVE-2017-0290).
"""

import sys

from agent.platform.base import SpoolFile

if sys.platform == "darwin":
    from agent.platform.macos import create_spool_file, prepare_spool_dir
elif sys.platform == "win32":
    from agent.platform.windows import create_spool_file, prepare_spool_dir
else:
    from agent.platform.linux import create_spool_file, prepare_spool_dir

__all__ = ["SpoolFile", "create_spool_file", "prepare_spool_dir"]
