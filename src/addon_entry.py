"""mitmdump 진입점. 저장소 루트에서: `mitmdump -s src/addon_entry.py`

mitmdump -s 는 스크립트 디렉터리를 sys.path 맨 앞에 넣는다. 이 파일을 src/ 에 두면 `agent`·`teecher`를
그대로 import할 수 있고, src/agent/platform/ 이 표준 라이브러리 platform을 가리는 일도 없다.

코드를 고쳤으면 mitmdump를 재시작한다. 핫 리로드는 이 파일만 감시하고(agent.addon은 sys.modules에
캐시된 옛 코드가 그대로 쓰인다), 옛 인스턴스의 async done()을 동기로 불러 실패한 채 넘어간다.
"""

from agent.addon import HoldPipeline

addons = [HoldPipeline()]
