import pytest

from agent.policy import EMPTY_POLICY, Policy
from teecher.agent.v1 import agent_pb2

PINNED = agent_pb2.BYPASS_CATEGORY_PINNED
SECURITY_UPDATE = agent_pb2.BYPASS_CATEGORY_SECURITY_UPDATE


def response(*entries: tuple[str, int]) -> agent_pb2.GetPolicyResponse:
    return agent_pb2.GetPolicyResponse(
        bypass_hosts=[agent_pb2.BypassHost(host=host, category=category) for host, category in entries]
    )


def test_정확한_호스트만_바이패스한다():
    policy = Policy.from_proto(response(("dl.google.com", SECURITY_UPDATE)))

    assert policy.bypass_category("dl.google.com") == SECURITY_UPDATE
    assert policy.bypass_category("x.dl.google.com") is None
    assert policy.bypass_category("google.com") is None
    assert policy.bypass_category("dl.google.com.evil.com") is None


def test_대소문자와_끝의_점은_같은_호스트로_본다():
    policy = Policy.from_proto(response(("DL.Google.com.", SECURITY_UPDATE)))

    assert policy.bypass_category("dl.google.com") == SECURITY_UPDATE
    assert policy.bypass_category("DL.GOOGLE.COM.") == SECURITY_UPDATE


@pytest.mark.parametrize(
    ("host", "category"),
    [
        ("*.google.com", SECURITY_UPDATE),
        ("", PINNED),
        ("a.example", agent_pb2.BYPASS_CATEGORY_UNSPECIFIED),
        ("b.example", 7),
    ],
)
def test_와일드카드_빈_호스트_알_수_없는_분류는_버린다(host, category):
    entry = agent_pb2.BypassHost(host=host)
    entry.category = category  # proto3 enum은 열려 있어 7도 들어간다

    policy = Policy.from_proto(agent_pb2.GetPolicyResponse(bypass_hosts=[entry]))

    assert dict(policy.bypass_hosts) == {}


def test_파일_유형_정책은_보관만_한다():
    ftp = agent_pb2.FileTypePolicy(file_type="exe", inspection_level=agent_pb2.INSPECTION_LEVEL_NONE)

    policy = Policy.from_proto(agent_pb2.GetPolicyResponse(file_type_policies=[ftp]))

    assert policy.file_type_policies == (ftp,)


def test_빈_정책은_아무것도_바이패스하지_않는다():
    assert EMPTY_POLICY.bypass_category("dl.google.com") is None
