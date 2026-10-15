"""Checks /app/output/cookie_headers.json against the Cookie headers Chromium actually sent, as
captured by the lab servers while the robot campaign was recorded (tests/expected.json)."""
import json
import os
from pathlib import Path

import pytest

ARTIFACT = Path('/app/output/cookie_headers.json')
EXPECTED = json.loads((Path(__file__).parent / 'expected.json').read_text())
FIRST_PARTY = ('.alderbay.com',)


def entries(header):
    """A Cookie header as its ordered list of entries; null and '' mean no header."""
    if header is None:
        return []
    return [part.strip() for part in header.split(';') if part.strip()]


@pytest.fixture(scope='module')
def answer():
    assert ARTIFACT.is_file() and not ARTIFACT.is_symlink(), f'{ARTIFACT} is missing'
    assert os.path.getsize(ARTIFACT) < 512 * 1024 * 1024
    data = json.loads(ARTIFACT.read_text())
    assert isinstance(data, dict), 'top level must be a JSON object'
    return data


def test_one_value_per_request(answer):
    missing = sorted(set(EXPECTED) - set(answer))
    extra = sorted(set(answer) - set(EXPECTED))
    assert not missing, f'{len(missing)} request ids missing, e.g. {missing[:5]}'
    assert not extra, f'{len(extra)} unknown keys, e.g. {extra[:5]}'
    bad = [k for k, v in answer.items() if v is not None and not isinstance(v, str)]
    assert not bad, f'values must be strings or null, e.g. {bad[:5]}'


def _compare(answer, first_party):
    wrong = []
    for rid, (host, header) in EXPECTED.items():
        if host.endswith(FIRST_PARTY) != first_party:
            continue
        got = answer.get(rid)
        if not (got is None or isinstance(got, str)) or entries(got) != entries(header):
            wrong.append(rid)
    return wrong


def test_alderbay_requests(answer):
    wrong = _compare(answer, True)
    assert not wrong, f'{len(wrong)} alderbay.com requests differ, e.g. {wrong[:5]}'


def test_third_party_requests(answer):
    wrong = _compare(answer, False)
    assert not wrong, f'{len(wrong)} requests to other sites differ, e.g. {wrong[:5]}'
