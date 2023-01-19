# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import sys
import os
import yara

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "code"))
from parsers.curl import CurlParser
from models import ExtractedDependency, ExtractedFinding, DependencyRelation, FindingSeverity


def test_yara_rule():
    # Arrange
    POSITIVE_TEST_STRINGS = [
        "curl -o output.txt http://example.com",
        "curl https://httpstat.us/400 -f",
        "curl http://executable.sh | bash",
        "curl ftp://user@host/foo/bar.txt",
        "curl www.helloworld.com > test.file"
    ]
    NEGATIVE_TEST_STRINGS = [
        "#6 [resource  3/23] RUN apt install -y --no-install-recommends     curl     gnupg     gzip",
        "#7 [resource  4/23] RUN apt install lib-curl",
    ]
    rule = yara.compile(sources={
        "pytest": CurlParser.yara_rule
    })

    # Act/Assert
    for string in POSITIVE_TEST_STRINGS:
        result = rule.match(data=string)
        assert result != []
    for string in NEGATIVE_TEST_STRINGS:
        result = rule.match(data=string)
        assert result == []


def test_on_load():
    CurlParser().on_load()


def test_get_document_dependencies():
    TEST_DATA = """
    curl -o output.txt http://example.com
    curl https://httpstat.us/400 -f
    curl http://executable.sh | bash
    curl ftp://user@host/foo/bar.txt
    curl www.helloworld.com > test.file

    8 [resource  5/23] RUN curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | bash

    6 [resource  3/23] RUN apt install -y --no-install-recommends     curl     gnupg     gzip     jq     openssl     libssl-dev     make     g++     openssh-client     libstdc++6     software-properties-common
    """

    expected_output = [
        ExtractedDependency(
            name='example.com',
            version='Unknown',
            type='curl',
            result=DependencyRelation.CONSUMED,
            extraction_source='curl -o output.txt http://example.com',
            download_location='http://example.com'
        ),
        ExtractedDependency(
            name='httpstat.us/400',
            version='Unknown',
            type='curl',
            result=DependencyRelation.CONSUMED,
            extraction_source='curl https://httpstat.us/400',
            download_location='https://httpstat.us/400'
        ),
        ExtractedDependency(
            name='executable.sh',
            version='Unknown',
            type='curl',
            result=DependencyRelation.CONSUMED,
            extraction_source='curl http://executable.sh',
            download_location='http://executable.sh'
        ),
        ExtractedDependency(
            name='user@host/foo/bar.txt',
            version='Unknown',
            type='curl',
            result=DependencyRelation.CONSUMED,
            extraction_source='curl ftp://user@host/foo/bar.txt',
            download_location='ftp://user@host/foo/bar.txt'
        ),
        ExtractedDependency(
            name='helloworld.com',
            version='Unknown',
            type='curl',
            result=DependencyRelation.CONSUMED,
            extraction_source='curl www.helloworld.com',
            download_location='www.helloworld.com'
        ),
        ExtractedDependency(
            name='packagecloud.io/install/repositories/github/git-lfs/script.deb.sh',
            version='Unknown',
            type='curl',
            result=DependencyRelation.CONSUMED,
            extraction_source='RUN curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh',
            download_location='https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh'
        )
    ]

    parser = CurlParser()
    result = parser.get_document_dependencies(document=TEST_DATA)
    assert result == expected_output

