# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import sys
import os
import yara

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "code"))
from parsers.goget import GoGetParser
from models import ExtractedDependency, ExtractedFinding, DependencyRelation, FindingSeverity


def test_yara_rule():
    # Arrange
    POSITIVE_TEST_STRINGS = [
        "go get example.com/pkg",
        "go get example.com/pkg@v1.2.3",
        "RUN go get -v example.com/mod@none",
        "INFO[0017] RUN go get -u github.com/zmap/zgrab2 && cd $GOPATH/src/github.com/zmap/zgrab2*"
    ]
    NEGATIVE_TEST_STRINGS = [
        "#6 [resource  3/23] RUN apt install -y --no-install-recommends  go get     gzip",
        "#7 [resource  4/23] RUN apt install go get",
    ]
    rule = yara.compile(sources={
        "pytest": GoGetParser.yara_rule
    })

    # Act/Assert
    for string in POSITIVE_TEST_STRINGS:
        result = rule.match(data=string)
        assert result != []
    for string in NEGATIVE_TEST_STRINGS:
        result = rule.match(data=string)
        assert result == []


def test_on_load():
    GoGetParser().on_load()


def test_get_document_dependencies():
    TEST_DATA = """
    go get example.com/pkg
    go get example.com/pkg@v1.2.3
    RUN go get -v example.com/mod@none

    INFO[0017] RUN go get -u github.com/zmap/zgrab2 && cd $GOPATH/src/github.com/zmap/zgrab2* 

    #6 [resource  3/23] RUN apt install -y --no-install-recommends    go get     gzip     jq     openssl     libssl-dev     make     g++     openssh-client     libstdc++6 
    """

    expected_output = [
        ExtractedDependency(
            name='example.com/pkg',
            version='Unknown',
            type='go-get',
            result=DependencyRelation.CONSUMED,
            extraction_source='go get example.com/pkg',
            download_location='example.com/pkg'
        ),
        ExtractedDependency(
            name='example.com/pkg@v1.2.3',
            version='1.2.3',
            type='go-get',
            result=DependencyRelation.CONSUMED,
            extraction_source='go get example.com/pkg@v1.2.3',
            download_location='example.com/pkg@v1.2.3'
        ),
        ExtractedDependency(
            name='example.com/mod@none',
            version='Unknown',
            type='go-get',
            result=DependencyRelation.CONSUMED,
            extraction_source='RUN go get -v example.com/mod@none',
            download_location='example.com/mod@none'
        ),
        ExtractedDependency(
            name='github.com/zmap/zgrab2',
            version='Unknown',
            type='go-get',
            result=DependencyRelation.CONSUMED,
            extraction_source='RUN go get -u github.com/zmap/zgrab2',
            download_location='github.com/zmap/zgrab2'
        )
    ]

    parser = GoGetParser()
    result = parser.get_document_dependencies(document=TEST_DATA)
    assert result == expected_output

