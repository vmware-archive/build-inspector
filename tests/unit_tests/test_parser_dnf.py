# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import sys
import os
import yara

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "code"))
from parsers.dnf import DNFParser
from models import ExtractedDependency, ExtractedFinding, DependencyRelation, FindingSeverity


def test_yara_rule():
    # Arrange
    POSITIVE_TEST_STRINGS = [
        " dnf install go",
        " dnf update go",
        " dnf update ",
    ]
    NEGATIVE_TEST_STRINGS = [
        "yum install dnf",
        "dnf --version",
    ]
    rule = yara.compile(sources={
        "pytest": DNFParser.yara_rule
    })

    # Act/Assert
    for string in POSITIVE_TEST_STRINGS:
        result = rule.match(data=string)
        assert result != []
    for string in NEGATIVE_TEST_STRINGS:
        result = rule.match(data=string)
        assert result == []


def test_on_load():
    DNFParser().on_load()


def test_get_document_dependencies():
    TEST_DATA = """
     dnf install go
    Last metadata expiration check: 0:01:44 ago on Mon Feb 13 11:10:09 2023.
    Dependencies resolved.
    ==========================================================================================================================================================================================================================
     Package                                                        Architecture                               Version                                                      Repository                                   Size
    ==========================================================================================================================================================================================================================
    Installing:
     golang                                                         x86_64                                     1.19.5-1.fc37                                                updates                                     579 k
    Installing dependencies:
     apr                                                            x86_64                                     1.7.2-2.fc37                                                 updates                                     127 k
     apr-util                                                       x86_64                                     1.6.3-2.fc37                                                 updates                                      96 k
     binutils                                                       x86_64                                     2.38-25.fc37                                                 updates                                     5.4 M'
    Installed:
      apr-1.7.2-2.fc37.x86_64                                apr-util-1.6.3-2.fc37.x86_64                   
      binutils-2.38-25.fc37.x86_64      
    """

    expected_output = [
        ExtractedDependency(
            name='apr',
            version='1.7.2-2.fc37',
            type='Fedora',
            result=DependencyRelation.CONSUMED,
            extraction_source='apr1.7.2-2.fc37x86_64.rpm',
            download_location='Fedora'
        ),
        ExtractedDependency(
            name='apr-util',
            version='1.6.3-2.fc37',
            type='Fedora',
            result=DependencyRelation.CONSUMED,
            extraction_source='apr-util1.6.3-2.fc37x86_64.rpm',
            download_location='Fedora'
        ),
        ExtractedDependency(
            name= 'binutils',
            version= '2.38-25.fc37',
            type= 'Fedora',
            result= DependencyRelation.CONSUMED,
            extraction_source= 'binutils2.38-25.fc37x86_64.rpm',
            download_location= 'Fedora'
        )
    ]

    parser = DNFParser()
    result = parser.get_document_dependencies(document=TEST_DATA)
    assert result == expected_output

