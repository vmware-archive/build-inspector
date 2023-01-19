# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import sys
import os
import yara

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "code"))
from parsers.pip import PipParser
from models import ExtractedDependency, ExtractedFinding, DependencyRelation, FindingSeverity


def test_yara_rule():
    # Arrange
    POSITIVE_TEST_STRINGS = [
        "pip install yara",
        "pip -q install test",
        "pip3 install test",
        "pip -abcd install somethingsomething"
    ]
    NEGATIVE_TEST_STRINGS = [
        "pipenv install",
        "pip freeze"
    ]
    rule = yara.compile(sources={
        "pytest": PipParser.yara_rule
    })
    
    # Act/Assert
    for string in POSITIVE_TEST_STRINGS:
        result = rule.match(data=string)
        assert result != []
    for string in NEGATIVE_TEST_STRINGS:
        result = rule.match(data=string)
        assert result == []


def test_on_load():
    # Arrange

    # Act
    PipParser().on_load()


def test_get_document_dependencies():
    # Arrange
    TEST_DOCUMENT = """
Collecting boto3==1.9.183
  Downloading boto3-1.9.183-py2.py3-none-any.whl (128 kB)
Collecting botocore<1.13.0,>=1.12.183
  Downloading botocore-1.12.253-py2.py3-none-any.whl (5.7 MB)
Collecting docutils<0.16,>=0.10
  Downloading docutils-0.15.2-py3-none-any.whl (547 kB)
    """
    expected = [
        ExtractedDependency(
            name="boto3",
            version="1.9.183-py2.py3-none-any",
            type="python",
            result=DependencyRelation.CONSUMED,
            extraction_source="Downloading boto3-1.9.183-py2.py3-none-any.whl",
            download_location="Unknown"
        ),
        ExtractedDependency(
            name="botocore",
            version="1.12.253-py2.py3-none-any",
            type="python",
            result=DependencyRelation.CONSUMED,
            extraction_source="Downloading botocore-1.12.253-py2.py3-none-any.whl",
            download_location="Unknown"
        ),
        ExtractedDependency(
            name="docutils",
            version="0.15.2-py3-none-any",
            type="python",
            result=DependencyRelation.CONSUMED,
            extraction_source="Downloading docutils-0.15.2-py3-none-any.whl",
            download_location="Unknown"
        ),
    ]
    parser = PipParser()

    # Act
    result = parser.get_document_dependencies(document=TEST_DOCUMENT)

    # Assert
    assert result == expected


def test_get_document_dependencies__non_pypi():
    # Arrange
    TEST_DOCUMENT = """
Collecting hg-evolve
  Downloading https://files.pythonhosted.org/packages/f5/e8/e63ca238ef785660c0bc7a5a8f7d345cea5f372229405f99abd40c645553/hg-evolve-10.5.1.tar.gz (845kB)
    """
    expected = [
        ExtractedDependency(
            name="hg-evolve",
            version="10.5.1",
            type="python",
            result=DependencyRelation.CONSUMED,
            extraction_source=(
                "Downloading "
                "https://files.pythonhosted.org/packages/f5/e8/e63ca238ef785660c0bc7a5a8f7d345cea5f372229405f99abd40c645553/hg-evolve-10.5.1.tar.gz"
            ),
            download_location=(
                "https://files.pythonhosted.org/packages/f5/e8/e63ca238ef785660c0bc7a5a8f7d345cea5f372229405f99abd40c645553/hg-evolve-10.5.1.tar.gz"
            )
        ),
    ]
    parser = PipParser()

    # Act
    result = parser.get_document_dependencies(document=TEST_DOCUMENT)

    # Assert
    assert result == expected


def test_get_document_findings():
    # Arrange
    TEST_DOCUMENT = """
pip install -q something
pip3 install --quiet some other things
    """
    expected = [
        ExtractedFinding(
            source='PipParser',
            description=(
                'The Pip parser is unable to parse dependency information for quiet installs. Please remove the '
                'quiet flag from this install.'
            ),
            offset=0,
            finding_data='pip install -q something\n',
            severity=FindingSeverity.INFORMATIONAL,
            category='dependency-collection'
        ),
        ExtractedFinding(
            source='PipParser',
            description=(
                'The Pip parser is unable to parse dependency information for quiet installs. '
                'Please remove the quiet flag from this install.'
            ),
            offset=0,
            finding_data='pip3 install --quiet some other things\n',
            severity=FindingSeverity.INFORMATIONAL,
            category='dependency-collection'
        )
    ]
    parser = PipParser()

    # Act
    result = parser.get_document_findings(document=TEST_DOCUMENT)

    # Assert
    assert result == expected
