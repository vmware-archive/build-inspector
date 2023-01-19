# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import json
import sys
import os
from pytest import fixture
import xml.etree.ElementTree

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "code"))
from formatters.spdx import SPDXBaseFormatter, SPDXJsonFormatter, SPDXXMLFormatter
from formatters.base import BaseFormatter
from models import ExtractedFinding, ExtractedDependency, DocumentReport, FindingSeverity, DependencyRelation

@fixture
def mock_finding():
    MOCK_FINDING = ExtractedFinding(
        source = "MOCK SOURCE",
        description = "MOCK DESCRIPTION",
        offset = 0,
        finding_data = "MOCK DATA",
        severity = FindingSeverity.INFORMATIONAL,
        category = "MOCK CATEGORY"
    )
    return MOCK_FINDING

@fixture
def mock_dependency():
    MOCK_DEPENDENCY = ExtractedDependency(
        name = "MOCK DEPENDENCY",
        version = "MOCK VERSION",
        type = "MOCK TYPE",
        result = DependencyRelation.CONSUMED,
        extraction_source = "MOCK SOURCE",
        download_location = "MOCK LOCATION"
    )
    return MOCK_DEPENDENCY

@fixture
def mock_report(mock_finding, mock_dependency):
    MOCK_REPORT = DocumentReport(
        findings = [mock_finding],
        dependencies = [mock_dependency]
    )
    return MOCK_REPORT

def test_proper_inheritance():
    # Arrange
    EXPECTED_BASE = BaseFormatter

    # Act
    JSONformatter = SPDXJsonFormatter
    XMLformatter = SPDXXMLFormatter

    # Assert
    assert issubclass(JSONformatter, EXPECTED_BASE)
    assert issubclass(XMLformatter, EXPECTED_BASE)

def test_JSON_format_findings(mock_finding):
    # Act
    result = SPDXJsonFormatter.format_findings([mock_finding])

    # Assert
    assert json.loads(result) # Is valid JSON data
    result_obj = json.loads(result)
    assert isinstance(result_obj, dict) # The return is a dict object
    assert result_obj != {} # Is not blank

def test_JSON_format_dependencies(mock_dependency):
    # Act
    result = SPDXJsonFormatter.format_dependencies([mock_dependency])

    # Assert
    assert json.loads(result) # Is valid JSON data
    result_obj = json.loads(result)
    assert isinstance(result_obj, list) # The return is a list
    assert result_obj != [] # Is not blank
    assert len(result_obj) == 1 # It has 1 dependency

def test_JSON_format_report(mock_report):
    # Act
    result = SPDXJsonFormatter.format_report(mock_report)

    # Assert
    assert json.loads(result) # Is valid JSON data
    result_obj = json.loads(result)
    assert isinstance(result_obj, list) # The return is a list
    assert result_obj != [] # Is not blank
    assert len(result_obj) == 2 # It has 1 dependency and 1 base document

def test_XML_format_findings(mock_finding):
    # Act
    result = SPDXXMLFormatter.format_findings([mock_finding])

    # Assert
    assert xml.etree.ElementTree.fromstring(result) # is valid XML data
    result_obj = xml.etree.ElementTree.fromstring(result)
    assert result_obj.tag == "SpdxDocument"

def test_XML_format_dependencies(mock_dependency):
    # Act
    result = SPDXXMLFormatter.format_dependencies([mock_dependency])

    # Assert
    documents = result.split('\n---\n')
    for document in documents:
        assert xml.etree.ElementTree.fromstring(document) # is valid XML data
        result_obj = xml.etree.ElementTree.fromstring(document)
        assert result_obj.tag == "SpdxDocument"

def test_XML_format_report(mock_report):
    # Act
    result = SPDXXMLFormatter.format_report(mock_report)

    # Assert
    documents = result.split('\n---\n')
    for document in documents:
        assert xml.etree.ElementTree.fromstring(document) # is valid XML data
        result_obj = xml.etree.ElementTree.fromstring(document)
        assert result_obj.tag == "SpdxDocument"
