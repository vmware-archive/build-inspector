# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "code"))
from formatters.json import JsonFormatter
from formatters.base import BaseFormatter
from models import ExtractedFinding, ExtractedDependency, DocumentReport, FindingSeverity, DependencyRelation

def test_proper_inheritance():
    # Arrange
    EXPECTED_BASE = BaseFormatter

    # Act
    formatter = JsonFormatter

    # Assert
    assert issubclass(formatter, EXPECTED_BASE)

def test_format_findings():
    # Arrange
    MOCK_FINDING = ExtractedFinding(
        source = "MOCK SOURCE",
        description = "MOCK DESCRIPTION",
        offset = 0,
        finding_data = "MOCK DATA",
        severity = FindingSeverity.INFORMATIONAL,
        category = "MOCK CATEGORY"
    )
    MOCK_ERRORS = "MockError"

    # Act
    result = JsonFormatter.format_findings([MOCK_FINDING], [MOCK_ERRORS])

    # Assert
    assert json.loads(result) # Is valid JSON data
    result_obj = json.loads(result)
    assert isinstance(result_obj, dict) # The return is a dictionary
    assert result_obj != {} # Is not blank
    assert len(result_obj.keys()) == 2 # It has 2 keys
    assert "findings" in result_obj.keys()
    assert len(result_obj['findings']) == 1
    assert "errors" in result_obj.keys()
    assert len(result_obj['errors']) == 1

def test_format_dependencies():
    # Arrange
    MOCK_DEPENDENCY = ExtractedDependency(
        name = "MOCK DEPENDENCY",
        version = "MOCK VERSION",
        type = "MOCK TYPE",
        result = DependencyRelation.CONSUMED,
        extraction_source = "MOCK SOURCE",
        download_location = "MOCK LOCATION"
    )
    MOCK_ERRORS = "MockError"

    # Act
    result = JsonFormatter.format_dependencies([MOCK_DEPENDENCY], [MOCK_ERRORS])

    # Assert
    assert json.loads(result) # Is valid JSON data
    result_obj = json.loads(result)
    assert isinstance(result_obj, dict) # The return is a dictionary
    assert result_obj != {} # Is not blank
    assert len(result_obj.keys()) == 2 # It has 2 keys
    assert "dependencies" in result_obj.keys()
    assert len(result_obj['dependencies']) == 1
    assert "errors" in result_obj.keys()
    assert len(result_obj['errors']) == 1