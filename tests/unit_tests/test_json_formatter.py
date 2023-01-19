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

    # Act
    result = JsonFormatter.format_findings([MOCK_FINDING])

    # Assert
    assert json.loads(result) # Is valid JSON data
    result_obj = json.loads(result)
    assert isinstance(result_obj, list) # The return is a list
    assert result_obj != [] # Is not blank
    assert len(result_obj) == 1 # It has 1 finding

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

    # Act
    result = JsonFormatter.format_dependencies([MOCK_DEPENDENCY])

    # Assert
    assert json.loads(result) # Is valid JSON data
    result_obj = json.loads(result)
    assert isinstance(result_obj, list) # The return is a list
    assert result_obj != [] # Is not blank
    assert len(result_obj) == 1 # It has 1 dependency