# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import os
import sys
import time
from mock import patch, mock_open
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "code"))
import settings

def test_settings_defaults():
    # Arrange
    EXPECTED_ATTRS = ['parser_timeout', 'disabled_parsers']
    DEFAULT_TIMEOUT = 1
    DEFAULT_DISABLED = []

    # Act
    result = settings.Settings()

    # Assert
    for attr in EXPECTED_ATTRS:
        getattr(result, attr)
    assert result.parser_timeout == DEFAULT_TIMEOUT
    assert result.disabled_parsers == DEFAULT_DISABLED

MOCK_SETTINGS_FILE = """
parser_timeout: 10
disabled_parsers:
- CurlParser
"""

@patch('settings.isfile')
@patch("builtins.open", new_callable=mock_open, read_data=MOCK_SETTINGS_FILE)
def test_settings_load_file(mock_file, mock_isfile):
    # Arrange
    MOCK_PATH = "/config/conf.yml"
    EXPECTED_TIMEOUT = 10
    EXPECTED_DISABLED = ["CurlParser"]
    mock_isfile.return_value = True

    # Act
    result = settings.Settings.load_from_file(MOCK_PATH)

    # Assert
    mock_isfile.assert_called_once_with(MOCK_PATH)
    mock_file.assert_called_with(MOCK_PATH, 'r')
    assert result.parser_timeout == EXPECTED_TIMEOUT
    assert result.disabled_parsers == EXPECTED_DISABLED

@patch('settings.isfile')
def test_settings_load_file_nonexistent(mock_isfile):
    # Arrange
    MOCK_PATH = "/config/conf.yml"
    EXPECTED_TIMEOUT = 1
    EXPECTED_DISABLED = []
    mock_isfile.return_value = False

    # Act
    result = settings.Settings.load_from_file(MOCK_PATH)

    # Assert
    mock_isfile.assert_called_once_with(MOCK_PATH)
    assert result.parser_timeout == EXPECTED_TIMEOUT
    assert result.disabled_parsers == EXPECTED_DISABLED