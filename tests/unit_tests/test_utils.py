# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "code"))
import utils

def test_timeout_success():
    # Arrange
    @utils.timeout(10)
    def mot():
        time.sleep(1)
        return "Success"

    # Act
    result = mot()

    # Assert
    assert result == "Success"

def test_timeout_timeout():
    # Arrange
    @utils.timeout(1)
    def mot():
        time.sleep(2)
        return "Success"

    # Act
    with pytest.raises(utils.TimeoutExpiredError) as ex:
        mot()

    # Assert
    assert isinstance(ex.value.args, tuple)
    assert isinstance(ex.value.args[0],str)
    assert "timed out" in ex.value.args[0] 
    assert ex.value.args[1] == "mot"
    assert ex.value.args[2] == 1


def test_timeout_passes_exception():
    # Arrange
    @utils.timeout(1)
    def mot():
        raise RuntimeError

    # Act
    with pytest.raises(RuntimeError):
        mot()

    # Assert
