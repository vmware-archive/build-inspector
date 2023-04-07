# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import os
import sys
import mock
from yara import Rules
from fastapi.testclient import TestClient
import pytest
import http.client


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "code"))
import microservice


@pytest.fixture
def test_client():
    test_client = TestClient(microservice.microservice_api)
    return test_client


@mock.patch("microservice.os.listdir")
@mock.patch("microservice.yara.compile")
def test_load_finding_yara_rules(
    mock_compile: mock.MagicMock, mock_listdir: mock.MagicMock
):
    # Arrange
    mock_listdir.return_value = ["file-1.yar", "file-2.yar", "not-a-rule.txt"]
    EXPECTED_FILEPATHS = {
        "file-1": f"{microservice.YARA_RULES_PATH}/file-1.yar",
        "file-2": f"{microservice.YARA_RULES_PATH}/file-2.yar",
    }
    EXPECTED_RETURN = object()
    mock_compile.return_value = EXPECTED_RETURN

    # Act
    result = microservice.load_finding_yara_rules()

    # Assert
    assert result == EXPECTED_RETURN


@mock.patch("microservice.yara.compile")
def test_load_parser_rules(mock_compile: mock.MagicMock):
    # Arrange
    MOCK_PARSER = mock.MagicMock()
    MOCK_PARSER.yara_rule = "A Fake Yara Rule"
    microservice.ALL_PARSERS = {"MockParser": MOCK_PARSER}
    EXPECTED_RETURN = mock_compile()

    # Act
    result = microservice.load_parser_rules()

    # Assert
    assert result == EXPECTED_RETURN


# Test endpoints


@mock.patch.dict(os.environ, {"SERVICE_VERSION": "mock.mock.mock"})
def test_get_version(test_client: TestClient):
    # Arrange

    # Act
    response = test_client.get("/v1/version")

    # Assert
    assert response.status_code == 200
    assert response.json() == {"version": "mock.mock.mock"}


def test_health_check(test_client: TestClient):
    # Arrange

    # Act
    response = test_client.get("/v1/healthy")

    # Assert
    assert response.status_code == 200


def test_list_parsers(test_client: TestClient):
    # Arrange

    # Act
    response = test_client.get("/v1/parsers")

    # Assert
    assert response.status_code == 200
    assert isinstance(response.json(), dict)
    assert "available_parsers" in response.json().keys()
    assert isinstance(response.json()["available_parsers"], list)


@mock.patch("microservice.load_finding_yara_rules")
@mock.patch("microservice.load_parser_rules")
def test_list_rules(
    mock_load_parser: mock.MagicMock,
    mock_load_finding: mock.MagicMock,
    test_client: TestClient,
):
    # Arrange
    FINDING_RULE_1 = mock.MagicMock("rule1")
    FINDING_RULE_1.identifier = "Mock_rule_1"
    FINDING_RULE_1.meta = {"description": "A mock finding rule for testing"}
    mock_load_finding.return_value = [FINDING_RULE_1]

    PARSER_RULE_1 = mock.MagicMock("rule1")
    PARSER_RULE_1.identifier = "Mock_rule_1"
    PARSER_RULE_1.meta = {"description": "A mock parser rule for testing"}
    mock_load_parser.return_value = [PARSER_RULE_1]

    # Act
    response = test_client.get("/v1/rules")

    # Assert
    assert response.status_code == 200
    assert isinstance(response.json(), dict)
    assert "available_rules" in response.json().keys()
    assert isinstance(response.json()["available_rules"], list)


@mock.patch("microservice.generate_buildlog_findings")
def test_generate_findings_buildlog(
    mock_generate_findings: mock.MagicMock, test_client: TestClient
):
    # Arrange
    POST_DATA = "This is a buildlog"
    TYPE = "buildlog"
    FINDINGS_RETURN = ([],[])
    mock_generate_findings.return_value = FINDINGS_RETURN
    EXPECTED_RETURN = {'errors': [], 'findings': []}

    # Act
    response = test_client.post(url=f"/v1/findings?type={TYPE}", content=POST_DATA)

    # Assert
    assert response.status_code == 200
    assert response.json() == EXPECTED_RETURN
    mock_generate_findings.assert_called_once_with(POST_DATA)


def test_generate_findings_nonimplemented(test_client: TestClient):
    # Arrange
    POST_DATA = "This is a buildlog"
    TYPE = "anotimplementedtypeofgenerator"

    # Act
    response = test_client.post(url=f"/v1/findings?type={TYPE}", content=POST_DATA)

    # Assert
    assert response.status_code == http.client.BAD_REQUEST


@mock.patch("microservice.generate_buildlog_dependencies")
def test_generate_deps_buildlog(
    mock_generate_deps: mock.MagicMock, test_client: TestClient
):
    # Arrange
    POST_DATA = "This is a buildlog"
    TYPE = "buildlog"
    EXPECTED_RETURN = {'dependencies': [], 'errors': []}
    DEPS_RETURN = ([],[])
    mock_generate_deps.return_value = DEPS_RETURN

    # Act
    response = test_client.post(url=f"/v1/dependencies?type={TYPE}", content=POST_DATA)

    # Assert
    assert response.status_code == 200
    assert response.json() == EXPECTED_RETURN
    mock_generate_deps.assert_called_once_with(POST_DATA)


def test_generate_deps_nonimplemented(test_client: TestClient):
    # Arrange
    POST_DATA = "This is a buildlog"
    TYPE = "anotimplementedtypeofgenerator"

    # Act
    response = test_client.post(url=f"/v1/dependencies?type={TYPE}", content=POST_DATA)

    # Assert
    assert response.status_code == http.client.BAD_REQUEST


@mock.patch("microservice.generate_buildlog_dependencies")
@mock.patch("microservice.generate_buildlog_findings")
def test_generate_report_buildlog(
    mock_generate_findings: mock.MagicMock,
    mock_generate_deps: mock.MagicMock,
    test_client: TestClient,
):
    # Arrange
    POST_DATA = "This is a buildlog"
    TYPE = "buildlog"
    EXPECTED_GENERATE_RETURNS = ([],[])
    mock_generate_deps.return_value = EXPECTED_GENERATE_RETURNS
    mock_generate_findings.return_value = EXPECTED_GENERATE_RETURNS
    EXPECTED_RETURN_JSON = {
        "dependencies": [],
        "findings": [],
        "errors": []
    }

    # Act
    response = test_client.post(url=f"/v1/report?type={TYPE}", content=POST_DATA)

    # Assert
    assert response.status_code == 200
    assert response.json() == EXPECTED_RETURN_JSON
    mock_generate_deps.assert_called_once_with(POST_DATA)
    mock_generate_findings.assert_called_once_with(POST_DATA)


def test_generate_report_nonimplemented(test_client: TestClient):
    # Arrange
    POST_DATA = "This is a buildlog"
    TYPE = "anotimplementedtypeofgenerator"

    # Act
    response = test_client.post(url=f"/v1/report?type={TYPE}", content=POST_DATA)

    # Assert
    assert response.status_code == http.client.BAD_REQUEST


@mock.patch("microservice.load_finding_yara_rules")
@mock.patch("microservice.load_parser_rules")
def test_generate_buildlog_findings(
    mock_load_parser: mock.MagicMock, mock_load_finding: mock.MagicMock
):
    # Arrange
    MOCK_DOCUMENT = "This is a mock buildlog"

    FINDING_RULES = mock_load_finding()
    FINDING_INSTANCE1 = (1, None, b"MockFinding")
    FINDING_MATCH1 = mock.MagicMock()
    FINDING_MATCH1.meta = {"description": "mock finding!"}
    FINDING_MATCH1.rule = "MockRule"
    FINDING_MATCH1.strings = [FINDING_INSTANCE1]
    FINDING_MATCHES = [FINDING_MATCH1]
    FINDING_RULES.match.return_value = FINDING_MATCHES

    MOCK_PARSER = mock.MagicMock()
    MOCK_PARSER().get_document_findings.return_value = ["Mock finding"]
    microservice.ALL_PARSERS = {"MockParser": MOCK_PARSER}
    PARSER_RULES = mock_load_parser()
    PARSER_MATCH1 = mock.MagicMock()
    PARSER_MATCH1.namespace = "MockParser"
    PARSER_MATCHES = [PARSER_MATCH1]
    PARSER_RULES.match.return_value = PARSER_MATCHES

    # Act
    result = microservice.generate_buildlog_findings(MOCK_DOCUMENT)

    # Assert
    assert isinstance(result, tuple)
    assert len(result[0]) == 2
    assert len(result[1]) == 0
    PARSER_RULES.match.assert_called_once_with(data=MOCK_DOCUMENT)
    FINDING_RULES.match.assert_called_once_with(data=MOCK_DOCUMENT)


@mock.patch("microservice.load_parser_rules")
def test_generate_buildlog_dependencies(mock_load_parser: mock.MagicMock):
    # Arrange
    MOCK_DOCUMENT = "This is a mock buildlog"

    MOCK_PARSER = mock.MagicMock()
    MOCK_PARSER().get_document_dependencies.return_value = ["Mock dependency"]
    microservice.ALL_PARSERS = {"MockParser": MOCK_PARSER}
    PARSER_RULES = mock_load_parser()
    PARSER_MATCH1 = mock.MagicMock()
    PARSER_MATCH1.namespace = "MockParser"
    PARSER_MATCHES = [PARSER_MATCH1]
    PARSER_RULES.match.return_value = PARSER_MATCHES

    # Act
    result = microservice.generate_buildlog_dependencies(MOCK_DOCUMENT)

    # Assert
    assert isinstance(result, tuple)
    assert len(result[0]) == 1
    assert len(result[1]) == 0
    PARSER_RULES.match.assert_called_once_with(data=MOCK_DOCUMENT)