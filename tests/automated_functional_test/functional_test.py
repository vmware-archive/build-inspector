# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2

import sys
import os
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "code"))

from argparse import ArgumentParser
import os
import sys
import logging
import urllib.parse
from fastapi.testclient import TestClient
from microservice import microservice_api
from typing import List
from pydantic import parse
from pydantic_yaml import YamlModel, main

class FindingConfig(YamlModel):
    source: str
    finding_data: str
    false_positive: bool = False

    def __str__(self) -> str:
        if self.false_positive:
            return f'Negative Finding - Source: {self.source}, Data: {self.finding_data}'
        else:
            return f'Finding - Source: {self.source}, Data: {self.finding_data}'

class DependencyConfig(YamlModel):
    type: str
    name: str
    version: str
    download_location: str
    false_positive: bool = False

    def __str__(self) -> str:
        if self.false_positive:
            return f'Negative Dependency - Name: {self.name}, Version: {self.version}'
        else:
            return f'Dependency - Name: {self.name}, Version: {self.version}'

class TestConfig(YamlModel):
    input_data: str
    expected_findings: List[FindingConfig] = []
    expected_dependencies: List[DependencyConfig] = []

class FunctionalTest(YamlModel):
    name: str
    description: str
    config: TestConfig

def parse_arguments():
    parser = ArgumentParser(description="A utility for automated testing of the BoM Generator API")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--configs","-c",help="Location of the test configurations directory", default=os.path.dirname(os.path.realpath(__file__)) + "/test_configs/")
    parser.add_argument("--url","-u",help="Base URL for API testing",default="http://localhost:8080/")
    config = parser.parse_args()
    return config


class FunctionalTestRunner():
    API_REPORT_PATH = "/v1/report?type=buildlog&format=json"

    def __init__(self, config) -> None:
        self.config = config
        if config.debug:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)
        self.test_cases = []
        self.failures = []
        self.failed_test_count = 0
        self.passed_test_count = 0
        self.logger = logging.getLogger("FunctionalTestRunner")
        self.api_client = TestClient(microservice_api)
        self.load_test_cases()
    
    def load_test_cases(self):
        for root, dir, files in os.walk(self.config.configs):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path,"r") as testfile:
                    try:
                        content = testfile.read()
                        self.logger.debug(f'Loading test config from file "{file_path}"')
                        test_config = FunctionalTest.parse_raw(content)
                        self.test_cases.append((file_path,test_config))
                        self.logger.debug(f'Loaded test case "{test_config.name}"')
                    except:
                        self.logger.exception(f'Exception loading test config from file "{file_path}"')
        self.logger.info(f'Loaded {len(self.test_cases)} total tests.')

    def run_all_tests(self):
        success = True
        for filepath, test_config in self.test_cases:
            self.logger.debug(f'Running test "{test_config.name}"" from file "{filepath}"')
            single_success = self.run_one_test(test_config)
            if not single_success:
                success = False
        return success
    
    def run_one_test(self, test_config):
        self.logger.debug(f'Starting test {test_config.name}')
        API_result = self.send_test_to_API(test_config)
        success = self.check_test_result(test_config, API_result)
        return success

    def send_test_to_API(self, test_config):
        body = test_config.config.input_data
        url = self.API_REPORT_PATH
        try:
            response = self.api_client.post(url=url,data=body.encode('utf-8'))
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f'Non-200 response code recieved when running test {test_config.name}. Response: {response.status_code}')
                return None
        except:
            self.logger.exception(f'Exception when sending test data to API for test {test_config.name}')
            return None
        
    def check_finding(self, finding, API_result):
        for found in API_result['findings']:
            try:
                assert found['source'] == finding.source
                assert found['finding_data'] == finding.finding_data
                self.logger.debug(f'{finding} matched {found}')
                return True # Match found, return true
            except AssertionError:
                self.logger.debug(f'{finding} did not match {found}')
        return False # Match not found, return false
        
    def check_dependency(self, dependency, API_result):
        for dep in API_result['dependencies']:
            try:
                assert dep['name'] == dependency.name
                assert dep['type'] == dependency.type
                assert dep['version'] == dependency.version
                assert dep['download_location'] == dependency.download_location
                self.logger.debug(f'{dependency} matched {dep}')
                return True # Match found, return true
            except AssertionError:
                self.logger.debug(f'{dependency} did not match {dep}')
        return False # Match not found, return false

    def check_test_result(self,test_config,API_result):
        success = True
        if API_result:
            self.logger.debug(f'Checking result for test {test_config.name}.')
            for finding in test_config.config.expected_findings:
                found = self.check_finding(finding, API_result)
                if finding.false_positive == found: 
                    self.logger.debug(f'Incorrect result for test {test_config.name}. Test Failed!')
                    self.failed_test_count += 1
                    self.failures.append((test_config,f'Expected finding does not match results. {finding}'))
                    success = False
                else:
                    self.logger.debug(f'Correct result found for test {test_config.name}. Test Passed!')
                    self.passed_test_count += 1
            for dependency in test_config.config.expected_dependencies:
                found = self.check_dependency(dependency, API_result)
                if not found:
                    self.logger.info(f'Incorrect result for test {test_config.name}. Test Failed!\nExpected: {dependency} \nGot {API_result["dependencies"]}')
                    self.failed_test_count += 1
                    self.failures.append((test_config,f'Expected dependency does not match results. {dependency}'))
                    success = False
                else:
                    self.logger.debug(f'Correct result found for test {test_config.name}. Test Passed!')
                    self.passed_test_count += 1
        else:
            self.failures.append((test_config, 'No Result returned from API'))
            self.logger.error(f'No API result returned for test {test_config.name}. Test failed!')
            self.failed_test_count += 1
            success = False # No results returned. Test failed
        return success

if __name__ == "__main__":
    config = parse_arguments()
    runner = FunctionalTestRunner(config)
    success = runner.run_all_tests()
    logging.info(f'Passed: {runner.passed_test_count} Failed: {runner.failed_test_count}')
    if not success:
        logging.error('!!!!FAIL FAIL FAIL FAIL FAIL FAIL FAIL FAIL!!!!')
        for test_case, failure in runner.failures:
            logging.error(f'{test_case.name} - {failure}')
        sys.exit(1)
    else:
        logging.info('!!!!PASS PASS PASS PASS PASS PASS PASS PASS!!!!')
        sys.exit(0)