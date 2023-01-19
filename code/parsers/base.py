# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from abc import ABC, abstractmethod, abstractproperty
from logging import getLogger
import logging
from typing import List
from models import ExtractedDependency, ExtractedFinding


class ParserBase(ABC):

    yara_rule = "Yara Rule goes here"
    parser_name = "ParserBase"
    parser_description = "Parser Description Goes Here"

    def __init__(self) -> None:
        self._logger = logging.getLogger(self.parser_name)
        self.on_load()
        self._logger.debug(f"Loaded parser {self.parser_name}")
        super().__init__()

    def on_load(self) -> None:
        pass

    @abstractmethod
    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        return []

    @abstractmethod
    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        return []

    def process_document(self, document: str) -> dict:
        return {
            "dependencies": self.get_document_dependencies(document),
            "findings": self.get_document_findings(document),
        }