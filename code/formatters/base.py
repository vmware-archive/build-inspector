# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from abc import ABC, abstractclassmethod
from typing import List
from models import DocumentReport, ExtractedDependency, ExtractedFinding

AVAILABLE_FORMATTERS = {}

class BaseFormatter(ABC):
    MIME_TYPE = None

    @abstractclassmethod
    def format_findings(cls, findings: List[ExtractedFinding]):
        pass

    @abstractclassmethod
    def format_dependencies(cls, dependencies: List[ExtractedDependency]):
        pass

    @abstractclassmethod
    def format_report(cls, report: DocumentReport):
        pass