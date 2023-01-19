# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from typing import List
from formatters.base import BaseFormatter, AVAILABLE_FORMATTERS
from models import DocumentReport, ExtractedDependency, ExtractedFinding
from json import dumps

class JsonFormatter(BaseFormatter):
    MIME_TYPE = 'application/json'
    
    @classmethod
    def format_findings(cls, findings: List[ExtractedFinding]):
        return dumps([finding.dict() for finding in findings])

    @classmethod
    def format_dependencies(cls, dependencies: List[ExtractedDependency]):
        return dumps([dependency.dict() for dependency in dependencies])

    @classmethod
    def format_report(cls, report: DocumentReport):
        return dumps(report.dict())

AVAILABLE_FORMATTERS['json'] = JsonFormatter