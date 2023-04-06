# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from typing import List
from formatters.base import BaseFormatter, AVAILABLE_FORMATTERS
from models import DocumentReport, ExtractedDependency, ExtractedFinding
from json import dumps

class JsonFormatter(BaseFormatter):
    MIME_TYPE = 'application/json'
    
    @classmethod
    def format_findings(cls, findings: List[ExtractedFinding], errors: List[str]):
        return dumps({"findings":[finding.dict() for finding in findings],"errors":errors})

    @classmethod
    def format_dependencies(cls, dependencies: List[ExtractedDependency], errors: List[str]):
        return dumps({"dependencies":[dependency.dict() for dependency in dependencies],"errors":errors})

    @classmethod
    def format_report(cls, report: DocumentReport):
        return dumps(report.dict())

AVAILABLE_FORMATTERS['json'] = JsonFormatter