# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from enum import Enum
from typing import List
from pydantic import BaseModel
from yara import Match


class DependencyRelation(str, Enum):
    CONSUMED: str = "consumed"
    CREATED: str = "created"


class FindingSeverity(str, Enum):
    INFORMATIONAL: str = "informational"
    MINOR: str = "minor"
    MAJOR: str = "major"
    CRITICAL: str = "critical"


class ExtractedDependency(BaseModel):
    name: str
    version: str
    type: str
    result: DependencyRelation
    extraction_source: str
    download_location: str


class ExtractedFinding(BaseModel):
    source: str
    description: str
    offset: int
    finding_data: str
    severity: FindingSeverity
    category: str


class DocumentReport(BaseModel):
    findings: List[ExtractedFinding]
    dependencies: List[ExtractedDependency]