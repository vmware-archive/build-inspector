# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import re
from typing import List
from parsers.base import ParserBase
from models import (
    DependencyRelation,
    ExtractedDependency,
    ExtractedFinding
)


class GoGetParser(ParserBase):
    yara_rule = """
    rule goget
    {
    meta:
        description = "detects go get being run to download a file or files"
        parser = "GoGetParser"
    strings:
        $goget_command = /\\go get (-.*)?(\S+)/
    condition:
        any of them
    }
    """
    parser_name = "GoGetParser"
    parser_description = (
        "This parser is designed to extract dependencies downloaded with GoGet command."
    )

    def on_load(self) -> None:
        self.goget_extractor_regex = re.compile(r'((?:\S+[ \t])?go get (-.*?\s)?(\S+))')
        self.version_extractor_regex = re.compile(r'(\d+(\.\d+)+)')

    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        dependencies = []
        goget_dependencies = self.goget_extractor_regex.findall(document)
        for match in goget_dependencies:
            version = re.search(self.version_extractor_regex, match[2])
            dependencies.append(
                ExtractedDependency(
                    name=match[2],
                    version=version.group() if version else "Unknown",
                    type="go-get",
                    extraction_source=match[0],
                    download_location=match[2],
                    result=DependencyRelation.CONSUMED,
                )
            )
        return dependencies

    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        findings = []
        return findings