# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from typing import List
from parsers.base import ParserBase
from models import DependencyRelation, ExtractedDependency, ExtractedFinding
import re


class AptParser(ParserBase):

    yara_rule = """
        rule apt
        {
        meta:
            description = "detects the aptitude package manager being run and provides package and version extraction"
            parser = "AptParser"
        strings:
            $install_or_upgrade = /\\b(apt|apt-get)(\\b|\\b.*\\b)(install|upgrade)\\b/
        condition:
            any of them
        }
        """
    parser_name = "AptParser"
    parser_description = "This parser is designed to extract dependencies brought in through the Aptitude (apt) package installer."

    def on_load(self) -> None:
        self.dependency_extractor_regex = re.compile(r'(Get:\d+ (https?://\S+) (\S+) (\S+) (\S+) (\S+) (\S+) \[([\d\.]+ (k|m|g)?B)\])')

    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        dependencies = []
        downloaded_packages = self.dependency_extractor_regex.findall(document)
        for match in downloaded_packages:
                dependencies.append(
                    ExtractedDependency(
                        name=match[4],
                        version=f"{match[3]}-{match[6]}",
                        type="linux",
                        extraction_source=match[0],
                        download_location=match[1],
                        result=DependencyRelation.CONSUMED,
                    )
                )
        return dependencies

    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        findings = []

        return findings
