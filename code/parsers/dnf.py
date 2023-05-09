# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from typing import List
from parsers.base import ParserBase
from models import DependencyRelation, ExtractedDependency, ExtractedFinding
import re


class DNFParser(ParserBase):

    yara_rule = """
        rule dnf
        {
        meta:
            description = "detects dnf being run and provides package and version extraction"
            parser = "DNFParser"
        strings:
            $install_or_update = /\\bdnf(\\b|\\b.*\\b)(update|install)\\b/
        condition:
            any of them
        }
        """
    parser_name = "DNFParser"
    parser_description = "This parser is designed to extract dependencies brought in through the DNF package installer."

    def on_load(self) -> None:
        self.dependency_extractor_regex = re.compile(
            r"\s+(\S+-\S+-\S+(-\d+)?\.\S+)+"
        )

    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        dependencies = []
        dependency_matches = self.dependency_extractor_regex.findall(document)
        packages = []
        for match in dependency_matches:
            package_pattern = r"([a-zA-Z-]+)-([\d\.\-a-zA-Z]+)\.(\S+)\s*"
            package_matches = re.findall(package_pattern, match[0])
            packages.extend(package_matches)

        for package in packages:
                dependencies.append(
                    ExtractedDependency(
                        name=f"{package[0]}",
                        version=f"{package[1]}",
                        type="Fedora",
                        extraction_source=f"{''.join(package)+'.rpm'}",
                        download_location="Fedora",
                        result=DependencyRelation.CONSUMED,
                    )
                )
        return dependencies

    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        findings = []

        return findings