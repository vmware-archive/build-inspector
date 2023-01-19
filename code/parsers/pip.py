# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from typing import List
from parsers.base import ParserBase
from models import (
    DependencyRelation,
    ExtractedDependency,
    ExtractedFinding,
    FindingSeverity,
)
import re


class PipParser(ParserBase):

    yara_rule = """
        rule pip
        {
        meta:
            description = "detects pip being run and provides package and version extraction"
            parser = "PipParser"
        strings:
            $install = /\\bpip\d?(\\b|\\b.*\\b)install\\b/
        condition:
            any of them
        }
        """
    parser_name = "PipParser"
    parser_description = "This parser is designed to extract dependencies brought in through the Python PIP package installer."

    def on_load(self) -> None:
        self.dependency_extractor_regex = re.compile(
            r"(Downloading ((?:http\S+/)?(?P<name>.*?)-(?P<version>[0-9].+?)(?:\.whl|\.tar\.gz)))\s"
        )
        self.pip_install_finder = re.compile(
            "(\\bpip[\d\.]* .*\\binstall\\b.*(\n|\r\n))"
        )
        self.quiet_flags = re.compile(" (-q|--quiet) ")

    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        dependencies = []
        dependency_matches = self.dependency_extractor_regex.findall(document)
        for match in dependency_matches:
            dependencies.append(
                ExtractedDependency(
                    name=match[2],
                    version=match[3],
                    type="python",
                    extraction_source=match[0],
                    download_location=match[1] if match[1].startswith("https://") else "Unknown",
                    result=DependencyRelation.CONSUMED,
                )
            )
        return dependencies

    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        findings = []
        # Look for quiet installs
        quiet_matches = self.pip_install_finder.findall(document)
        for match in quiet_matches:
            if self.quiet_flags.search(match[0]):
                findings.append(
                    ExtractedFinding(
                        source="PipParser",
                        description="The Pip parser is unable to parse dependency information for quiet installs. Please remove the quiet flag from this install.",
                        offset=0,
                        finding_data=match[0],
                        severity=FindingSeverity.INFORMATIONAL,
                        category="dependency-collection",
                    )
                )
        return findings