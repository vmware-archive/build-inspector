# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from typing import List
from parsers.base import ParserBase
from models import DependencyRelation, ExtractedDependency, ExtractedFinding
import re


class NpmParser(ParserBase):

    yara_rule = """
        rule npm
        {
        meta:
            description = "detects the node package manager (npm) being run and provides package and version extraction"
            parser = "NpmParser"
        strings:
            $install = /\\b(npm)\\b .*\\b(install)\\b/
        condition:
            any of them
        }
        """
    parser_name = "NpmParser"
    parser_description = "This parser is designed to extract dependencies brought in through the Node Package Manager (npm)."

    def on_load(self) -> None:
        self.dependency_extractor_regex = re.compile(r'(npm.{,20} .{,20}http.{,20} .{,20}fetch.{,20} .{,20}GET.{,20} .{,20}200.{,20} .{,20}(https?://(?:\S+/)?([^/]+)/([^/]+)/-/([^/]+)-([\w\.]+)\.tgz) [\d\.]+m?s)')

    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        dependencies = []
        found = set()
        downloaded_packages = self.dependency_extractor_regex.findall(document)
        for match in downloaded_packages:
            name = match[4]
            if match[2].startswith("@"):
                name = f"{match[2]}/{match[3]}".replace("@", "")
            version = match[5]
            name_version = f"{name}-{version}"
            if name_version in found:
                continue
            dependencies.append(
                ExtractedDependency(
                    name=name,
                    version=version,
                    type="npm",
                    extraction_source=match[0],
                    download_location=match[1],
                    result=DependencyRelation.CONSUMED,
                )
            )
            found.add(name_version)
        return dependencies

    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        findings = []

        return findings
