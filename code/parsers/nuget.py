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


class NuGetParser(ParserBase):
    yara_rule = """
    rule nuget
    {
    meta:
        description = "detects nuget being run to download a file or files"
        parser = "NuGetParser"
    strings:
        $nuget_command =/\\bnuget(\\b|\\b.*\\b)install\\b/
    condition:
        any of them
    }
    """
    parser_name = "NuGetParser"
    parser_description = (
        "This parser is designed to extract dependencies downloaded with NuGet command."
    )

    def on_load(self) -> None:
        self.nuget_extractor_regex = re.compile(r'((?:\S+[ \t])?nuget(.exe)? install (\S+[ \t]?)(-.*?\s+.+)?)')
        self.pkg_source_extractor_regex = re.compile(r'(-Source ([^\s]+))')
        self.version_extractor_regex = re.compile(r'(\d+(\.\d+)+)')

    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        dependencies = []
        nuget_dependencies = self.nuget_extractor_regex.findall(document)
        for match in nuget_dependencies:
            pkg_source_extract = self.pkg_source_extractor_regex.findall(match[0])
            pkg_src_list = [pkg_src[1] for pkg_src in pkg_source_extract]
            version = re.search(self.version_extractor_regex, match[0])

            dependencies.append(
                ExtractedDependency(
                    name=match[2].rstrip(),
                    version=version.group() if version else "Unknown",
                    type=f"nuget",
                    extraction_source=match[0],
                    download_location=', '.join(pkg_src_list) if pkg_src_list else match[2].rstrip(),
                    result=DependencyRelation.CONSUMED,
                )
            )
        return dependencies

    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        findings = []
        return findings