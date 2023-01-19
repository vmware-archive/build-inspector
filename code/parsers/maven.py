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


class MavenParser(ParserBase):
    yara_rule = """
    rule maven
    {
    meta:
        description = "detects mvn being run to download a file or files"
        parser = "MavenParser"
    strings:
        $maven_command = /\\mvn (.*)?(\S+)/
    condition:
        any of them
    }
    """
    parser_name = "MavenParser"
    parser_description = (
        "This parser is designed to extract dependencies downloaded with Maven command."
    )

    def on_load(self) -> None:
        self.maven_extractor_regex = re.compile(r'((?:\S+[ \t])?mvn (dependency:(get|copy)) (-D[A-Za-z0-9=:]+.+))')
        self.artifact_regex = re.compile(r'(-Dartifact(Id)?=([^\s]+))')
        self.repo_url_regex = re.compile(r'((-DrepoUrl|-DremoteRepositories)=([^\s]+))')
        self.version_regex = re.compile(r'([^:]+$)')

    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        dependencies = []
        maven_dependencies = self.maven_extractor_regex.findall(document)
        for match in maven_dependencies:
            artifact_extract = self.artifact_regex.findall(match[3]) if match[3] else []
            artifact = artifact_extract[0][2] if artifact_extract else match[0]

            version = self.version_regex.findall(artifact)[0] if artifact else "Unknown"

            repo_extract = self.repo_url_regex.findall(match[3]) if match[3] else []
            repo_url = repo_extract[0][2] if repo_extract else "Unknown"

            dependencies.append(
                ExtractedDependency(
                    name=artifact,
                    version=version,
                    type=f"maven {match[2]}",
                    extraction_source=match[0],
                    download_location=repo_url,
                    result=DependencyRelation.CONSUMED,
                )
            )
        return dependencies

    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        findings = []
        return findings