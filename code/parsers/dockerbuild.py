# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from typing import List
from parsers.base import ParserBase
from models import DependencyRelation, ExtractedDependency, ExtractedFinding
import re


class DockerBuildParser(ParserBase):

    yara_rule = """
        rule docker_build
        {
        meta:
            description = "detects docker build being run"
            parser = "DockerBuildParser"
        strings:
            $build_command = /\\bdocker build /
        condition:
            any of them
        }
        """
    parser_name = "DockerBuildParser"
    parser_description = "This parser is designed to extract dependencies brought in through the Docker build process."

    def on_load(self) -> None:
        self.docker_from_extractor_regex = re.compile("(\\bFROM ((\S+)/(\S+?):(\S+)))")
        self.docker_tagged_extractor_regex = re.compile(
            "(Successfully tagged ((\S+)/(\S+?):(\S+)))"
        )

    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        dependencies = []
        source_matches = self.docker_from_extractor_regex.findall(document)
        for match in source_matches:
            dependencies.append(
                ExtractedDependency(
                    name=match[3],
                    version=match[4],
                    type="docker",
                    extraction_source=match[0],
                    download_location=match[2],
                    result=DependencyRelation.CONSUMED,
                )
            )
        target_matches = self.docker_tagged_extractor_regex.findall(document)
        for match in target_matches:
            dependencies.append(
                ExtractedDependency(
                    name=match[3],
                    version=match[4],
                    type="docker",
                    extraction_source=match[0],
                    download_location=match[2],
                    result=DependencyRelation.CREATED,
                )
            )
        return dependencies

    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        findings = []

        return findings