# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from typing import List
from parsers.base import ParserBase
from models import DependencyRelation, ExtractedDependency, ExtractedFinding
import re


class YumParser(ParserBase):

    yara_rule = """
        rule yum
        {
        meta:
            description = "detects yum being run and provides package and version extraction"
            parser = "YumParser"
        strings:
            $install_or_update = /\\byum(\\b|\\b.*\\b)(update|install)\\b/
        condition:
            any of them
        }
        """
    parser_name = "YumParser"
    parser_description = "This parser is designed to extract dependencies brought in through the Yellow Dog Updater (yum) package installer."

    def on_load(self) -> None:
        self.yumblock_extractor_regex = re.compile(
            "^\W*=+$(\n|\r\n|\W)*Package(\n|\r\n|\W)+Arch(itecture)?(\n|\r\n|\W)+Version(\n|\r\n|\W)+Repository(\n|\r\n|\W)+Size(\n|\r\n|\W)^\W*=+$([\s\S]*?)Transaction Summary(\n|\r\n)^\W*=+$",
            re.MULTILINE,
        )
        self.dependency_extractor_regex = re.compile(
            "( (?P<name>\S+)\s+(?P<arch>\S+)\s+(?P<version>\d\S+)\s+(?P<repo>\S+)\s+[\d\.]+ [kMGb])"
        )
        self.fastest_mirror_block_detection = re.compile(
            "((Determining fastest mirrors|Loading mirror speeds from cached hostfile)(\n|\r\n)(\s\*\s.*(\n|\r\n))+)",
            re.MULTILINE,
        )
        self.mirror_mapping_extraction = re.compile("\s\*\s(\w+):\s(\S+)")

    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        mirror_map = self.get_mirror_mapping(document)
        dependencies = []
        yumblock_matches = self.yumblock_extractor_regex.findall(document)
        for yumblock in yumblock_matches:
            dependency_matches = self.dependency_extractor_regex.findall(yumblock[3])
            for match in dependency_matches:
                dl_mirror = mirror_map.get(match[4], "Unknown")
                dependencies.append(
                    ExtractedDependency(
                        name=match[1],
                        version=f"{match[3]}-{match[2]}",
                        type="linux",
                        extraction_source=match[0],
                        download_location=dl_mirror,
                        result=DependencyRelation.CONSUMED,
                    )
                )
        return dependencies

    def get_mirror_mapping(self, document) -> dict:
        mirror_map = {}
        mirror_blocks = self.fastest_mirror_block_detection.findall(document)
        for block in mirror_blocks:
            mirrors = self.mirror_mapping_extraction.findall(block[0])
            for mirror in mirrors:
                if mirror_map.get(mirror[0], None):
                    if not mirror[1] in mirror_map[mirror[0]]:
                        mirror_map[mirror[0]] += f" {mirror[1]}"
                else:
                    mirror_map[mirror[0]] = mirror[1]
        return mirror_map

    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        findings = []

        return findings