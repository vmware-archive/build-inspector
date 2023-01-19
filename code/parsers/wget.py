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


class WgetParser(ParserBase):

    yara_rule = """
        rule wget
        {
        meta:
            description = "detects wget being run to download a file or files"
            parser = "WgetParser"
        strings:
            $wget_command = /\\bwget (-.*)?(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?/
        condition:
            any of them
        }
        """
    parser_name = "WgetParser"
    parser_description = (
        "This parser is designed to extract dependencies downloaded with wget."
    )

    def on_load(self) -> None:
        self.wget_block_extractor_regex = re.compile(
            "\\b(wget (-.*)?(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?[\s\S]+? saved \[\d+/\d+\])"
        )
        self.url_extractor = re.compile(
            "((http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/|ftp:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?)(\n|\r\n)"
        )
        self.ip_extractor = re.compile("(Connecting to \S+ \(\S+\)\|(\S+)\|:\d+)")
        self.filename_extractor = re.compile("(Saving to: [‘'](\S+)[’'])")

    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        dependencies = []
        wget_blocks = self.wget_block_extractor_regex.findall(document)
        for block in wget_blocks:
            urls = self.url_extractor.findall(block[0])
            connected_ips = self.ip_extractor.findall(block[0])
            filenames = self.filename_extractor.findall(block[0])
            source_command = block[0].split("\n")[0]
            dependencies.append(
                ExtractedDependency(
                    name=filenames[0][1],
                    version=urls[0][0],
                    type="wget",
                    extraction_source=source_command,
                    download_location=connected_ips[0][1],
                    result=DependencyRelation.CONSUMED,
                )
            )
        return dependencies

    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        findings = []
        return findings