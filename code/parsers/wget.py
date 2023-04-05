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
import time


class WgetParser(ParserBase):

    yara_rule = """
        rule wget
        {
        meta:
            description = "detects wget being run to download a file or files"
            parser = "WgetParser"
        strings:
            $wget_command = /\\bwget (-.*)?(https?:\/\/)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}/
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
            r"\b(wget (-.*)?((https?:\/\/)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/=]*)))\s"
        )
        self.url_extractor_regex = re.compile(
            r"((http|ftp|https):\/\/([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-]*/([\w.,@?^=%&:\/~+#-]*[\w@?^=%&\/~+#-])))"
        )
        self.output_extractor_regex = re.compile(
            r"-O (.*?) "
        )

    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        dependencies = []
        wget_blocks = self.wget_block_extractor_regex.findall(document)
        for block in wget_blocks:
            command = block[0]
            urls = self.url_extractor_regex.findall(command)
            if urls:
                url = urls[0][0]
            else:
                url = "unknown"
            output_files = self.output_extractor_regex.findall(command)
            if output_files:
                filename = output_files[0]
            elif urls:
                filename = urls[0][4]
            else:
                filename = "unknown"

            dependencies.append(
                ExtractedDependency(
                    name=filename,
                    version="unknown",
                    type="wget",
                    extraction_source=command,
                    download_location=url,
                    result=DependencyRelation.CONSUMED,
                )
            )
        return dependencies

    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        findings = []
        return findings