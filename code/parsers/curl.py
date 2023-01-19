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


class CurlParser(ParserBase):
    yara_rule = """
    rule curl
    {
    meta:
        description = "detects curl being run to download a file or files"
        parser = "CurlParser"
    strings:
        $curl_command = /\\curl (-.*)?(http:\/\/(\S+)|https:\/\/(\S+)|www\.(\S+)|ftp:\/\/?(\S+))/
    condition:
        any of them
    }
    """
    parser_name = "CurlParser"
    parser_description = (
        "This parser is designed to extract dependencies downloaded with CURL command."
    )

    def on_load(self) -> None:
        self.curl_extractor_regex = re.compile(r'((?:\S+[ \t])?curl (-.*)?(\S+)?(https?:\S+|www\.\S+|ftp:\S+(.*)))')
        self.url_extractor_regex = re.compile(r"(https?:\S+[^'\"]|www\.\S+[^'\"]|ftp:\S+[^'\"])")
        self.name_extractor_regex = re.compile(r"https?://|(www\.)|ftp://?")


    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        dependencies = []
        curl_dependencies = self.curl_extractor_regex.findall(document)
        for match in curl_dependencies:
            url_extract = self.url_extractor_regex.findall(match[3])[0]
            name_extract = self.name_extractor_regex.sub('', url_extract)
            dependencies.append(
                ExtractedDependency(
                    name=name_extract,
                    version="Unknown",
                    type="curl",
                    extraction_source=match[0],
                    download_location=url_extract,
                    result=DependencyRelation.CONSUMED,
                )
            )
        return dependencies

    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        findings = []
        return findings