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
        self.curl_extractor_regex = re.compile(r'(curl(?: -[^ \t]+)* (\S+)(?:(?: https?|www\.|ftp:)\S+)*.(?:(?!curl).)*)')
        self.url_extractor_regex = re.compile(r"(https?:\S+[^'\"]|www\.\S+[^'\"]|ftp:\S+[^'\"])")
        self.name_extractor_regex = re.compile(r"https?://|(www\.)|ftp://?")


    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        dependencies = []
        curl_dependencies = self.curl_extractor_regex.findall(document)
        for match in curl_dependencies:
            curl_extraction_source = match[0]
            url_extract = self.url_extractor_regex.findall(curl_extraction_source)
            download_location = url_extract[0].strip() if url_extract else None
            if download_location is None:
                continue
            name_extract = self.name_extractor_regex.sub('', download_location)
            dependencies.append(
                ExtractedDependency(
                    name=name_extract,
                    version="Unknown",
                    type="curl",
                    extraction_source=curl_extraction_source,
                    download_location=download_location,
                    result=DependencyRelation.CONSUMED,
                )
            )
        return dependencies

    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        findings = []
        return findings