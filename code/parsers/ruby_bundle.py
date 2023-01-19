# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from typing import List
from parsers.base import ParserBase
from models import DependencyRelation, ExtractedDependency, ExtractedFinding
import re


class BundleParser(ParserBase):

    yara_rule = """
        rule ruby_bundle
        {
        meta:
            description = "detects bundle install being run"
            parser = "BundleParser"
        strings:
            $install = /\\bbundle(\\b|\\b.*\\b)install\\b/
        condition:
            any of them
        }
        """
    parser_name = "BundleParser"
    parser_description = "This parser is designed to extract dependencies brought in through the Ruby 'bundler' package installer."

    def on_load(self) -> None:
        self.bundler_block_extractor_regex = re.compile(
            "(\\bbundle(\\b|\\b.*\\b)install\\b[\s\S]+?Bundle complete! \d+ Gemfile dependenc(y|ies), \d+ gems? now installed.)",
            re.MULTILINE,
        )
        self.install_line_extractor_regex = re.compile("(Installing (\S+) ([\d\.]+))")

    def get_document_dependencies(self, document: str) -> List[ExtractedDependency]:
        dependencies = []
        bundler_blocks = self.bundler_block_extractor_regex.findall(document)
        for block in bundler_blocks:
            dependency_matches = self.install_line_extractor_regex.findall(block[0])
            for match in dependency_matches:
                dependencies.append(
                    ExtractedDependency(
                        name=match[1],
                        version=match[2],
                        type="ruby",
                        extraction_source=match[0],
                        download_location="Unknown",
                        result=DependencyRelation.CONSUMED,
                    )
                )
        return dependencies

    def get_document_findings(self, document: str) -> List[ExtractedFinding]:
        findings = []

        return findings