# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from parsers.apt import AptParser
from parsers.dockerbuild import DockerBuildParser
from parsers.pip import PipParser
from parsers.ruby_bundle import BundleParser
from parsers.wget import WgetParser
from parsers.yum import YumParser
from parsers.npm import NpmParser
from parsers.curl import CurlParser
from parsers.goget import GoGetParser
from parsers.maven import MavenParser
from parsers.nuget import NuGetParser
from parsers.dnf import DNFParser

# TODO: Figure out dynamic loading of parsers
ALL_PARSERS = {
    "PipParser": PipParser,
    "YumParser": YumParser,
    "DockerBuildParser": DockerBuildParser,
    "BundleParser": BundleParser,
    "WgetParser": WgetParser,
    "AptParser": AptParser,
    "NpmParser": NpmParser,
    "CurlParser": CurlParser,
    "GoGetParser": GoGetParser,
    "MavenParser": MavenParser,
    "NuGetParser": NuGetParser,
    "DNFParser": DNFParser
}
