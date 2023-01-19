# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import sys
import os
import yara

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "code"))
from parsers.nuget import NuGetParser
from models import ExtractedDependency, DependencyRelation


def test_yara_rule():
    # Arrange
    POSITIVE_TEST_STRINGS = [
        "nuget install Newtonsoft.Json -OutputDirectory packages",
        "nuget install packages.config -OutputDirectory packages",
        "nuget install elmah",
        "nuget install ninject -OutputDirectory c:\proj",
        "nuget install DevExtreme.AspNet.Core -Source https://nuget.devexpress.com/api",
        "nuget.exe install Newtonsoft.Json -Version 4.0.5",
        "mono /usr/local/bin/nuget.exe install MyPackage -Source c:\Temp\Packages -Source https://api.nuget.org/v3/index.json -DependencyVersion Lowest -OutputDirectory c:\Temp\Output"
    ]
    NEGATIVE_TEST_STRINGS = [
        "#6 [resource  3/23] RUN apt install -y --no-install-recommends nuget gzip",
        "#7 [resource  4/23] RUN apt install nuget",
    ]
    rule = yara.compile(sources={
        "pytest": NuGetParser.yara_rule
    })

    # Act/Assert
    for string in POSITIVE_TEST_STRINGS:
        result = rule.match(data=string)
        assert result != []
    for string in NEGATIVE_TEST_STRINGS:
        result = rule.match(data=string)
        assert result == []


def test_on_load():
    NuGetParser().on_load()


def test_get_document_dependencies():
    TEST_DATA = """
    nuget install Newtonsoft.json -OutputDirectory packages
    
    nuget install packages.config -OutputDirectory packages
    
    nuget install elmah
    
    nuget install ninject -OutputDirectory c:\proj
    
    nuget install DevExtreme.AspNet.Core -Source https://nuget.devexpress.com/api
    
    nuget.exe install Newtonsoft.json -Version 4.0.5
    
    mono /usr/local/bin/nuget.exe install MyPackage -Source https://nuget.devexpress.com/api -Source https://api.nuget.org/v3/index.json -DependencyVersion Lowest -OutputDirectory c:\Temp\Output

    #6 [resource  3/23] RUN apt install -y --no-install-recommends     curl     nuget     gzip     jq     openssl     libssl-dev     make     g++     openssh-client     libstdc++6 
    """

    expected_output = [
        ExtractedDependency(
            name='Newtonsoft.json',
            version='Unknown',
            type='nuget',
            result=DependencyRelation.CONSUMED,
            extraction_source='nuget install Newtonsoft.json -OutputDirectory packages',
            download_location='Newtonsoft.json'
        ),
        ExtractedDependency(
            name='packages.config',
            version='Unknown',
            type='nuget',
            result=DependencyRelation.CONSUMED,
            extraction_source='nuget install packages.config -OutputDirectory packages',
            download_location='packages.config'
        ),
        ExtractedDependency(
            name='elmah',
            version='Unknown',
            type='nuget',
            result=DependencyRelation.CONSUMED,
            extraction_source='nuget install elmah',
            download_location='elmah'
        ),
        ExtractedDependency(
            name='ninject',
            version='Unknown',
            type='nuget',
            result=DependencyRelation.CONSUMED,
            extraction_source='nuget install ninject -OutputDirectory c:\\proj',
            download_location='ninject'
        ),
        ExtractedDependency(
            name='DevExtreme.AspNet.Core',
            version='Unknown',
            type='nuget',
            result=DependencyRelation.CONSUMED,
            extraction_source='nuget install DevExtreme.AspNet.Core -Source https://nuget.devexpress.com/api',
            download_location='https://nuget.devexpress.com/api'
        ),
        ExtractedDependency(
            name='Newtonsoft.json',
            version='4.0.5',
            type='nuget',
            result=DependencyRelation.CONSUMED,
            extraction_source='nuget.exe install Newtonsoft.json -Version 4.0.5',
            download_location='Newtonsoft.json'
        ),
        ExtractedDependency(
            name='MyPackage',
            version='Unknown',
            type='nuget',
            result=DependencyRelation.CONSUMED,
            extraction_source='nuget.exe install MyPackage -Source https://nuget.devexpress.com/api -Source https://api.nuget.org/v3/index.json -DependencyVersion Lowest -OutputDirectory c:\\Temp\\Output',
            download_location='https://nuget.devexpress.com/api, https://api.nuget.org/v3/index.json'
        )
    ]

    parser = NuGetParser()
    result = parser.get_document_dependencies(document=TEST_DATA)
    assert result == expected_output

