# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import sys
import os
import yara

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "code"))
from parsers.maven import MavenParser
from models import ExtractedDependency, DependencyRelation


def test_yara_rule():
    # Arrange
    POSITIVE_TEST_STRINGS = [
        "mvn dependency:get -DrepoUrl=something -Dartifact=group:artifact:version",
        "mvn dependency:copy -Dartifact=group:artifact:version -DoutputDirectory=.",
        "cmd: mvn dependency:get -DremoteRepositories=http://localhost:8082/nexus/content/repositories/releases -DgroupId=my.test.testapp -DartifactId=APP -Dversion=001 -Dpackaging=ear -Dtransitive=false",
        "cmd: mvn dependency:copy -Dartifact=my.test.testapp:APP:001:ear -DoutputDirectory=./Dump/",
        "mvn dependency:get -Dartifact=org.springframework:spring-context:5.0.0.BUILD-SNAPSHOT",
        "mvn dependency:get -Dartifact=org.springframework:spring-core:5.3.15"
    ]
    NEGATIVE_TEST_STRINGS = [
        "#6 [resource  3/23] RUN apt install -y --no-install-recommends maven gzip",
        "#7 [resource  4/23] RUN apt install maven",
    ]
    rule = yara.compile(sources={
        "pytest": MavenParser.yara_rule
    })

    # Act/Assert
    for string in POSITIVE_TEST_STRINGS:
        result = rule.match(data=string)
        assert result != []
    for string in NEGATIVE_TEST_STRINGS:
        result = rule.match(data=string)
        assert result == []


def test_on_load():
    MavenParser().on_load()


def test_get_document_dependencies():
    TEST_DATA = """
    mvn dependency:get -DrepoUrl=something -Dartifact=group:artifact:version

    RUN mvn dependency:copy -Dartifact=group:artifact:version -DoutputDirectory=.
    
    cmd: mvn dependency:get -DremoteRepositories=http://localhost:8082/nexus/content/repositories/releases -DgroupId=my.test.testapp -DartifactId=APP -Dversion=001 -Dpackaging=ear -Dtransitive=false
    
    cmd: mvn dependency:copy -Dartifact=my.test.testapp:APP:001:ear -DoutputDirectory=./Dump/
    
    mvn dependency:get -Dartifact=org.springframework:spring-context:5.0.0.BUILD-SNAPSHOT
    
    mvn dependency:get -Dartifact=org.springframework:spring-core:5.3.15
    
    #6 [resource  3/23] RUN apt install -y --no-install-recommends    maven   gzip     jq     openssl     libssl-dev     make     g++     openssh-client     libstdc++6 
    """

    expected_output = [
        ExtractedDependency(
            name='group:artifact:version',
            version='version',
            type='maven get',
            result=DependencyRelation.CONSUMED,
            extraction_source='mvn dependency:get -DrepoUrl=something -Dartifact=group:artifact:version',
            download_location='something'
        ),
        ExtractedDependency(
            name='group:artifact:version',
            version='version',
            type='maven copy',
            result=DependencyRelation.CONSUMED,
            extraction_source='RUN mvn dependency:copy -Dartifact=group:artifact:version -DoutputDirectory=.',
            download_location='Unknown'
        ),
        ExtractedDependency(
            name='APP',
            version='APP',
            type='maven get',
            result=DependencyRelation.CONSUMED,
            extraction_source='cmd: mvn dependency:get -DremoteRepositories=http://localhost:8082/nexus/content/repositories/releases -DgroupId=my.test.testapp -DartifactId=APP -Dversion=001 -Dpackaging=ear -Dtransitive=false',
            download_location='http://localhost:8082/nexus/content/repositories/releases'
        ),
        ExtractedDependency(
            name='my.test.testapp:APP:001:ear',
            version='ear',
            type='maven copy',
            result=DependencyRelation.CONSUMED,
            extraction_source='cmd: mvn dependency:copy -Dartifact=my.test.testapp:APP:001:ear -DoutputDirectory=./Dump/',
            download_location='Unknown'
        ),
        ExtractedDependency(
            name='org.springframework:spring-context:5.0.0.BUILD-SNAPSHOT',
            version='5.0.0.BUILD-SNAPSHOT',
            type='maven get',
            result=DependencyRelation.CONSUMED,
            extraction_source='mvn dependency:get -Dartifact=org.springframework:spring-context:5.0.0.BUILD-SNAPSHOT',
            download_location='Unknown'
        ),
        ExtractedDependency(
            name='org.springframework:spring-core:5.3.15',
            version='5.3.15',
            type='maven get',
            result=DependencyRelation.CONSUMED,
            extraction_source='mvn dependency:get -Dartifact=org.springframework:spring-core:5.3.15',
            download_location='Unknown'
        )
    ]

    parser = MavenParser()
    result = parser.get_document_dependencies(document=TEST_DATA)
    assert result == expected_output

