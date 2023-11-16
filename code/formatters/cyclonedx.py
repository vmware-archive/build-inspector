# Copyright 2020-2023 VMware, Inc.

import json
import uuid
from typing import List
from packageurl import PackageURL
from cyclonedx.model.bom import Bom
from cyclonedx.output import get_instance
from cyclonedx.output.xml import XmlV1Dot4
from cyclonedx.output.json import JsonV1Dot4
from models import DocumentReport, ExtractedDependency
from cyclonedx.model.component import Component, ComponentType
from formatters.base import BaseFormatter, AVAILABLE_FORMATTERS


class CycloneDXBaseFormatter(BaseFormatter):
    @classmethod
    def create_base_bom(cls, name) -> Bom:
        bom = Bom()
        rootComponent = Component(
            name=name,
            type=ComponentType.APPLICATION,
            bom_ref = f"root-{uuid.uuid4()}"  # Unique bom_ref for root component
        )
        bom.metadata.component = rootComponent
        bom.components.add(rootComponent)
        return bom, rootComponent

    @classmethod
    def format_dependencies(cls, dependencies: List[ExtractedDependency],  errors: List[str]) -> Bom:
        unique_name = f'dependency-{uuid.uuid4()}'
        bom, rootComponent = cls.create_base_bom(unique_name)
        all_deps = []
        for dependency in dependencies:
            component_bom_ref = f"{dependency.name}-{dependency.version}-{uuid.uuid4()}"  # Unique bom_ref for each dependency
            component = Component(
                type=ComponentType.LIBRARY,
                name=dependency.name,
                version=dependency.version,
                bom_ref=component_bom_ref,  # Setting bom_ref
                purl=PackageURL(type=dependency.type, namespace=None, name=dependency.name, version=dependency.version, qualifiers={}, subpath=None)
            )
            bom.components.add(component)
            all_deps.append(component)
        bom.register_dependency(rootComponent, [component])
        return bom


class CycloneDXJsonFormatter(CycloneDXBaseFormatter):
    MIME_TYPE = 'application/json'

    @classmethod
    def format_dependencies(cls, dependencies: List[ExtractedDependency],  errors: List[str]):
        bom = super().format_dependencies(dependencies, errors)
        serializedJSON = JsonV1Dot4(bom).output_as_string()
        return serializedJSON



class CycloneDXXMLFormatter(CycloneDXBaseFormatter):
    MIME_TYPE = 'application/xml'

    @classmethod
    def format_dependencies(cls, dependencies: List[ExtractedDependency],  errors: List[str]):
        bom = super().format_dependencies(dependencies, errors)
        serializedXML = XmlV1Dot4(bom).output_as_string()
        return serializedXML



AVAILABLE_FORMATTERS['cyclonedx'] = CycloneDXJsonFormatter
AVAILABLE_FORMATTERS['cyclonedx-json'] = CycloneDXJsonFormatter
AVAILABLE_FORMATTERS['cyclonedx-xml'] = CycloneDXXMLFormatter