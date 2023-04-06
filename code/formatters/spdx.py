# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import os
from typing import List
from formatters.base import BaseFormatter, AVAILABLE_FORMATTERS
from models import DocumentReport, ExtractedDependency, ExtractedFinding
from spdx.document import Document, License, ExternalDocumentRef
from spdx.annotation import Annotation
from spdx.creationinfo import Tool
from spdx.package import Package
from spdx.version import Version
from spdx.writers import json, xml
from spdx.checksum import Algorithm
from hashlib import sha1
from json import dumps, loads
from uuid import uuid4
from io import StringIO


APP_VERSION = os.environ.get("SERVICE_VERSION", "0.0.0")
SPDX_SPEC_VERSION = Version(2,0)
SPDX_METADATA_LICENSE = License.from_identifier("CC0-1.0")
SPDX_NAMESPACE_BASE = "http://spdx.org/spdxdocs/"
SPDX_TOOL = Tool(f'BoM Generator-v{APP_VERSION}')

def create_base_spdx_document(name) -> Document:
    newDocument = Document()
    newDocument.version = SPDX_SPEC_VERSION
    newDocument.data_license = SPDX_METADATA_LICENSE
    newDocument.name = name
    newDocument.namespace = create_spdx_namespace(name)
    newDocument.spdx_id = f'{newDocument.namespace}#SPDXRef-DOCUMENT'
    newDocument.creation_info.add_creator(SPDX_TOOL)
    newDocument.creation_info.set_created_now()
    return newDocument

def create_spdx_namespace(documentName: str) -> str:
    return f'{SPDX_NAMESPACE_BASE}{documentName}-{uuid4()}'

def document_to_json(SPDX_document: Document) -> str:
    out_buffer = StringIO()
    json.write_document(SPDX_document, out_buffer,validate=False) # Disable validation as we are not providing fully spec compliant documents (Missing package details for base package due to not having them)
    out_buffer.seek(0)
    return out_buffer.read()

def document_to_xml(SPDX_document: Document) -> str:
    out_buffer = StringIO()
    xml.write_document(SPDX_document, out_buffer, validate=False) # Disable validation as we are not providing fully spec compliant documents (Missing package details for base package due to not having them)
    out_buffer.seek(0)
    return out_buffer.read()


class SPDXBaseFormatter(BaseFormatter):
    __TO_METHOD__ = None

    @classmethod
    def format_findings(cls, findings: List[ExtractedFinding], errors: List[str]):
        SPDX_document = create_base_spdx_document('LogFileSource')
        SPDX_document.package = Package(name=SPDX_document.name,spdx_id=SPDX_document.spdx_id)
        for finding in findings:
            finding_annotation = Annotation()
            finding_annotation.annotator = SPDX_TOOL
            finding_annotation.spdx_id = SPDX_document.spdx_id
            finding_annotation.set_annotation_date_now()
            finding_annotation.annotation_type = "OTHER"
            finding_annotation.comment = finding.json()
            SPDX_document.add_annotation(finding_annotation)
        return cls.__TO_METHOD__(SPDX_document)

    @classmethod
    def format_dependencies(cls, dependencies: List[ExtractedDependency], errors: List[str]):
        dependent_documents = []
        for dependency in dependencies:
            dep_document = create_base_spdx_document(dependency.name)
            dep_document.package = Package(name=dependency.name, spdx_id=dep_document.spdx_id, download_location=dependency.download_location, version=dependency.version)
            dependent_documents.append(dep_document)
        return dependent_documents

    @classmethod
    def format_report(cls, report: DocumentReport):
        SPDX_document = create_base_spdx_document('LogFileSource')
        SPDX_document.package = Package(name=SPDX_document.name,spdx_id=SPDX_document.spdx_id)
        for finding in report.findings:
            finding_annotation = Annotation()
            finding_annotation.annotator = SPDX_TOOL
            finding_annotation.spdx_id = SPDX_document.spdx_id
            finding_annotation.set_annotation_date_now()
            finding_annotation.annotation_type = "OTHER"
            finding_annotation.comment = finding.json()
            SPDX_document.add_annotation(finding_annotation)
        dependent_documents = []
        for dependency in report.dependencies:
            dep_document = create_base_spdx_document(dependency.name)
            dep_document.package = Package(name=dependency.name, spdx_id=dep_document.spdx_id, download_location=dependency.download_location, version=dependency.version)
            SPDX_document.ext_document_references.append(
                ExternalDocumentRef(
                    external_document_id=dep_document.spdx_id,
                    check_sum=Algorithm(identifier="SHA1",value=sha1(cls.__TO_METHOD__(dep_document).encode()).hexdigest()),
                    spdx_document_uri=dep_document.namespace
                    )
                    )
            dependent_documents.append(dep_document)
        return (SPDX_document, dependent_documents)
        

class SPDXJsonFormatter(SPDXBaseFormatter):
    __TO_METHOD__ = document_to_json
    MIME_TYPE = 'application/json'

    @classmethod
    def format_dependencies(cls, dependencies: List[ExtractedDependency], errors: List[str]):
        dependent_docs = super().format_dependencies(dependencies, errors)
        return_value = f"[{','.join([document_to_json(doc) for doc in dependent_docs])}]"
        return return_value

    @classmethod
    def format_report(cls, report: DocumentReport):
        base_doc, dependent_docs = super().format_report(report)
        return_value = f"[{document_to_json(base_doc)},{','.join([document_to_json(doc) for doc in dependent_docs])}]"
        return return_value

class SPDXXMLFormatter(SPDXBaseFormatter):
    MIME_TYPE = 'application/xml'
    __TO_METHOD__ = document_to_xml

    @classmethod
    def format_dependencies(cls, dependencies: List[ExtractedDependency], errors: List[str]):
        dependent_docs = super().format_dependencies(dependencies, errors)
        return_value = '\n---\n'.join([document_to_xml(doc) for doc in dependent_docs])
        return return_value

    @classmethod
    def format_report(cls, report: DocumentReport):
        base_doc, dependent_docs = super().format_report(report)
        return_value = document_to_xml(base_doc)
        return_value += '\n---\n'
        return_value += '\n---\n'.join([document_to_xml(doc) for doc in dependent_docs])
        return return_value

AVAILABLE_FORMATTERS['spdx'] = SPDXJsonFormatter
AVAILABLE_FORMATTERS['spdx-json'] = SPDXJsonFormatter
AVAILABLE_FORMATTERS['spdx-xml'] = SPDXXMLFormatter