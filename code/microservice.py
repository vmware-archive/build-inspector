# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from sys import exc_info
from models import (
    DocumentReport,
    ExtractedDependency,
    ExtractedFinding,
    FindingSeverity,
)
from typing import Any, List, Optional
from fastapi import FastAPI, Response, HTTPException
from fastapi.params import Body
from starlette.requests import Request
from parsers import ALL_PARSERS

from formatters.base import AVAILABLE_FORMATTERS
from formatters.json import *
from formatters.spdx import *
from functools import lru_cache
import http.client
import logging
import yara
import os

APP_VERSION = os.environ.get("SERVICE_VERSION", "0.0.0")
YARA_RULES_PATH = os.path.dirname(os.path.realpath(__file__)) + "/rules/"

microservice_api = FastAPI(
    title="CI Build Log BoM Generator",
    description="This service provides utilities for processing and parsing CI build logging, resulting in a standardized Software Bill of Materials document that can be used to determine the specific dependencies used in a build.",
    version=APP_VERSION,
)

logger = logging.getLogger('BoMGeneratorMicroservice')


@lru_cache
def load_finding_yara_rules():
    files = os.listdir(YARA_RULES_PATH)
    filepaths = {}
    for file in files:
        if file.endswith(".yar"):
            filepaths[file.rstrip(".yar")] = os.path.join(YARA_RULES_PATH, file)
    rules = yara.compile(filepaths=filepaths)
    return rules


@lru_cache
def load_parser_rules():
    sources = {}
    for parser in ALL_PARSERS:
        sources[parser] = ALL_PARSERS[parser].yara_rule
    rules = yara.compile(sources=sources)
    return rules


### V1 API ENDPOINTS ###


@microservice_api.get("/v1/version")
def get_version():
    app_version = os.environ.get("SERVICE_VERSION", "0.0.0")
    return {"version": app_version}


@microservice_api.get("/")
@microservice_api.get("/v1/healthy")
def health_check():
    is_healthy = True  # TODO: Add an actual health check here!
    if is_healthy:
        return Response(status_code=200)
    else:
        return Response(status_code=500)


@microservice_api.get("/v1/parsers")
def list_parsers():
    parsers = []
    for parser in ALL_PARSERS.values():
        parsers.append(f"{parser.parser_name} - {parser.parser_description}")
    return {"available_parsers": parsers}


@microservice_api.get("/v1/rules")
def list_rules():
    findings_rules = load_finding_yara_rules()
    parser_rules = load_parser_rules()
    rules = []
    for rule in findings_rules:
        rules.append(
            f'{rule.identifier} - {rule.meta.get("description","No Description")}'
        )
    for rule in parser_rules:
        rules.append(
            f'{rule.identifier} - {rule.meta.get("description","No Description")}'
        )
    return {"available_rules": rules}


@microservice_api.post(
    "/v1/findings"
)  ### TODO: Change to have proper documentation in Swagger once https://github.com/tiangolo/fastapi/issues/1018 is fixed
async def generate_findings(
    type: Optional[str] = "buildlog",
    format: Optional[str] = "json",
    request: Request = Body(None, media_type="text/plain"),
):
    request_body = (
        await request.body()
    )  # Have to get the request body directly to allow non-JSON body until TODO is fixed ^^^
    if type == "buildlog":
        findings =  generate_buildlog_findings(request_body.decode())
        formatter = AVAILABLE_FORMATTERS.get(format, None)
        if not formatter:
            raise HTTPException(
            status_code=http.client.BAD_REQUEST,
            detail=f"Format {format} is invalid. Valid formats are {','.join(AVAILABLE_FORMATTERS.keys())}",
        )
        x = formatter.format_findings(findings)
        return Response(
            content=x,
            media_type=formatter.MIME_TYPE
            )
    else:
        raise HTTPException(
            status_code=http.client.BAD_REQUEST,
            detail=f"Finding input type {type} cannot be processed.",
        )


@microservice_api.post(
    "/v1/dependencies"
)  ### TODO: Change to have proper documentation in Swagger once https://github.com/tiangolo/fastapi/issues/1018 is fixed
async def generate_dependencies(
    type: Optional[str] = "buildlog",
    format: Optional[str] = "json",
    request: Request = Body(None, media_type="text/plain"),
):
    request_body = (
        await request.body()
    )  # Have to get the request body directly to allow non-JSON body until TODO is fixed ^^^
    if type == "buildlog":
        dependencies =  generate_buildlog_dependencies(request_body.decode())
        formatter = AVAILABLE_FORMATTERS.get(format, None)
        if not formatter:
            raise HTTPException(
            status_code=http.client.BAD_REQUEST,
            detail=f"Format {format} is invalid. Valid formats are {','.join(AVAILABLE_FORMATTERS.keys())}",
        )
        return Response(
            content=formatter.format_dependencies(dependencies),
            media_type=formatter.MIME_TYPE
            )
        
    else:
        raise HTTPException(
            status_code=http.client.BAD_REQUEST,
            detail=f"Dependencies input type {type} cannot be processed.",
        )


@microservice_api.post(
    "/v1/report"
)  ### TODO: Change to have proper documentation in Swagger once https://github.com/tiangolo/fastapi/issues/1018 is fixed
async def generate_report(
    type: Optional[str] = "buildlog",
    format: Optional[str] = "json",
    request: Request = Body(None, media_type="text/plain"),
):
    request_body = (
        await request.body()
    )  # Have to get the request body directly to allow non-JSON body until TODO is fixed ^^^
    if type == "buildlog":
        report = DocumentReport(
            dependencies=generate_buildlog_dependencies(request_body.decode()),
            findings=generate_buildlog_findings(request_body.decode()),
        )
        formatter = AVAILABLE_FORMATTERS.get(format, None)
        if not formatter:
            raise HTTPException(
            status_code=http.client.BAD_REQUEST,
            detail=f"Format {format} is invalid. Valid formats are {','.join(AVAILABLE_FORMATTERS.keys())}",
        )
        return Response(
            content=formatter.format_report(report),
            media_type=formatter.MIME_TYPE
            )
    else:
        raise HTTPException(
            status_code=http.client.BAD_REQUEST,
            detail=f"Report input type {type} cannot be processed.",
        )


def generate_buildlog_findings(document: str):
    findings_rules = load_finding_yara_rules()
    parser_rules = load_parser_rules()
    findings = []
    finding_matches = findings_rules.match(data=document)
    for match in finding_matches:
        for instance in match.strings:
            try:
                finding_severity = match.meta.get(
                    "severity", FindingSeverity.INFORMATIONAL
                )
            except ValueError as raised_error:
                logging.warn(
                    f"Invalid severity provided in rule {match.rule}. {raised_error}"
                )
                finding_severity = FindingSeverity.INFORMATIONAL
            findings.append(
                ExtractedFinding(
                    source=match.rule,
                    offset=instance[0],
                    finding_data=instance[2].decode(),
                    description=match.meta.get("description", "None Provided"),
                    category=match.meta.get("category", "Unknown"),
                    severity=finding_severity,
                )
            )
    parser_matches = parser_rules.match(data=document)
    parsers_to_run = []
    for match in parser_matches:
        parser = ALL_PARSERS[match.namespace]
        parsers_to_run.append(parser)
    for parser in set(parsers_to_run):
        parser_instance = parser()
        findings += parser_instance.get_document_findings(document)
    return findings


def generate_buildlog_dependencies(document: str):
    dependencies = []
    parser_rules = load_parser_rules()
    parser_matches = parser_rules.match(data=document)
    parsers_to_run = []
    for match in parser_matches:
        parser = ALL_PARSERS[match.namespace]
        parsers_to_run.append(parser)
    for parser in set(parsers_to_run):
        parser_instance = parser()
        dependencies += parser_instance.get_document_dependencies(document)
    return dependencies