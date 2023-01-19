# Copyright 2020-2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

FROM python:3.9-slim

ARG BUILD_VERSION=0.0.0

ENV SERVICE_PORT=8080
ENV SERVICE_VERSION=${BUILD_VERSION}

RUN apt-get update && apt-get upgrade -y && apt-get -y install gcc yara && rm -rf /var/lib/apt/lists*

COPY ./code/ /code/

RUN pip install -r code/requirements.txt

WORKDIR /code

RUN adduser --disabled-password --gecos '' microservice

USER microservice

CMD uvicorn microservice:microservice_api --host 0.0.0.0 --port ${SERVICE_PORT} --app-dir /code/