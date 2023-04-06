# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from typing import List
import yaml
import json
from pydantic import BaseModel
from os.path import isfile

class Settings(BaseModel):
    parser_timeout: int = 1                      # Max time for a single parser to run
    disabled_parsers: List[str] = []             # List of parsers to disable

    @classmethod
    def load_from_file(cls, file_path: str = "defaults.yml"):
        if isfile(file_path):
            with open(file_path, 'r') as settings_file:
                settings = yaml.load(settings_file, yaml.SafeLoader)
            settings_obj = cls.parse_raw(json.dumps(settings))
            return settings_obj
        else:
            return cls()