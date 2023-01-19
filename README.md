# Build Inspector

The Build Inspector service is designed to provide the ability to process plaintext CI/CD build and deployment logs, extract any available software dependency information along with information about actions being taken in the build pipeline that could be vectors for a potential compromise.

### Build & Run

1. `docker build . -t bi_localdev`
2. `docker run -d -e SERVICE_PORT=8080 -p 8080:8080 --name bi_localdev bi_localdev`
3. API documentation can be located at http://localhost:8080/docs/swagger once the container is running.

## Documentation

API documentation can be located at http://localhost:8080/docs/swagger once the container is running.
Documentation for each of the included rules can be found in the rule's `.yar` file

## Contributing

The build-inspector project team welcomes contributions from the community. Before you start working with build-inspector, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

# Adding New Rules and Parsers
One of the easiest ways to add new functionality and value to the Build Inspector service is to add new detection and extraction options, so that additional information can be extracted from the build logs being processed.

## Should I Write a Rule or a Parser?
Rules and parsers are each designed to handle specific situations, and depending on the complexity of the functionality you desire to add, it's important to choose the correct type. 

A `rule` is a simple method of searching through a text log for one or more related patterns via regular expressions, and utilizing that data to generate a `Finding`. Typically rules are used to flag un-desirable behavior, or potentially items that could be of use to a developer in improving their CI pipeline. Examples of this include leaks of secret data into the build log, performing risky operations such as curl-bashing, or notifying developers of warnings and deprecation notices being shown in their build logs.

A `parser` is a more significant effort, typically used for parsing and extracting the output from one or more dependency managers being used in a CI build. Parsers typically work in 2 phases, which are a fast-match using one or more regular expressions to identify if the relevant dependency manager is being used, followed by a more intensive extraction step where you can utilize Python code to parse, extract and correlate information about the dependencies being used in a build. In addition to generating one or more `Dependency` objects, a parser can also generate one or more `Finding` objects, if it is determined that they are needed. For example, a parser might look at the output of an `apt-get install` command being run, extract the specific names and versions of packages that are installed (which then would generate `Dependency` objects), and potentially identify any warning or deprecation messages being output (which would generate `Finding` objects).

## Writing a New Rule
Behavioral rules are created using the YARA YAML format, with specific fields used for adding additional details. Reference on the YARA rule language can be found [here](https://yara.readthedocs.io/en/stable/writingrules.html).

The general format of a rule is as follows, along with basic details of each field.
```
rule my_new_rule                                             ## The rule name should follow DNS naming standards
{
    meta:
        description = "Doing this thing is bad because XYZ"  ## Should be a basic description of what the rule looks for and why it is a rule. 
        severity = "informational"                           ## Severity should be a reflection of the severity of the issue indicated by this rule's findings
        category = "unknown"                                 ## Category should be used to group similar sets of rules together
    strings:                                                 ## Strings and condition are used to identify if the behavior/leak exists
        $mystring1 = /thing to look for/
        $mystring2 = /other thing/
    condition:                                               ## Conditions are used to combine multiple string conditions through boolean logic
        any of them
}
```

Rules will generate one finding per match of the rule in a log file. 

## Writing a New Parser

Dependency parsers are created using a mix of YARA rule language, and more advanced text processing through a Python class. All parsers should be based on the `parsers.base.ParserBase` abstract class. The items that MUST be implemented in this new class are as follows:

- `yara_rule` - This should be the full text of a YARA rule that will trigger ONLY if this parser should be run in full. The metadata section of the rule should include the attribute `parser` which should match the value of `parser_name` for this new class
- `parser_name` - The name assigned to this specific parser
- `parser_description` - A brief description of what this specific parser is designed to parse
- `get_document_dependencies()` - This method should be the main method that is called to parse actual dependency information from any log text.
- `get_document_findings()` - This method, while not completely necessary to all parsers, must be implemented. It can return a list of any findings that relate to this specific dependency manager, or an empty list
- The parser MUST be added to the list of `ALL_PARSERS` in the `__init__.py` file at `/code/parsers/` to be loaded at startup.

The following items are optional to implement:

- `on_load()` - This method is provided as a way to allow for pre-configuration of any necessary items that might take a longer time to process, or can be processed once rather than each time the parser is run. Examples include things like compiling regex statements

## Adding Test Cases for Parsers and Rules 

A critical part of the automated testing of the microservice lies in the automated functional test found at `/tests/automated_functional_test`. Any new rule or parser that is added to the microservice should have basic test configurations added to ensure not only that the expected results are generated for a known input, but also that changes to the microservice over time do not change the results of running a specific parser or rule. Test cases should be added as YAML files to the `/tests/automated_functional_test/test_configs` directory, with a new file being used for each new parser or rule. An example test configuration is shown here:
```
name: example                         ## Ideally this name would match the name of the parser or rule under test
description: An example test config   ## This should have a brief description of the test cases used
config:
  input_data: |                       ## The input data is the mock log data to be extracted against. 
                                      ## Typically this should be real-world logging data to allow for the
                                      ## best possible test reliability
          root@02424c6b934f:/# bundle install
          Fetching gem metadata from https://rubygems.org/.
          Resolving dependencies...
          Using bundler 2.2.32
          Fetching python 0.0.1
          Installing python 0.0.1
          Fetching sqlite3 1.4.2
          Installing sqlite3 1.4.2 with native extensions
          Bundle complete! 2 Gemfile dependencies, 3 gems now installed.
          Use `bundle info [gemname]` to see where a bundled gem is installed.
          root@02424c6b934f:/# bundle install
          Fetching gem metadata from https://rubygems.org/.
          Resolving dependencies...
          Using bundler 2.2.32
          Fetching package 0.0.1
          Installing package 0.0.1
          Bundle complete! 1 Gemfile dependency, 2 gems now installed.
          Use `bundle info [gemname]` to see where a bundled gem is installed.
  expected_dependencies:            ## This should be a list of all of the dependency objects that are
                                    ## expected to be extracted from the provided data
    - type: example
      name:  example
      version: 0.0.1
      download_location: example
  expected_findings:                ## This should be a list of all of the finding objects that are
                                    ## expected to be extracted from the provided data
    - source: example
      finding_data: example
    - source: example
      finding_data: notwhatiwant
      false_positive: true          ## the false_positive flag can be used to identify items that should NOT
                                    ## be extracted, and the test case will fail if they ARE extracted

## License
VMware Build Inspector Copyright 2020-2023 VMware, Inc.

The BSD-2 license (the "License") set forth below applies to all parts of the VMware Image Builder Examples project. You may not use this file except in compliance with the License.

BSD-2 License

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.