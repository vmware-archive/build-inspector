# Contributing to build-inspector

We welcome contributions from the community and first want to thank you for taking the time to contribute!

Please familiarize yourself with the [Code of Conduct](https://github.com/vmware/.github/blob/main/CODE_OF_CONDUCT.md) before contributing.

Before you start working with build-inspector, please read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on as an open-source patch.

## Ways to contribute

We welcome many different types of contributions and not all of them need a Pull request. Contributions may include:

* New features and proposals
* Adding new rules and parsers
* Documentation
* Bug fixes
* Issue Triage
* Answering questions and giving feedback
* Helping to onboard new contributors
* Other related activities

## Getting started

### Build & Run

1. `$ docker build . -t bi_localdev`
2. `docker run -d -e SERVICE_PORT=8080 -p 8080:8080 --name bi_localdev bi_localdev`
3. API documentation can be located at http://localhost:8080/docs/swagger once the container is running.

### Running Tests
* Pytest Tests: `pytest tests/unit_tests`
* Functional Tests (with local instance running): `python tests/automated_functional_test/functional_test.py --configs tests/automated_functional_test/test_configs --url https://localhost:8080`

## Contribution Flow

This is a rough outline of what a contributor's workflow looks like:

* Make a fork of the repository within your GitHub account
* Create a topic branch in your fork from where you want to base your work
* Make commits of logical units
* Make sure your commit messages are with the proper format, quality and descriptiveness (see below)
* Ensure that all tests are passing
* Push your changes to the topic branch in your fork
* Create a pull request containing that commit

We follow the GitHub workflow and you can find more details on the [GitHub flow documentation](https://docs.github.com/en/get-started/quickstart/github-flow).

### Pull Request Checklist

Before submitting your pull request, we advise you to use the following:

1. Check if your code changes will pass code linting checks, unit tests, and the automated functional tests.
2. Ensure your commit messages are descriptive. We follow the conventions on [How to Write a Git Commit Message](http://chris.beams.io/posts/git-commit/). Be sure to include any related GitHub issue references in the commit message. See [GFM syntax](https://guides.github.com/features/mastering-markdown/#GitHub-flavored-markdown) for referencing issues and commits.
3. Check the commits and commits messages and ensure they are free from typos.

## Testing Conventions
Addition or modification of any rules or dependency parsers should include test cases in the `/tests/automated_functional_test/test_configs/` directory.

Addition or modification of service code should include Pytest unit test coverage in `/tests/unit_tests`

## Reporting Bugs and Creating Issues

For specifics on what to include in your report, please follow the guidelines in the issue and pull request templates when available.


## Ask for Help

The best way to reach us with a question when contributing is to ask on the original GitHub issue.