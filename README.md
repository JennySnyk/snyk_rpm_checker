# Snyk PURL Vulnerability Checker

This script checks for vulnerabilities in a list of RPM packages by querying the Snyk API using their Package URLs (PURLs).

## Prerequisites

- Python 3
- A Snyk account with an API token and Organization ID.

## Setup

1.  **Clone the repository or download the files.**

2.  **Install the required Python packages:**

    ```bash
    pip install -r requirements.txt
    ```

3.  **Set your Snyk API token and Organization ID as environment variables.** You can find these in your Snyk account settings.

    On macOS or Linux:
    ```bash
    export SNYK_TOKEN='your_snyk_api_token'
    export SNYK_ORG_ID='your_snyk_organization_id'
    ```

    On Windows (Command Prompt):
    ```bash
    set SNYK_TOKEN=your_snyk_api_token
    set SNYK_ORG_ID=your_snyk_organization_id
    ```

    On Windows (PowerShell):
    ```bash
    $env:SNYK_TOKEN="your_snyk_api_token"
    $env:SNYK_ORG_ID="your_snyk_organization_id"
    ```

## Usage

Create a file (e.g., `purls.txt`) and add the PURLs you want to check, with one PURL per line.

Then, run the script from your terminal, providing the path to your file:

```bash
python snyk_vuln_checker.py --file purls.txt
```

The script will read the PURLs from the specified file, query the Snyk API, and print any found vulnerabilities for each package.

### Using the Virtual Environment

If you are using the created virtual environment, the command would be:

```bash
./venv/bin/python snyk_vuln_checker.py --file purls.txt
```

## PURL Formatting for RPMs

When checking RPM packages, the Snyk API requires the PURL to include a `distro` qualifier. The format should be:

`pkg:rpm/[namespace]/[package]@[version]?arch=[architecture]&distro=[distribution]`

For example, for a package from CentOS 8, the PURL would look like this:
`pkg:rpm/centos/harfbuzz@1.7.5-4.el8?arch=x86_64&distro=centos-8`

Failure to include the `distro` qualifier will result in a `400 Bad Request` error from the API.

## Example Output

Here is an example of a successful output when checking the `harfbuzz` package with a correctly formatted PURL:

```
Checking for vulnerabilities in: pkg:rpm/centos/harfbuzz@1.7.5-4.el8?arch=x86_64&distro=centos-8
  Found 1 vulnerabilities.
    - ID: SNYK-CENTOS8-HARFBUZZ-3311786
      Title: Allocation of Resources Without Limits or Throttling
      Severity: medium
----------------------------------------
```
