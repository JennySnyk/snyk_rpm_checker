import requests
import os
import argparse
import urllib.parse

# It's recommended to set your Snyk token as an environment variable
# and not hardcode it in the script.
# export SNYK_TOKEN='your_snyk_api_token'
SNYK_TOKEN = os.getenv('SNYK_TOKEN')
ORG_ID = os.getenv('SNYK_ORG_ID') # Get your Org ID from your Snyk account settings

if not SNYK_TOKEN or not ORG_ID:
    print("Error: SNYK_TOKEN and SNYK_ORG_ID environment variables must be set.")
    exit(1)

def get_purls_from_file(filepath):
    """Reads PURLs from a file, one per line."""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: The file '{filepath}' was not found.")
        exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        exit(1)

def check_purl_vulnerabilities(purl):
    """Queries the Snyk API for vulnerabilities for a given PURL."""
    encoded_purl = urllib.parse.quote(purl, safe='')
    api_version = "2024-05-24"  # The API version is required as a query parameter
    url = f"https://api.snyk.io/rest/orgs/{ORG_ID}/packages/{encoded_purl}/issues?version={api_version}"
    headers = {
        'Authorization': f'token {SNYK_TOKEN}',
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        return {'error': f"HTTP error occurred: {http_err}", 'details': response.text}
    except Exception as err:
        return {'error': f"An error occurred: {err}"}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check Snyk for vulnerabilities for a list of PURLs.')
    parser.add_argument('-f', '--file', required=True, help='Path to a file containing PURLs, one per line.')
    args = parser.parse_args()

    purls_to_check = get_purls_from_file(args.file)

    for purl in purls_to_check:
        print(f"Checking for vulnerabilities in: {purl}")
        vulnerabilities = check_purl_vulnerabilities(purl)
        
        if 'error' in vulnerabilities:
            print(f"  Error: {vulnerabilities['error']}")
            if 'details' in vulnerabilities:
                print(f"  Details: {vulnerabilities['details']}")
        elif vulnerabilities.get('data'):
            print(f"  Found {len(vulnerabilities['data'])} vulnerabilities.")
            for issue in vulnerabilities['data']:
                attributes = issue.get('attributes', {})
                print(f"    - ID: {issue.get('id')}")
                print(f"      Title: {attributes.get('title')}")
                print(f"      Severity: {attributes.get('effective_severity_level')}")
        else:
            print("  No vulnerabilities found or an unexpected response was received.")
        print("-"*40)
