import argparse
import requests
import logging
from bs4 import BeautifulSoup
import urllib.parse
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default parameter values to fuzz
DEFAULT_PARAMETERS = ['id', 'page', 'order', 'sort', 'limit', 'offset', 'size', 'count']
DEFAULT_FUZZ_VALUES = ["'", "\"", "<script>alert('XSS')</script>", "1=1", "1=2",  "%27", "%22", "..%2F..%2Fetc%2Fpasswd", "NULL", "null"] # Added NULL/null
DEFAULT_TIMEOUT = 10 # Timeout for requests

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description='Detects potential parameter tampering vulnerabilities.')
    parser.add_argument('url', help='The URL to scan.')
    parser.add_argument('--params', nargs='+', default=DEFAULT_PARAMETERS,
                        help='List of parameters to fuzz (default: id page order sort limit offset size count)')
    parser.add_argument('--fuzz_values', nargs='+', default=DEFAULT_FUZZ_VALUES,
                        help='List of fuzz values to use (default: \', ", <script>alert(\'XSS\')</script>, 1=1, 1=2, %27, %22, ..%2F..%2Fetc%2Fpasswd, NULL, null)') # Added NULL/null
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help='Timeout for requests in seconds (default: 10)')
    parser.add_argument('--user_agent', type=str, default='vscan-parameter-tampering-detector/1.0', help='Custom User-Agent header')
    parser.add_argument('--data', type=str, help='Optional data to send with the request (e.g., POST data).  Must be URL encoded')
    parser.add_argument('--method', type=str, default='GET', choices=['GET', 'POST'], help='HTTP method to use (GET or POST, default: GET)')

    return parser

def sanitize_url(url):
    """
    Sanitizes the URL to prevent common errors.

    Args:
        url (str): The URL to sanitize.

    Returns:
        str: The sanitized URL.
    """
    url = url.strip()
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    return url

def check_parameter_tampering(url, param, fuzz_value, timeout, user_agent, data=None, method='GET'):
    """
    Checks for parameter tampering vulnerabilities by fuzzing a specific parameter.

    Args:
        url (str): The URL to scan.
        param (str): The parameter to fuzz.
        fuzz_value (str): The fuzz value to use.
        timeout (int): Timeout for requests in seconds.
        user_agent (str): Custom User-Agent header.
        data (str, optional): Optional data to send with the request (e.g., POST data). Defaults to None.
        method (str, optional): HTTP method to use (GET or POST). Defaults to 'GET'.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # Add or modify the parameter with the fuzz value
        query_params[param] = [fuzz_value]

        # Reconstruct the URL with the modified query parameters
        new_query_string = urllib.parse.urlencode(query_params, doseq=True)
        tampered_url = parsed_url._replace(query=new_query_string).geturl()

        headers = {'User-Agent': user_agent}

        if method == 'GET':
            response = requests.get(tampered_url, headers=headers, timeout=timeout, verify=False) # Disable SSL verification for testing
        elif method == 'POST':
            # If data is provided, use it. Otherwise, send the tampered parameters as POST data.
            post_data = data if data else query_params
            response = requests.post(url, headers=headers, data=post_data, timeout=timeout, verify=False)  # Disable SSL verification for testing
        else:
            logging.error(f"Invalid HTTP method: {method}")
            return

        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        logging.info(f"URL: {tampered_url}, Status Code: {response.status_code}")

        # Analyze the response for potential vulnerabilities (e.g., error messages, unexpected content)
        if response.status_code == 500:
            logging.warning(f"Possible server error with fuzz value '{fuzz_value}' for parameter '{param}'.")
        elif response.status_code == 400:
            logging.info(f"Bad Request (400) with fuzz value '{fuzz_value}' for parameter '{param}'.  Possible input validation.")
        elif fuzz_value in response.text:
            logging.warning(f"Fuzz value '{fuzz_value}' reflected in the response.  Possible XSS vulnerability.") #XSS Detection
        elif 'SQL syntax' in response.text:
             logging.warning(f"Potential SQL injection vulnerability detected with fuzz value '{fuzz_value}' for parameter '{param}'.")

        # Example: Checking for sensitive information in the response
        if "password" in response.text.lower() or "secret" in response.text.lower():
            logging.warning(f"Possible exposure of sensitive information in response for parameter '{param}' with value '{fuzz_value}'.")

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

def main():
    """
    Main function to execute the parameter tampering detection.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    url = sanitize_url(args.url)

    logging.info(f"Starting parameter tampering scan on: {url}")

    for param in args.params:
        for fuzz_value in args.fuzz_values:
            logging.info(f"Testing parameter '{param}' with value '{fuzz_value}'")
            check_parameter_tampering(url, param, fuzz_value, args.timeout, args.user_agent, args.data, args.method)

    logging.info("Parameter tampering scan completed.")


if __name__ == "__main__":
    main()