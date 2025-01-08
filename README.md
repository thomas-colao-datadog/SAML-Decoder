# SAML-Decoder
This is a tool to quickly parse the data out of a SAML assertion. Decoding and formatting the output contained in the logs for failed logins can be a tedious process, and the XML data is often too clunky and verbose to paste into a ticket. 

This script neatly outputs the relevant data from the assertion either into text that can be quickly copied, or to a file for local storage.

Another useful feature of this script is it's ability to parse the data from X509 certificates, which typically require an additional tool. This can be used to quickly diagnose a previously difficult to find issue, where the certificates in a user's SAML assertion were out of data, or otherwise invalid.

## Getting Started

### Installation
1. Clone the repo
```sh
git clone https://github.com/thomas-colao-datadog/SAML-Decoder.git
```
2. Install dependencies
```sh
pip install -r requirements.txt
```

## Usage
This tool requires that you have a base64 encoded SAML Assertion saved in a text file. If the assertion is copied to your clipboard, you can create the file with the following command
```sh
echo <ENCODED_ASSERTION> > assertion.txt
```

With the assertion properly formatted, the following command outputs the assertion contents to stdout
```sh
python decode -f <ASSERTION_FILE> 
```

You can also specify an output file for the assertion
```sh
python decode -f <ASSERTION_FILE> -o <OUTPUT_FILE>
```

The `-m` flag will output the assertion in markdown. This allows for quick copy-pasting from the command line into a compact, readable TL;DR
