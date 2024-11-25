import base64
import xml.etree.ElementTree as ET
import re

class Assertion:
    def __init__(self, encoded_assertion):
        self.encoded_assertion = encoded_assertion
        self.decoded_assertion = self.decode()
        self.xml_root = ET.fromstring(self.decoded_assertion)
        self.identity_provider = self.parse_idp()
        if self.identity_provider == "Okta":
            self.attributes = self.parse_attributes("def:(.*?)'")
        if self.identity_provider == "Azure":
            self.attributes = self.parse_attributes("Name': '(.*?)'")
        pass

    def decode(self):
        return str(base64.b64decode(self.encoded_assertion).decode('utf-8'))
        
    
    def parse_attributes(self, regex):
        attributes = []
        for Attribute in self.xml_root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            attributeName = str(Attribute.attrib)
            attributeName = re.search(regex, attributeName)[1]
            attributeValue = Attribute.find("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue").text
            attributes.append((attributeName, attributeValue))
        return attributes
    
    def parse_idp(self):
        for issuer in self.xml_root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer'):
            idp = re.search("\\.(.*)\\.", issuer.text)[1]
            if idp == "okta":
                return "Okta"
            elif idp == "windows":
                return "Azure"
            else:
                return "N/A"

    
    def get_assertion(self):
        return self.decoded_assertion
    
    def __str__(self):
        output = ""
        if self.identity_provider == "N/A":
            output = "Error: Unable to decode SAML Assertion"
        else:
            output += "Identity Provider: " + self.identity_provider + "\n"
            output += "Attributes:"
            for i in range(0, len(self.attributes)):
                output += "\n" + str(self.attributes[i][0]) + ": "
                output += str(self.attributes[i][1])
        return output


## This is not working as expected. It appears that python's input() cannot read > 1024 characters
#  Current workaround is `echo ${encoded assertion} > assertion.txt`
#  May implement reading from stdin
def get_assertion():
    encoded_assertion_path = input("Enter the path to the encoded assertion\n")
    assertion = None
    if re.search("\\.", encoded_assertion_path) == None:
        assertion = encoded_assertion_path
    else:
        try:
            f = open(encoded_assertion_path)
            assertion = f.read()
            f.close()
        except:
            print("Error: Could not read file: " + encoded_assertion_path)
    return assertion
    
if __name__ == "__main__":
    encoded_assertion = None
    while encoded_assertion == None:
        encoded_assertion = get_assertion()

    assertion = Assertion(encoded_assertion)
    print()
    print(assertion)
