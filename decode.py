import base64
import xml.etree.ElementTree as ET
import re

class Assertion:
    def __init__(self, encoded_assertion):
        self.encoded_assertion = encoded_assertion
        self.decoded_assertion = self.decode()
        self.elements = self.parse_xml(ET.fromstring(self.decoded_assertion))
        pass

    def decode(self):
        return str(base64.b64decode(self.encoded_assertion).decode('utf-8'))
        
    def parse_xml(self, root):
        elements = []
        for element in root.iter():
            # elements.append((re.search("}(.*?)$", element.tag)[1], element.attrib, element.text))
            # print(re.search("}(.*?)$", element.tag)[1], re.search("'Name': '(.*?)'|attribute-def:(.*?)'", str(element.attrib)), element.text)
            print((self.clean_tag(element.tag), self.clean_attrib(element.attrib), self.clean_text(element.text)))
            elements.append((self.clean_tag(element.tag), self.clean_attrib(element.attrib), self.clean_text(element.text)))
        return elements
    
    def clean_tag(self, tag):
        return re.search("}(.*?)$", tag)[1]
    
    def clean_attrib(self, attrib):
        output = re.search("'Name': '(.*?)'|attribute-def:(.*?)'", str(attrib))
        if not output == None:
            return output[1]
    
    def clean_text(self, text):
        return text
    
    def parse_certificates(self):
        certificates = []
        # for element in self.xml_root.find('{http://www.w3.org/2000/09/xmldsig#}Signature'):
        #     print(element)
            # print(certificate.find('{http://www.w3.org/2000/09/xmldsig#}KeyInfo'))
        for element in self.xml_root.iter():
            if "X509Certificate" in re.search("}(.*?)$", element.tag)[1]:
                print(element.text)
        pass
    
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

    
    def get_assertion_xml(self):
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
    
