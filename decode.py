import base64
import xml.etree.ElementTree as ET
import re
import io

class Assertion:
    def __init__(self, encoded_assertion_path):
        self.encoded_assertion_path = encoded_assertion_path
        self.decoded_assertion = self.decode()
        self.xml_root = ET.fromstring(self.decoded_assertion)
        self.identity_provider = self.parse_idp()
        self.attributes = self.parse_attributes()
        pass

    def decode(self):
        f = open(self.encoded_assertion_path, 'r')
        encoded_assertion = f.read()
        f.close()
        return str(base64.b64decode(encoded_assertion).decode('utf-8'))
        
    
    def parse_attributes(self):
        attributes = []
        for Attribute in self.xml_root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            attributeName = str(Attribute.attrib)
            attributeName = re.search("def:(.*?)'", attributeName)[1]
            attributeValue = Attribute.find("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue").text
            attributes.append((attributeName, attributeValue))
        return attributes
    
    def parse_idp(self):
        for issuer in self.xml_root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer'):
            idp = re.search("www.(.*).com", issuer.text)[1]
            if idp != None:
                return idp

    
    def get_assertion(self):
        return self.decoded_assertion
    
    def __str__(self):
        output = ""
        output += "Identity Provider: " + self.identity_provider + "\n"
        output += "Attributes:"
        for i in range(0, len(self.attributes)):
            output += "\n" + str(self.attributes[i][0]) + ": "
            output += str(self.attributes[i][1])
        return output
    
if __name__ == "__main__":
    encoded_assertion_path = input("Enter the path to the encoded assertion " + 
                                   "(Default: \"encoded_assertion.txt\"\n")
    if encoded_assertion_path == "":
        encoded_assertion_path = "encoded_assertion.txt"
    assertion = Assertion(encoded_assertion_path)
    print()
    print(assertion)