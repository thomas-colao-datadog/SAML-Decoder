import base64
import xml.etree.ElementTree as ET
import re
import sys
from cryptography import x509

class Element:
    def __init__(self, title, value):
        self.title = title
        self.value = value

    def get_title(self):
        return self.title
    
    def get_value(self):
        return self.value
    
    def __str__(self):
        output = str(self.title) + ": " + str(self.value)
        return output
    
class Certificate(Element):
    def __init__(self, title, value):
        super().__init__(title, value)
        self.details = self.expand_certificate()
    
    def expand_certificate(self):
        delimiters = ["-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"]
        pem_file = delimiters[0] + self.value + delimiters[1]
        cert = x509.load_pem_x509_certificate(pem_file.encode())
        return [("Issuer: ", cert.issuer),  ("Subject: ", cert.subject), ("Not Valid Before: ", cert.not_valid_before_utc), ("Not Valid After: ", cert.not_valid_after_utc)]

    def __str__(self):
        output = super().__str__()
        for d in self.details:
            output += "\n " + str(d[0]) + str(d[1])
        return output

class Attribute(Element):
    def __init__(self, title, attributes = []):
        super().__init__(title, attributes)
        self.attributes = attributes

    def __str__(self):
        output = ""
        output += self.title + ": " + self.value[0]
        for a in self.value[1]:
            output += "\n " + str(a)    
        return output

class Assertion:
    def __init__(self, encoded_assertion):
        self.decoded_assertion = self.decode(encoded_assertion)
        self.elements = self.build_elements(self.parse_xml(ET.fromstring(self.decoded_assertion)))

    def decode(self, encoded_assertion):
        return str(base64.b64decode(encoded_assertion).decode('utf-8'))
        
    def parse_xml(self, root):
        raw_elements = []
        for e in root.iter():
            raw_elements.append((self.clean_tag(e.tag), self.clean_attrib(e.attrib), self.clean_text(e.text)))
        return raw_elements
    
    def build_elements(self, raw_elements):
        element_list = []
        for i in range(0, len(raw_elements)):
            match raw_elements[i][0]:
                case "Attribute":
                    attribute = Attribute(raw_elements[i][0])
                    attributes = [raw_elements[i][1]]
                    temp = []
                    for j in range (i+1, len(raw_elements)):
                        if raw_elements[j][0] == "AttributeValue":
                            temp.append(raw_elements[j][2])
                        else: break
                    attributes.append(temp)
                    attribute.value = attributes
                    element_list.append(attribute)
                case "AttributeValue":
                    pass
                case "X509Certificate":
                    element_list.append(Certificate(raw_elements[i][0], raw_elements[i][2])) 
                case _:
                    if not raw_elements[i][2] == None:
                        element_list.append(Element(raw_elements[i][0], raw_elements[i][2]))
        return element_list

    
    def clean_tag(self, tag):
        return re.search("}(.*?)$", tag)[1]
    
    def clean_attrib(self, attrib):
        output = re.search("'Name': '(.*?)'|attribute-def:(.*?)\'", str(attrib))
        if not output == None:
            return output[1]
    
    def clean_text(self, text):
        return text

    def get_assertion_xml(self):
        return self.decoded_assertion
    
    def get_elements(self):
        return self.elements
    
    def __str__(self):
        output = ""
        for e in self.elements:
            output += str(e) + "\n"
        return output

def get_assertion():
    if len(sys.argv) < 2:
        encoded_assertion_path = input("Enter the path to the encoded assertion\n")
    else:
        encoded_assertion_path = str(sys.argv[1])
    assertion = None
    try:
        f = open(encoded_assertion_path)
        assertion = f.read()
        f.close()
    except:
        print("Error: Could not read file: " + encoded_assertion_path)
    return assertion
    
if __name__ == "__main__":
    """
    Loops until user enters a valid assertion file
    """
    encoded_assertion = None
    while encoded_assertion == None:
        encoded_assertion = get_assertion()
    assertion = Assertion(encoded_assertion)
    print(assertion)
    
