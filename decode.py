import base64
import xml.etree.ElementTree as ET
import re

class Assertion:
    def __init__(self, encoded_assertion):
        # Assertion Metadata
        self.decoded_assertion = self.decode(encoded_assertion)
        self.elements = self.parse_xml(ET.fromstring(self.decoded_assertion))

    def decode(self, encoded_assertion):
        return str(base64.b64decode(encoded_assertion).decode('utf-8'))
        
    def parse_xml(self, root):
        elements = []
        for element in root.iter():
            # print((self.clean_tag(element.tag), self.clean_attrib(element.attrib), self.clean_text(element.text)))
            elements.append((self.clean_tag(element.tag), self.clean_attrib(element.attrib), self.clean_text(element.text)))
        return elements
    
    def parse_attributes(self):
        pass
    
    def clean_tag(self, tag):
        return re.search("}(.*?)$", tag)[1]
    
    def clean_attrib(self, attrib):
        output = re.search("'Name': '(.*?)'|attribute-def:(.*?)'", str(attrib))
        if not output == None:
            return output[1]
    
    def clean_text(self, text):
        return text

    def get_assertion_xml(self):
        return self.decoded_assertion
    
    def __str__(self):
        output = ""
        for element in self.elements:
            output += str(element) + "\n"
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
    print(assertion)
    
