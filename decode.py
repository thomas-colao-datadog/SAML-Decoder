import base64
import xml.etree.ElementTree as ET
import re
import sys

class Element:
    def __init__(self, title, value):
        self.title = title
        self.value = value
        self.expand_certificate()

    def get_title(self):
        return self.title
    
    def get_value(self):
        return self.value
    
    def expand_certificate(self):
        if not self.title == "X509Certificate":
            return
        else:
            pass
    
    def __str__(self):
        output = ""
        if type(self.value) == str:
            output = str(self.title) + ": " + str(self.value)
        elif type(self.value) == list:
            output += "Attribute: " + self.title
            for value in self.value:
                output += "\n " + value
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
        for e in raw_elements:
            if not e[0] == "Attribute" and not e[0] == "AttributeValue":
                element_list.append(Element(e[0], e[2]))
        
        for i in range(0, len(raw_elements)):
            if raw_elements[i][0] == "Attribute":
                attribute_name = raw_elements[i][1]
                attribute_value = []
                for j in range(i+1, len(raw_elements)):
                    if raw_elements[j][0] == "AttributeValue":
                        attribute_value.append(raw_elements[j][2])
                    else:
                        break
                element_list.append(Element(attribute_name, attribute_value))
        element_list = [e for e in element_list if not e.get_value() == None]
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


## This is not working as expected. It appears that python's input() cannot read > 1024 characters
#  Current workaround is `echo ${encoded assertion} > assertion.txt`
#  May implement reading from stdin
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
    
