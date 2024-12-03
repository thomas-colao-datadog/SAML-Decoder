import base64
import xml.etree.ElementTree as ET
import re

class Assertion:
    return_attributes = ["Issuer", "X509Certificate", "NameID", "Audience"]
    def __init__(self, encoded_assertion):
        self.decoded_assertion = self.decode(encoded_assertion)
        self.elements = {}
        self.raw_elements = self.parse_xml(ET.fromstring(self.decoded_assertion))

    def decode(self, encoded_assertion):
        return str(base64.b64decode(encoded_assertion).decode('utf-8'))
        
    def parse_xml(self, root):
        elements = []
        for element in root.iter():
            elements.append((self.clean_tag(element.tag), self.clean_attrib(element.attrib), self.clean_text(element.text)))
        attribute_statement = [a for a in elements if a[0] == "Attribute" or a[0] == "AttributeValue"]
        attributes = []
        for i in range(0, len(attribute_statement)):
            if attribute_statement[i][0] == "Attribute":
                attribute_name = attribute_statement[i][1]
                attribute_value = []
                for j in range(i+1, len(attribute_statement)):
                    if attribute_statement[j][0] == "AttributeValue":
                        attribute_value.append(attribute_statement[j][2])
                    else:
                        break
                attributes.append((attribute_name, attribute_value))
        elements = [e for e in elements if e[0] in self.return_attributes]
        for e in elements:
            self.elements.update({e[0]:e[2]})
        self.elements.update({"Attributes":attributes})
        return elements
    
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
    
    def get_elements(self):
        return self.elements
    
    def __str__(self):
        output = ""
        output += "Issuer:\n " + self.elements["Issuer"] + "\n"
        output += "Audience:\n " + self.elements["Audience"] + "\n"
        output += "Certificates\n " + self.elements["X509Certificate"] + "\n"
        output += "NameID:\n " + self.elements["NameID"] + "\n"
        output += "Attributes:\n"
        for attribute in self.elements["Attributes"]:
            output += attribute[0] + ":\n"
            for value in attribute[1]:
                output += " " + value + "\n"
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

def menu(assertion: Assertion):
    menu = "1. All Elements\n2. Issuer\n3. Audience\n4. Certificates\n5. NameID \n6. Attributes\n"
    selection = input("Select an option\n" + menu)
    elements = assertion.get_elements()
    for i in range(0, len(selection)):
        match selection[i]:
            case "1":
                print(assertion)
            case "2":
                print("Issuer:\n", elements["Issuer"])
            case "3":
                print("Audience:\n", elements["Audience"])
            case "4":
                print("Certificates\n", elements["X509Certificate"])
            case "5":
                print("NameID:\n", elements["NameID"])
            case "6":
                print("Attributes:")
                for attribute in elements["Attributes"]:
                    print(attribute[0] + ":")
                    for value in attribute[1]:
                        print(" " + value)
    
if __name__ == "__main__":
    """
    Loops until user enters a valid assertion file
    """
    encoded_assertion = None
    while encoded_assertion == None:
        encoded_assertion = get_assertion()
    assertion = Assertion(encoded_assertion)
    menu(assertion)
    
