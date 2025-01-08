import base64
import xml.etree.ElementTree as ET
import re
import sys
from cryptography import x509

class Element:
    def __init__(self, title, value):
        """An Element in a SAML Assertion

        Parameters:
        title -- name of the element
        value -- value of the element
        """
        self.title = title
        self.value = value

    def get_title(self):
        """Getter for title"""
        return self.title
    
    def get_value(self):
        """Getter for value"""
        return self.value
    
    def __str__(self):
        """Returns element as a string"""
        output = str(self.title) + ": " + str(self.value)
        return output
    
    def markdown(self):
        """Returns element as markdown"""
        output = "**" + str(self.title) + "** " + str(self.value)
        return output

class Certificate(Element):
    def __init__(self, title, value):
        """An X509 Cerfticate Element
        
        Parameters:
        title -- name of the element
        value -- the encoded certificate
        """
        super().__init__(title, value)
        self.details = self.expand_certificate() #the certificate's issuer, subject, and creation and expiration dates
    
    def expand_certificate(self):
        """Decodes certificate and extracts details"""
        delimiters = ["-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"]
        pem_file = delimiters[0] + self.value + delimiters[1]
        cert = x509.load_pem_x509_certificate(pem_file.encode())
        return [("Not Valid Before", cert.not_valid_before_utc), ("Not Valid After", cert.not_valid_after_utc)]

    def __str__(self):
        """Returns certificate as a string"""
        output = super().__str__()
        for d in self.details:
            output += "\n " + str(d[0]) + " " + str(d[1])
        return output
    
    def markdown(self):
        """Returns certificate as markdown"""
        output = "**" + self.title + "** \n"
        output += "```\n" + self.value + "\n```" 
        for d in self.details:
            output += "\n**" + str(d[0]) + "** "+ str(d[1])
        return output


class Attribute(Element):

    def __init__(self, title, attributes = []):
        super().__init__(title, attributes)

    def __str__(self):
        """Returns attribute as a string"""
        output = ""
        output += self.title + ": " + self.value[0]
        for a in self.value[1]:
            output += "\n " + str(a)    
        return output
    
    def markdown(self):
        """Returns attribute as markdown"""
        output = ""
        output += "**" + self.title + "** " + self.value[0]
        output += "\n```\n"
        for a in self.value[1]:
            output += str(a)
        output += "\n```"
        return output

class Assertion:
    def __init__(self, encoded_assertion):
        """A SAML Assertion
        
        Parameters:
        encoded_assertion -- base64 encoded SAML assertion
        """
        self.decoded_assertion = self.decode(encoded_assertion)
        self.elements = self.build_elements()

    def decode(self, encoded_assertion):
        """Decode assertion to utf-8

        Parameters:
        encoded_assertion -- based64 encoded SAML assertion
        """
        decoded = str(base64.b64decode(encoded_assertion).decode('utf-8'))
        return decoded
        
    def parse_xml(self):
        """Parse XML from decoded assertion"""
        root = ET.fromstring(self.decoded_assertion)
        raw_elements = []
        for e in root.iter():
            raw_elements.append((self.clean_tag(e.tag), self.clean_attrib(e.attrib), self.clean_text(e.text)))
        return raw_elements
    
    def build_elements(self):
        """Create list of elements from XML tree"""
        raw_elements = self.parse_xml()
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
        """Isolate element name
        
        Parameters:
        tag -- an element's name
        """
        return re.search("}(.*?)$", tag)[1]
    
    def clean_attrib(self, attrib):
        """Isolate element attributes
        
        Parameters:
        attrib -- a dictionary of an element's attributes
        """
        output = re.search("'Name': '(.*?)'|attribute-def:(.*?)\'", str(attrib))
        if not output == None:
            return output[1]
    
    def clean_text(self, text):
        """Isolate element text
        
        Parameters:
        text -- text before first subelement
        """
        return text

    def get_assertion_xml(self):
        """Getter for assertion"""
        return self.decoded_assertion
    
    def get_elements(self):
        """"Getter for elements"""
        return self.elements
    
    def __str__(self):
        """Returns assertion as a string"""
        output = ""
        for e in self.elements:
            output += str(e) + "\n"
        return output
    
    def markdown(self):
        """Returns assertion as markdown"""
        output = "## Assertion\n"
        for e in self.elements:
            output += e.markdown() + "\n"
        return output


def read_flags():
    """Parses command line arguments
    
    -f -- input file
    -o -- output file
    -m -- markdown
    """
    flags = ["f", "o", "m"]
    output = {"-f":None, "-o":None, "-m":False}
    if len(sys.argv) > 1:
        args = sys.argv[1:]
        for i in range (0, len(args)):
            match args[i]:
                case "-f":
                    output["-f"] = args[i + 1]
                    i += 1
                case "-o":
                    output["-o"] = args[i + 1]
                    i += 1
                case "-m":
                    output["-m"] = True
    return output

def handle_error(err):
    print(f'Unexpected Error {err}')
    sys.exit()

if __name__ == "__main__":
    """
    Reads assertion from file and prints to stdout or specified output file
    """
    flags = read_flags()
    try:
        f = open(flags["-f"], 'r')
        assertion = Assertion(f.read())
        f.close()
    except Exception as err:
        handle_error(err)
    assetion_output = ""
    if flags["-m"]:
        assertion_output = assertion.markdown()
    else:
        assertion_output = str(assertion)
    try:
        if not flags["-o"] == None:
            f = open(flags["-o"], 'w')
            f.write(assertion_output)
            f.close()
        else:
            print(assertion_output)
    except Exception as err:
            handle_error(err)
    
