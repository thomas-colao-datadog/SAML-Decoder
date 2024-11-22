import base64
import xml.etree.ElementTree as ET

def parseAttributes(decoded_path = 'assertions/decoded_assertion.xml'):
    tree = ET.parse(decoded_path)
    root = tree.getroot()
    attributes = []
    for Attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        attributeName = Attribute.attrib
        attributeValue = Attribute.find("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue").text
        attributes.append((attributeName, attributeValue))
    return attributes

def decode(encoded_path = 'assertions/encoded_assertion.txt', decoded_path = 'assertions/decoded_assertion.xml'):
    f = open(encoded_path, 'r')
    encoded_assertion = f.read()
    f.close()
    decoded_assertion = base64.b64decode(encoded_assertion).decode('utf-8')
    f = open(decoded_path, 'w')
    f.write(str(decoded_assertion))
    f.close()

decode()
attributes = parseAttributes()
for attribute in attributes:
    print(attribute)
