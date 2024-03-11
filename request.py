import base64
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

# Function to generate the SAML authentication request
def generate_authn_request(entity_id, acs_url):
    authn_request = ET.Element('{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest', {
        'AssertionConsumerServiceURL': acs_url,
        'Destination': 'http://127.0.0.1:5000//user/saml/login',
        'ID': '_{}'.format(base64.b64encode(entity_id.encode()).decode()),
        'IssueInstant': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        'Version': '2.0'
    })
    return ET.tostring(authn_request, encoding='utf-8', method='xml')