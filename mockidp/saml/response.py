# coding: utf-8
import base64
import time
import datetime
import pkg_resources

from jinja2 import Environment, PackageLoader, select_autoescape
from lxml import etree
from signxml import XMLSigner
import xmlsec
from mockidp.core.config import get_service_provider

env = Environment(
    loader=PackageLoader("mockidp", "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)


def saml_timestamp(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch))


env.filters["timestamp"] = saml_timestamp


def read_bytes(path):
    filename = pkg_resources.resource_filename("mockidp", path)
    return open(filename, "rb").read()


def encrypt_node(root, node):
    enc_data = xmlsec.template.encrypted_data_create(
        root,
        xmlsec.constants.TransformAes128Cbc,
        type=xmlsec.constants.TypeEncElement,
        ns="xenc",
    )
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
    key_info = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns="dsig")
    enc_key = xmlsec.template.add_encrypted_key(
        key_info, xmlsec.constants.TransformRsaOaep
    )
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)

    encryption_key = xmlsec.Key.generate(
        xmlsec.constants.KeyDataAes, 256, xmlsec.constants.KeyDataTypeSymmetric
    )
    manager = xmlsec.KeysManager()
    key = xmlsec.Key.from_file(
        pkg_resources.resource_filename("mockidp", "keys/cert.pem"),
        xmlsec.constants.KeyDataFormatCertPem,
        None,
    )
    manager.add_key(key)
    enc_ctx = xmlsec.EncryptionContext(manager)
    enc_ctx.key = encryption_key
    return enc_ctx.encrypt_xml(enc_data, node)


def sign_and_encrypt_assertion(response_str):
    # Sign the assertions
    response_element = etree.fromstring(response_str)

    assertion_node = response_element.find(
        ".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion"
    )

    signer = XMLSigner(
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
    )
    signed_e = signer.sign(
        assertion_node, key=read_bytes("keys/key.pem"), cert=read_bytes("keys/cert.pem")
    )

    enc_data = encrypt_node(response_element, signed_e)

    # Replace the original Assertion node with the encrypted one
    assertion_node.getparent().replace(assertion_node, enc_data)

    # Serialize the modified XML document
    signed_and_encrypted_response = etree.tostring(response_element, pretty_print=True)

    return signed_and_encrypted_response


def create_auth_response(config, session):
    service_provider = get_service_provider(config, session.sp_entity_id)
    url = service_provider["response_url"]

    rendered_response = render_response(session, session.user, url)
    signed_response = sign_and_encrypt_assertion(rendered_response)
    encoded_response = base64.b64encode(signed_response).decode("utf-8")

    return url, encoded_response


def render_response(session, user, recipient):
    template = env.get_template("saml_response.xml")
    issue_instant = get_issue_instant(session)
    params = dict(
        issue_instant=issue_instant,
        session=session,
        user=user,
        recipient=recipient,
    )
    response = template.render(params)

    return response


def create_logout_response(config, session):
    rendered_response = render_logout_response(config, session.user, session)

    signed_response = sign_and_encrypt_assertion(rendered_response)

    encoded_response = base64.b64encode(signed_response).decode("utf-8")

    service_provider = get_service_provider(config, session.sp_entity_id)
    url = service_provider["logout_url"]
    return url, encoded_response


def render_logout_response(config, user, session):
    template = env.get_template("saml/logout_response.xml")
    issue_instant = get_issue_instant(session)
    params = dict(
        config=config, issue_instant=issue_instant, session=session, user=user
    )
    response = template.render(params)
    return response


def get_issue_instant(session):
    # Convert session.created to a datetime object and replace the timezone with UTC
    created_datetime = datetime.datetime.fromtimestamp(
        session.created, tz=datetime.timezone.utc
    )

    # Format the datetime object as the specified string format
    issue_instant = created_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")

    return issue_instant
