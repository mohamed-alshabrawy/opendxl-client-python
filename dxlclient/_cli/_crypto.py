# -*- coding: utf-8 -*-
###############################################################################
# Copyright (c) 2026 Trellix - All Rights Reserved.
###############################################################################

"""
Helpers for crypto operations used by the cli tools - e.g., for creating
certificate requests and private keys.

Migrated from ``oscrypto``/``asn1crypto`` to the actively-maintained
``cryptography`` package (oscrypto is unmaintained and breaks on OpenSSL 3.x).
The public API of this module is unchanged.
"""

from __future__ import absolute_import
import logging

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from dxlclient import DxlUtils

logger = logging.getLogger(__name__)


def _bytes_to_unicode(obj):
    """
    Convert a `bytes` type object into a unicode string.

    :param obj: the object to convert
    :return: If the supplied `obj` is of type `bytes`, decode it into a unicode
        string. If the `obj` is anything else (including None), the original
        `obj` is returned.
    """
    return obj.decode() if isinstance(obj, bytes) else obj


def _unicode_to_bytes(obj):
    """
    Convert a unicode string into a `bytes` object.

    :param obj: the object to convert
    :return: If the supplied `obj` is a unicode string, encode it into `bytes`.
        If the `obj` is anything else (including None), the original `obj` is
        returned.
    """
    return obj.encode() if isinstance(obj, str) else obj


class X509Name(object):
    """
    Holder for an X.509 distinguished name, e.g., /C=US/CN=myname.
    """
    def __init__(self, common_name):
        """
        Constructor parameters:

        :param str common_name: Common Name (CN) attribute
        """
        self._common_name = common_name
        self._country_name = None
        self._state_or_province_name = None
        self._locality_name = None
        self._organization_name = None
        self._organizational_unit_name = None
        self._email_address = None

    @property
    def common_name(self):
        """
        Common Name (CN) attribute

        :rtype: str
        """
        return self._common_name

    @property
    def country_name(self):
        """
        Country (C) attribute

        :rtype: str
        """
        return self._country_name

    @country_name.setter
    def country_name(self, value):
        """
        Country (C) attribute to set

        :param str value: new name
        """
        self._country_name = value

    @property
    def state_or_province_name(self):
        """
        State or Province (ST) attribute

        :rtype: str
        """
        return self._state_or_province_name

    @state_or_province_name.setter
    def state_or_province_name(self, value):
        """
        State or Province (ST) attribute to set

        :param str value: new name
        """
        self._state_or_province_name = value

    @property
    def locality_name(self):
        """
        Locality (C) attribute

        :rtype: str
        """
        return self._locality_name

    @locality_name.setter
    def locality_name(self, value):
        """
        Locality (L) attribute to set

        :param str value: new name
        """
        self._locality_name = value

    @property
    def organization_name(self):
        """
        Organization (O) attribute

        :rtype: str
        """
        return self._organization_name

    @organization_name.setter
    def organization_name(self, value):
        """
         Organization (O) attribute to set

         :param str value: new name
         """
        self._organization_name = value

    @property
    def organizational_unit_name(self):
        """
        Organizational Unit (OU) attribute

        :rtype: str
        """
        return self._organizational_unit_name

    @organizational_unit_name.setter
    def organizational_unit_name(self, value):
        """
         Organizational Unit (OU) attribute to set

         :param str value: new name
         """
        self._organizational_unit_name = value

    @property
    def email_address(self):
        """
        e-mail address attribute

        :rtype: str
        """
        return self._email_address

    @email_address.setter
    def email_address(self, value):
        """
         e-mail address attribute to set

         :param str value: new name
         """
        self._email_address = value


_CRYPTO_KEY_PUBLIC_EXPONENT = 65537
_CRYPTO_KEY_BITS = 2048

# Maps X509Name attribute names to the corresponding cryptography NameOID.
# Order is significant: it defines the order of RDNs in the built subject and
# matches the ordering previously produced by asn1crypto.
_SUBJECT_OID_MAP = [
    (u"common_name", NameOID.COMMON_NAME),
    (u"country_name", NameOID.COUNTRY_NAME),
    (u"state_or_province_name", NameOID.STATE_OR_PROVINCE_NAME),
    (u"locality_name", NameOID.LOCALITY_NAME),
    (u"organization_name", NameOID.ORGANIZATION_NAME),
    (u"organizational_unit_name", NameOID.ORGANIZATIONAL_UNIT_NAME),
    (u"email_address", NameOID.EMAIL_ADDRESS),
]


class _KeyPair(object):
    """
    RSA public / private key pair generator
    """
    def __init__(self):
        self._private_key = rsa.generate_private_key(
            public_exponent=_CRYPTO_KEY_PUBLIC_EXPONENT,
            key_size=_CRYPTO_KEY_BITS
        )
        self._public_key = self._private_key.public_key()

    @property
    def private_key(self):
        """
        The private key

        :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
        """
        return self._private_key

    @property
    def public_key(self):
        """
        The public key

        :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey
        """
        return self._public_key

    def private_key_as_pem(self, passphrase=None):
        """
        Return the private key as a PEM-encoded (PKCS#8) byte string.

        :param passphrase: If a `str` (or `bytes`) object is supplied, encrypt
            the private key with the passphrase before converting it to PEM
            format. If `None` is supplied, convert it to PEM format without
            performing any encryption.
        :return: private key in PEM format
        :rtype: bytes
        """
        if passphrase:
            encryption = serialization.BestAvailableEncryption(
                _unicode_to_bytes(passphrase))
        else:
            encryption = serialization.NoEncryption()
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )


class _CertificateRequest(object):
    """
    Certificate request generator
    """
    def __init__(self, subject, key_pair, sans=None):
        """
        Constructor parameters:

        :param X509Name subject: subject to add to the certificate request
        :param _KeyPair key_pair: key pair containing the private key used to
            sign the certificate request and the public key embedded in it
        :param sans: collection of dns names to insert into a subjAltName
            extension for the certificate request
        :type sans: list(str) or tuple(str) or set(str)
        """
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            self._build_subject(subject))

        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=False)
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False)

        if sans:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(_bytes_to_unicode(san)) for san in sans]),
                critical=False)

        self._req = builder.sign(key_pair.private_key, hashes.SHA256())

    @staticmethod
    def _build_subject(subject):
        """
        Convert the supplied :class:`X509Name` into a
        :class:`cryptography.x509.Name`.

        :param X509Name subject: subject to convert
        :return: the built X.509 name
        :rtype: cryptography.x509.Name
        """
        attributes = []
        for attribute_name, oid in _SUBJECT_OID_MAP:
            value = getattr(subject, attribute_name)
            if value is not None:
                attributes.append(
                    x509.NameAttribute(oid, _bytes_to_unicode(value)))
        return x509.Name(attributes)

    def dump_to_pem(self):
        """
        Dump the certificate request to a PEM-encoded byte string

        :return: the certificate request PEM
        :rtype: bytes
        """
        return self._req.public_bytes(serialization.Encoding.PEM)


class CsrAndPrivateKeyGenerator(object):
    """
    Certificate request and private key generator
    """
    def __init__(self, subject, sans=None):
        """
        Constructor parameters:

        :param X509Name subject: subject to add to the certificate request
        :param sans: collection of dns names to insert into a subjAltName
            extension for the certificate request
        :type sans: list(str) or tuple(str) or set(str)
        """
        self._key_pair = _KeyPair()
        self._csr = _CertificateRequest(subject, self._key_pair, sans)

    def save_csr_and_private_key(self, csr_filename, private_key_filename,
                                 passphrase=None):
        """
        Save the certificate request and private key to disk in PEM format

        :param csr_filename: filename of the certificate request
        :param private_key_filename: filename of the private key
        :param passphrase: If a `str` object is supplied, encrypt the private
            key with the passphrase before converting it to PEM format. If
            `None` is supplied, convert it to PEM format without performing any
            encryption.
        """
        logger.info("Saving csr file to %s", csr_filename)
        DxlUtils.save_to_file(csr_filename, self._csr.dump_to_pem())
        logger.info("Saving private key file to %s", private_key_filename)
        DxlUtils.save_to_file(private_key_filename,
                              self._key_pair.private_key_as_pem(passphrase),
                              0o600)

    @property
    def csr(self):
        """
        Return the certificate request as a PEM-encoded byte string

        :return: the PEM-encoded certificate request
        :rtype: bytes
        """
        return self._csr.dump_to_pem()


def validate_cert_pem(pem_text, message_on_exception=None):
    """
    Validate that the supplied `pem_text` string contains a PEM-encoded
    certificate

    :param str pem_text: text to validate as a PEM-encoded certificate
    :param str message_on_exception: extra text to add into an exception if
        a validation failure occurs
    :raise Exception: if the `pem_text` does not represent a valid PEM-encoded
        certificate
    """
    try:
        pem_bytes = pem_text if isinstance(pem_text, bytes) \
            else pem_text.encode()
        # load_pem_x509_certificate parses and validates the DER structure of
        # the certificate; it raises ValueError if the PEM does not contain a
        # valid certificate (e.g. a CSR or key was supplied instead).
        x509.load_pem_x509_certificate(pem_bytes)
    except Exception as ex:
        logger.error("%s. Reason: %s",
                     message_on_exception or
                     "Failed to validate certificate PEM",
                     ex)
        logger.debug("Certificate PEM: %s", pem_text)
        raise
