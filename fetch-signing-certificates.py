#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import os
import sys
import argparse
from datetime import datetime
import requests
import base64
import cbor2
from cose.messages import CoseMessage, Sign1Message
from cose.keys import cosekey, keyops, keyparam, curves, keytype
from cose import algorithms, headers
from cryptography import x509
from cryptography import hazmat
from cryptojwt import (jwk as cjwtk, jws as cjws)

import logging

log = logging.getLogger(__name__)

DEFAULT_CERTS_DIR = "certs"
TRUST_LIST_COUNTRY_AUSTRIA = "Austria"
TRUST_LIST_COUNTRY_SWEDEN = "Sweden"
TRUST_LIST_COUNTRIES = (TRUST_LIST_COUNTRY_AUSTRIA, TRUST_LIST_COUNTRY_SWEDEN)

# Austrian govt official endpoints:
TRUST_LIST_AUSTRIA_URL = "https://dgc-trust.qr.gv.at/trustlist"
TRUST_LIST_AUSTRIA_SHA2_HASH_URL = "https://dgc-trust.qr.gv.at/trustlistsig"
# Trust list production signing certificate source:
# https://github.com/Federal-Ministry-of-Health-AT/green-pass-overview/
# Note: There HAS to be more "official" soure than GitHub for this!!
# Cert's expiry is at Jul 2 13:46:21 2022 GMT and having this hard-coded is stupid!
TRUST_LIST_AUSTRIA_ROOT_CERT = """
-----BEGIN CERTIFICATE-----
MIIB1DCCAXmgAwIBAgIKAXnM+Z3eG2QgVzAKBggqhkjOPQQDAjBEMQswCQYDVQQG
EwJBVDEPMA0GA1UECgwGQk1TR1BLMQwwCgYDVQQFEwMwMDExFjAUBgNVBAMMDUFU
IERHQyBDU0NBIDEwHhcNMjEwNjAyMTM0NjIxWhcNMjIwNzAyMTM0NjIxWjBFMQsw
CQYDVQQGEwJBVDEPMA0GA1UECgwGQk1TR1BLMQ8wDQYDVQQFEwYwMDEwMDExFDAS
BgNVBAMMC0FUIERHQyBUTCAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEl2tm
d16CBHXwcBN0r1Uy+CmNW/b2V0BNP85y5N3JZeo/8l9ey/jIe5mol9fFcGTk9bCk
8zphVo0SreHa5aWrQKNSMFAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBRTwp6d
cDGcPUB6IwdDja/a3ncM0TAfBgNVHSMEGDAWgBQfIqwcZRYptMGYs2Nvv90Jnbt7
ezAKBggqhkjOPQQDAgNJADBGAiEAlR0x3CRuQV/zwHTd2R9WNqZMabXv5XqwHt72
qtgnjRgCIQCZHIHbCvlgg5uL8ZJQzAxLavqF2w6uUxYVrvYDj2Cqjw==
-----END CERTIFICATE-----
"""
# Austrian mobile app endpoints:
API_ENDPOINT_AUSTRIA = "https://greencheck.gv.at/api/masterdata"
API_ENDPOINT_AUSTRIA_V2 = "https://greencheck.gv.at/api/v2/masterdata"
API_AUSTRIA_V2_CLIENT_VERSION = "1.12"


# Swedish govt official endpoints:
TRUST_LIST_SWEDEN_URL = "https://dgcg.covidbevis.se/tp/trust-list"
TRUST_LIST_SWEDEN_SIG_URL = "https://dgcg.covidbevis.se/tp/cert"


def _setup_logger() -> None:
    log_formatter = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s")
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(log_formatter)
    console_handler.propagate = False
    logging.getLogger().addHandler(console_handler)
    # log.setLevel(logging.DEBUG)
    log.setLevel(logging.INFO)


def fetch_certificates(country_to_use: str, destination_dir: str) -> dict:
    if country_to_use == TRUST_LIST_COUNTRY_AUSTRIA:
        return fetch_certificates_austria_api(destination_dir)
    elif country_to_use == TRUST_LIST_COUNTRY_SWEDEN:
        return fetch_certificates_sweden_api(destination_dir)

    raise ValueError("Don't know what to do with country {0}!".format(country_to_use))


def _cert_to_cose_key(cert: x509.Certificate) -> cosekey.CoseKey:
    public_key = cert.public_key()
    key_dict = None

    if isinstance(public_key, hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name
        matching_curve = None
        for name in dir(curves):
            if name.startswith('_'):
                continue
            if curve_name.lower() == name.lower():
                if name == 'SECP256R1':
                    matching_curve = curves.P256
                elif name == 'SECP384R1':
                    matching_curve = curves.P384
                else:
                    raise RuntimeError("Unknown curve {}!".format(curve_name))
                break

        if not matching_curve:
            raise RuntimeError("Could not find curve {} used in X.509 certificate from COSE!".format(curve_name))

        public_numbers = public_key.public_numbers()
        size_bytes = public_key.curve.key_size // 8
        x = public_numbers.x.to_bytes(size_bytes, byteorder="big")
        y = public_numbers.y.to_bytes(size_bytes, byteorder="big")
        key_dict = {
            keyparam.KpKeyOps: [keyops.VerifyOp],
            keyparam.KpKty: keytype.KtyEC2,
            keyparam.EC2KpCurve: matching_curve,
            keyparam.KpAlg: algorithms.Es256,
            keyparam.EC2KpX: x,
            keyparam.EC2KpY: y,
        }
    else:
        raise RuntimeError("Cannot handle RSA-keys!")

    key = cosekey.CoseKey.from_dict(key_dict)

    return key


def _save_certs(cert_list: list, destination_dir: str) -> dict:
    certs_out = {}
    for cert_item in cert_list:
        key_id = cert_item["i"]
        if "c" in cert_item:
            cert_der_data = cert_item["c"]
            cert = x509.load_der_x509_certificate(cert_der_data)
        else:
            raise NotImplemented("Cannot construct X.509 certificate from parts!")

        if key_id in certs_out:
            log.warning("Duplicate certificate with key ID{}!".format(key_id.hex()))

        certs_out[key_id] = cert

    # Make sure destination directory exists
    if os.path.exists(destination_dir):
        if not os.path.isdir(destination_dir):
            raise ValueError("Cannot save into {}. Is not a directory!".format(destination_dir))
    else:
        os.mkdir(destination_dir)

    # Save
    old_mask = os.umask(0o022)
    for key_id in certs_out:
        key_id_str = key_id.hex()
        log.info("Writing certificate with key ID {}".format(key_id_str))
        cert = certs_out[key_id]
        cert_pem = cert.public_bytes(hazmat.primitives.serialization.Encoding.PEM)
        filename = "{}/{}.pem".format(destination_dir, key_id_str)
        with open(filename, 'wb') as binary_file:
            binary_file.write(cert_pem)

    os.umask(old_mask)
    log.info("Done saving certificates. Did {} of them.".format(len(certs_out)))

    return certs_out


def fetch_certificates_austria_api_old(destination_dir: str) -> dict:
    log.debug("Get trust list from Austria API endpoint: {}".format(API_ENDPOINT_AUSTRIA_V2))
    request_headers = {
        'x-app-version': API_AUSTRIA_V2_CLIENT_VERSION,
        'x-app-type': 'browser',
        'Accept': 'application/json'
    }
    response = requests.get(API_ENDPOINT_AUSTRIA_V2, timeout=5.0, headers=request_headers)
    response.raise_for_status()

    json_data = response.json()
    epoc_utc_str = json_data['epochUTC']
    epoc_utc = datetime.utcfromtimestamp(epoc_utc_str // 1000)
    list_timestamp_str = json_data['trustList']['timeStamp']
    list_timestamp = datetime.strptime(list_timestamp_str, '%Y-%m-%dT%H:%M:%S.%f')
    signature_base64 = json_data['trustList']['trustListSignature']
    signature = base64.b64decode(signature_base64)
    list_base64 = json_data['trustList']['trustListContent']
    list_bytes = base64.b64decode(list_base64)

    # Verify signature
    # Root certificate loaded from: https://github.com/Federal-Ministry-of-Health-AT/green-pass-overview/
    sig = CoseMessage.decode(signature)
    if not sig or not isinstance(sig, Sign1Message):
        raise RuntimeError("Not valid list!")

    at_root_cert_filename = "{}/roots/Austria-prod.pem".format(destination_dir)
    with open(at_root_cert_filename, "rb") as pem_file:
        lines = pem_file.read()
    root_cert = x509.load_pem_x509_certificate(lines)
    root_key = _cert_to_cose_key(root_cert)
    sig.key = root_key
    if not sig.verify_signature():
        raise RuntimeError("Austrian list doesn't verify!")
    log.info("Signature of {} verified ok.".format(API_ENDPOINT_AUSTRIA_V2))

    # Save verified list of certificates
    cert_list = cbor2.loads(list_bytes)
    return _save_certs(cert_list["c"], destination_dir)


def fetch_certificates_austria_api(destination_dir: str) -> dict:
    log.debug("Get trust list from Austria endpoint: {}".format(TRUST_LIST_AUSTRIA_URL))

    # This code adapted from Panzi's code at:
    # https://github.com/panzi/verify-ehc/blob/main/verify_ehc.py#669

    # Step 1:
    # Get the SHA2 256-bit hash of the actual trust-list. It is signed.
    root_certs_signature_hash = requests.get(TRUST_LIST_AUSTRIA_SHA2_HASH_URL)
    sig_msg = CoseMessage.decode(root_certs_signature_hash.content)
    if not isinstance(sig_msg, Sign1Message):
        raise RuntimeError("Downloaded payload is not is not a COSE-signature message!")
    signed_hash = cbor2.loads(sig_msg.payload)

    # Verify signature to be signed with known public key
    root_cert = x509.load_pem_x509_certificate(TRUST_LIST_AUSTRIA_ROOT_CERT.encode('ascii'))
    root_cert_key_id = sig_msg.phdr.get(headers.KID) or sig_msg.uhdr[headers.KID]
    key_id = root_cert.fingerprint(hazmat.primitives.hashes.SHA256())[:8]
    if key_id != root_cert_key_id:
        raise RuntimeError("Downloaded payload is not is not signed with Austrian trust anchor!")

    # Verify the SHA2 hash signature.
    root_key = _cert_to_cose_key(root_cert)
    sig_msg.key = root_key
    if not sig_msg.verify_signature():
        raise RuntimeError("Austrian list doesn't verify!")
    log.info("Signature of {} verified ok.".format(TRUST_LIST_AUSTRIA_SHA2_HASH_URL))
    # Ok. Now the hash is verified to be signed properly.

    # Step 2:
    # Get the list of trusted certs
    root_certs_cose = requests.get(TRUST_LIST_AUSTRIA_URL)
    certs_cbor = cbor2.loads(root_certs_cose.content)

    # Get a SHA2 256-bit hash of the payload
    sha256_hasher = hazmat.primitives.hashes.Hash(hazmat.primitives.hashes.SHA256())
    sha256_hasher.update(root_certs_cose.content)
    digest = sha256_hasher.finalize()

    # What we calculated must match with the hash we loaded.
    if signed_hash[2] != digest:
        raise RuntimeError('Austrian root certificates list -signature does not verify.')

    # Save verified list of certificates
    return _save_certs(certs_cbor["c"], destination_dir)


def fetch_certificates_sweden_api(destination_dir: str) -> dict:
    log.debug("Get trust list from Sweden endpoint: {}".format(TRUST_LIST_SWEDEN_SIG_URL))

    # Step 1:
    # Get the signature key. Public-part.
    root_certs_signature_cert = requests.get(TRUST_LIST_SWEDEN_SIG_URL)
    sign_cert = x509.load_pem_x509_certificate(root_certs_signature_cert.content, hazmat.backends.default_backend())
    key = sign_cert.public_key()
    jwk = cjwtk.ec.ECKey()
    jwk.load_key(key)
    if jwk.kty != 'EC':
        raise RuntimeError("Cannot handle keys of type {}! Only EC-keys supported.".format(jwk.kty))
    signature_algo_map = {
        'P-256': "ES256",
        'P-384': "ES384",
        'P-512': "ES512",
    }
    if jwk.crv not in signature_algo_map:
        raise RuntimeError("Cannot handle EC-key with curve {}.".format(jwk.crv))
    log.debug("Got Elliptic Curve key with {} curve".format(jwk.crv))
    signature_algo = signature_algo_map[jwk.crv]

    # Step 2:
    # Get the list of root certs
    root_certs_jwt = requests.get(TRUST_LIST_SWEDEN_URL)
    # DEBUG: Simple approach:
    # import jwt # pyjwt
    # root_certs = jwt.decode(root_certs_jwt.content, options={"verify_signature": False})
    jwsig_verifier = cjws.jws.JWS(alg=signature_algo)
    verified_payload = jwsig_verifier.verify_compact(root_certs_jwt.content, [jwk])
    log.debug("Issued at: {}".format(datetime.utcfromtimestamp(verified_payload['iat']).strftime('%Y-%m-%d %H:%M:%S')))
    log.debug("Expiry   : {}".format(datetime.utcfromtimestamp(verified_payload['exp']).strftime('%Y-%m-%d %H:%M:%S')))

    keys_out = []
    for trusted_root_country in verified_payload['dsc_trust_list']:
        key_data = verified_payload['dsc_trust_list'][trusted_root_country]
        for key in key_data['keys']:
            kid = key['kid']
            root_cert = x509.load_der_x509_certificate(base64.b64decode(key['x5c'][0]),
                                                       hazmat.backends.default_backend())
            if False:
                # Create JSON-list of certs too? Maybe not.
                key_out = {
                    "serialNumber": "0179ccf8be3b7e605c7b",  # hex(cert.serial_number)
                    "subject": "C=AT, O=BMSGPK, 2.5.4.5=001001, CN=AT DGC DSC 1",  # cert.subject
                    "issuer": "C=AT, O=BMSGPK, 2.5.4.5=001, CN=AT DGC CSCA 1",  # cert.issuer
                    "notBefore": "2021-06-02T13:45:24.000Z",  # cert.not_valid_before
                    "notAfter": "2023-06-02T13:45:24.000Z",  # cert.not_valid_after
                    "signatureAlgorithm": "ECDSA",
                    "fingerprint": root_cert.fingerprint(hazmat.primitives.hashes.SHA1()).hex(),
                    # cert_public_key  = cert.public_key()
                    "publicKeyAlgorithm": {
                        "hash": {
                            "name": "SHA-256"  # cert.signature_hash_algorithm
                        },
                        "name": "ECDSA",
                        "namedCurve": "P-256"
                    },
                    # cert_public_key.public_bytes(encoding=hazmat.primitives.serialization.Encoding.DER,
                    #                              format=hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo
                    #                              )
                    # base64.b64encode(bytes).decode('ascii')
                    "publicKeyPem": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYE24qIKmdcfRWUh2TqklkfZ6nyNBpX4VHeLMxfFl8rkQ8Zku0bcnH5OZXckkSt+tKs+FGZ9tKJ1VtNDmedlL6w=="

                }
            key_out = {
                "i": base64.b64decode(kid),
                "c": root_cert.public_bytes(hazmat.primitives.serialization.Encoding.DER)
            }
            keys_out.append(key_out)

    # Save verified list of certificates
    return _save_certs(keys_out, destination_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description='EU COVID Passport Signing Certificate Fetcher')
    parser.add_argument('--country-trust-list',
                        default=TRUST_LIST_COUNTRY_AUSTRIA,
                        help='Trust list source country. Default: {0}'.format(TRUST_LIST_COUNTRY_AUSTRIA))
    parser.add_argument('--cert-directory', default=DEFAULT_CERTS_DIR,
                        help="Destination directory to save certificates into. Default: {}".format(DEFAULT_CERTS_DIR))

    args = parser.parse_args()
    _setup_logger()

    fetch_certificates(args.country_trust_list, args.cert_directory)


if __name__ == '__main__':
    main()
