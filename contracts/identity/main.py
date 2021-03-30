from boa3.builtin import NeoMetadata, metadata, public
from boa3.builtin.interop.storage import get, put
from boa3.builtin.interop.json import json_serialize, json_deserialize
from typing import List

# TODO: Notifications for identity creation and authentication updates
# TODO: Break out the keychain into its own file

class Index:
    _key: bytes = b''
    _unique: bool = False

    def __init__(self: any, key: bytes, unique: bool) -> any:
        self._key = key
        self._unique = unique

    def get_key(self: any) -> bytes:
        return self._key

    def get_unique(self: any) -> bool:
        return self._unique


# ---------------------------------
# CONTRACT HEADER
# ---------------------------------


CONTRACT_NAME = 'Vivid Identity'
CONTRACT_VERSION = 'v0.0.1'
AUTHOR = 'Tyler Adams'
EMAIL = 'tyler@coz.io'
DESCRIPTION = 'This smart contract implements the DID specification for Vivid identity'
DESCRIPTION_EXTENDED = ''


@metadata
def manifest_metadata() -> NeoMetadata:
    meta = NeoMetadata()
    meta.author = 'Tyler Adams'
    meta.email = 'tyler@coz.io'
    meta.description = 'This smart contract implements the DID specification for Vivid identity'
    return meta


# ---------------------------------
# CONTRACT GLOBALS
# ---------------------------------

# identity globals
DOMAIN_IDENTITY = b'identity'
INDEX_IDENTITY_ID = Index(b'i_i', True)

# keychain globals
DOMAIN_KEYCHAIN = b'keychain'
INDEX_KEYCHAIN_HOLDER = Index(b'i_hol', False)
INDEX_KEYCHAIN_OWNER = Index(b'i_own', False)
INDEX_KEYCHAIN_ISS = Index(b'i_iss', False)
INDEX_KEYCHAIN_HOLDER_SUB = Index(b'i_hol_sub', False)

# ---------------------------------
# EVENTS
# ---------------------------------

# identity created
# identity updated
# vivid key issued
# vivid key revoked

# ---------------------------------
# Methods (Identity)
# ---------------------------------


@public
def name() -> str:
    """
    Gets the name of the contract.

    :return: A string that communicates the name of the smart contract.
    """
    return CONTRACT_NAME


@public
def contract_version() -> str:
    """
    Gets the version of the contract.

    The contract version must use semantic versioning with the format: vX.X.X.

    :return: A string representing the version of the smart contract.
    """
    return CONTRACT_VERSION

@public
def create_root_key() -> bool:
    return

@public
def get_root_key_by_identity() ->

@public
def get_root_key_by_pointer() ->

@public
def get_root_key_write_pointer() ->

@public
def get_identity_exists() -> bool
    return


# ---------------------------------
# Methods (Keychain)
# ---------------------------------

@public
def issue_key() -> bool:
    return


@public
def get_key_by_pointer() -> any:
    return


@public
def get_key_by_holder() -> any:
    return


@public
def get_key_by_owner() -> any:
    return


@public
def get_key_by_issuer() -> any:


@public
def get_key_by_holder_sub() -> any:
    return

@public
def get_keychain_write_pointer() -> any:
    return

@public
def revoke_key_by_pointer() -> bool:
    return


