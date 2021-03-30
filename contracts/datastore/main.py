from boa3.builtin import NeoMetadata, metadata, public
from boa3.builtin.interop.storage import get, put
from boa3.builtin.interop.json import json_serialize, json_deserialize
from typing import List
from primatives.index import Index

# TODO: Domain-scoped security
# TODO: Domain listing
# TODO: Format Checking
# TODO: StorageMap updates
# TODO: Improved exception handling
# TODO: Delete and Update support
# TODO: Like functionality for queries
# TODO: Update to use context instead of a bunch of appends when boa adds support
# TODO: Audit Storage Scopes
# TODO: Move Primatives to their own file


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


CONTRACT_NAME = 'DataStore'
CONTRACT_VERSION = 'v0.0.1'
AUTHOR = 'Tyler Adams'
EMAIL = 'tyler@coz.io'
DESCRIPTION = 'This smart contract implements a pointer-based database on top of the key-value storage ' \
                       'layer to enable advanced storage features.'
DESCRIPTION_EXTENDED = ''


@metadata
def manifest_metadata() -> NeoMetadata:
    meta = NeoMetadata()
    meta.author = 'Tyler Adams'
    meta.email = 'tyler@coz.io'
    meta.description = 'This smart contract implements a pointer-based database on top of the key-value storage ' \
                       'layer to enable advanced storage features.'
    return meta


# ---------------------------------
# CONTRACT GLOBALS
# ---------------------------------


ROOT_MAP_PREFIX = b'_root'
WRITE_POINTER_KEY_PREFIX = b'_wp_'
VALUE_STORE_MAP_PREFIX = b'_v_'


# ---------------------------------
# EVENTS
# ---------------------------------


# ---------------------------------
# Methods
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
def create_index(domain: bytes, index: Index, key: bytes, pointer: int) -> bool:
    """
    Creates a new index in the datastore for a domain.

    :param domain: the scope that the index exists within (this is similar to a table)
    :param index: the index definition
    :param key: the key to store the data under
    :param pointer: the write pointer used to store the data

    :return: A boolean indicating whether the operation was successful.
    """
    index_values = get_index(domain, index, key)

    # Enforce unique indices.
    assert not (index.get_unique() and len(index_values) > 0), 'Exception: Unique index exists.'

    # Append the new domain-global pointer to the index-key entry and update storage.
    index_values.append(pointer)
    set_variable_prefixed_value(domain, index.get_key(), key, json_serialize(index_values))

    return True


@public
def create_object(domain: bytes, obj: bytes) -> int:
    """
    Creates an object in the datastore.

    :param domain: The domain to create the object in.
    :param obj: The object to store.
    :return: A global pointer indicating the location of the object being stored.
    """

    wp = get_write_pointer(domain) + 1
    set_variable_prefixed_value(domain, VALUE_STORE_MAP_PREFIX, wp.to_bytes(), obj)
    set_write_pointer(domain, wp)
    return wp


@public
def get_index(domain: bytes, index: Index, key: bytes) -> List[int]:
    """
    Gets the domain-global pointers of objects using an index query.

    :param domain: The domain which the index exists.
    :param index: The index object being used in the query.
    :param key: The key being queried with. i.e: `Select * from {{domain}} where {{index}} = {{key}}`
    :return: An array of global pointers to objects which match the query.
    """

    # TODO: this will break everything until its resolved
    # key_pointers: List[int] = json_deserialize(get_variable_prefixed_value(domain, index.get_key(), key)) # implicit cast List[bytes] -> List[int]

    key_pointers: List[int] = []
    # if len(index_key_values) > 0:
    #     key_pointers = index_key_values

    return key_pointers



# def get_index_storage_map(domain: bytes, index: Index) -> StorageMap:
#     """
#     Gets the storage map for an index.
#
#     :param domain: The domain that will handle the query.
#     :param index: The index to return the map for.
#     :return: Returns a storage map that is scoped for the requested domain and index.
#     """
#     return get_prefixed_storage_map(domain, index.get_key())


@public
def get_object(domain: bytes, pointer: int) -> bytes:
    """
    Gets an object from a domain using its domain-global pointer.
    :param domain: The domain to query against.
    :param pointer: The domain-global pointer of the object.
    :return: A byte array representation of the stored object.
    """
    return get_variable_prefixed_value(domain, VALUE_STORE_MAP_PREFIX, pointer.to_bytes())


@public
def get_objects_by_index(domain: bytes, index: Index, key: bytes) -> List[bytes]:
    """
    Gets all objects which match an index query in a target domain.

    :param domain: The domain being targeted.
    :param index: The index being queried against.
    :param key: The key that will be matched against the index.
    :return: An array of bytearrays which represent the results of the query.
    """

    pointers = get_index(domain, index, key)
    objects: List[bytes] = []
    for pointer in pointers:
        obj = get_object(domain, pointer)
        objects.append(obj)

    return objects


# TODO: Automatically insert "_" in the scope for security.
def get_variable_prefixed_value(prefix: bytes, variable: bytes, key: bytes) -> bytes:
    """
    Gets a variable storage map with a prefix.
    :param prefix: The prefix to use in the storage map.
    :param variable: A variable to concatenate to the prefix.
    :param key: The get to get
    :return: The bytes object from storage`
    """

    assert len(prefix) > 0 and len(variable) > 0 and len(key) > 0, 'Exception: Storage get requires prefix, ' \
                                                                   'variable, and key fields'
    return get(prefix + variable + key)


# TODO: Automatically insert "_" in the scope for security.
def set_variable_prefixed_value(prefix: bytes, variable: bytes, key: bytes, value: bytes) -> bool:
    """
    Sets the value of a prefixed storage location
    :param prefix: The prefix to use in the storage map.
    :param variable: A variable to concatenate to the prefix.
    :param key: The key to store against
    :param value: The value to store
    :return: A bool indicating success`
    """

    assert len(prefix) > 0 and len(variable) > 0 and len(key) > 0, 'Exception: Storage put requires prefix, ' \
                                                                   'variable, and key fields'
    put(prefix + variable + key, value)
    return True


@public
def verify_index_available(domain: bytearray, index: Index, key: bytearray) -> bool:
    """
    Verifies if a key can be stored against an index.

    For an index to be available, The index either must be non-unique(if the key value already exist on the index) or
    the key must not already be registered against the index.

    :param domain: The domain of the index.
    :param index: The index to evaluate against.
    :param key: The value to check availability of.
    :return: A boolean indicating whether the key is available for the index in the target domain.
    """
    if not index.get_unique():
        return True

    pointers = get_index(domain, index, key)
    if len(pointers) == 0:
        return True

    return False


@public
def get_write_pointer(domain: bytes) -> int:
    """
    Gets the domain-global write pointer for a domain.
    :param domain: The domain to evaluate.
    :return: The write pointer for the domain.
    """

    try:
        wp:int = get(domain + ROOT_MAP_PREFIX + WRITE_POINTER_KEY_PREFIX).to_int()
    except BaseException:
        wp = 1

    return wp


def set_write_pointer(domain: bytes, wp: int) -> bool:
    """
    Sets the write pointer for a domain.
    :param domain: The domain to operate on.
    :param wp: The write pointer to set.
    :return: A boolean indicating whether the operation was successful.
    """
    put(domain + ROOT_MAP_PREFIX + WRITE_POINTER_KEY_PREFIX, wp.to_bytes())
    return True