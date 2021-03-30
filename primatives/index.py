class Index:
    _key: bytearray = ""
    _unique: bool = False

    def __init__(self, key: bytearray, unique: bool):
        self._key = key
        self._unique = unique

    def get_key(self):
        return self._key

    def get_unique(self):
        return self._unique