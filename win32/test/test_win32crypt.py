# Test module for win32crypt

import unittest
import logging
import contextlib
from typing import Iterator, Any

import win32crypt
from win32con import *
from win32cryptcon import *
from pywin32_testutil import find_test_fixture, testmain, TestSkipped


class Crypt(unittest.TestCase):
    def testSimple(self):
        data = b"My test data"
        entropy = None
        desc = "My description"
        flags = 0
        ps = None
        blob = win32crypt.CryptProtectData(data, desc, entropy, None, ps, flags)
        got_desc, got_data = win32crypt.CryptUnprotectData(
            blob, entropy, None, ps, flags
        )
        self.assertEqual(data, got_data)
        self.assertEqual(desc, got_desc)

    def testEntropy(self):
        data = b"My test data"
        entropy = b"My test entropy"
        desc = "My description"
        flags = 0
        ps = None
        blob = win32crypt.CryptProtectData(data, desc, entropy, None, ps, flags)
        got_desc, got_data = win32crypt.CryptUnprotectData(
            blob, entropy, None, ps, flags
        )
        self.assertEqual(data, got_data)
        self.assertEqual(desc, got_desc)


# via https://github.com/mhammond/pywin32/issues/1859
_LOCAL_MACHINE = "LocalMachine"
_CURRENT_USER = "CurrentUser"


@contextlib.contextmanager
def open_windows_certstore(store_name: str, store_location: str) -> Iterator[Any]:
    """Open a windows certificate store

    :param store_name: store name
    :param store_location: store location
    :return: handle to cert store
    """
    print(f"opening cert store {store_name} on {store_location}")
    handle = None
    try:
        handle = win32crypt.CertOpenStore(
            CERT_STORE_PROV_SYSTEM,
            0,
            None,
            CERT_SYSTEM_STORE_LOCAL_MACHINE
            if store_location == _LOCAL_MACHINE
            else CERT_SYSTEM_STORE_CURRENT_USER,
            store_name,
        )
        yield handle
    finally:
        if handle is not None:
            handle.CertCloseStore(CERT_CLOSE_STORE_FORCE_FLAG)
            print("closed cert store {} on {}".format(store_name, store_location))


class TestCerts(unittest.TestCase):
    def checkFile(self, file_name):
        buf = bytearray(open(find_test_fixture(file_name), "rb").read())
        _certdict = win32crypt.CryptQueryObject(
            CERT_QUERY_OBJECT_BLOB,
            buf,
            CERT_QUERY_CONTENT_FLAG_CERT,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
        )
        print(_certdict)
        with open_windows_certstore(_CURRENT_USER, "Temp") as certstore:
            _newcertcontext = certstore.CertAddCertificateContextToStore(
                _certdict["Context"], CERT_STORE_ADD_REPLACE_EXISTING
            )
            print(_newcertcontext)

    def testOpen1(self):
        self.checkFile("win32crypt_testcert1.cer")

    def testOpen2(self):
        self.checkFile("win32crypt_testcert2.cer")


if __name__ == "__main__":
    testmain()
