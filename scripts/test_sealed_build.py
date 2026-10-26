import io
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from cryptography.exceptions import InvalidTag
from sealed_build import seal, unseal, extract

class SealedBuildTests(unittest.TestCase):
    def test_authentication(self):
        key = os.urandom(32)
        payload = seal(b'private input', key)
        self.assertEqual(unseal(payload, key), b'private input')
        with self.assertRaises(InvalidTag):
            unseal(payload, os.urandom(32))
        with self.assertRaises(InvalidTag):
            unseal(payload[:-1] + bytes([payload[-1] ^ 1]), key)

    def test_archive_guards(self):
        for name in ('../escape', '/absolute', 'C:/absolute', 'a\\escape'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, 'w') as archive:
                    archive.writestr(name, b'x')
                with self.assertRaises(AssertionError):
                    extract(buf.getvalue(), Path(tmp) / 'root')

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w') as archive:
                item = zipfile.ZipInfo('link')
                item.external_attr = 0o120777 << 16
                archive.writestr(item, '../escape')
            with self.assertRaises(AssertionError):
                extract(buf.getvalue(), Path(tmp) / 'root')

    def test_executable_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w') as archive:
                item = zipfile.ZipInfo('bin/tool')
                item.external_attr = 0o100755 << 16
                archive.writestr(item, b'data')
            root = Path(tmp) / 'root'
            extract(buf.getvalue(), root)
            self.assertEqual((root / 'bin/tool').read_bytes(), b'data')
            if os.name != 'nt':
                self.assertTrue((root / 'bin/tool').stat().st_mode & 0o111)

if __name__ == '__main__':
    unittest.main()
