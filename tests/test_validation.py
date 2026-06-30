import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).parents[1] / 'panel' / 'panel' / 'validation.py'
SPEC = importlib.util.spec_from_file_location('validation', MODULE_PATH)
validation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validation)


class ValidationTests(unittest.TestCase):
    def test_hostname_validation(self):
        self.assertTrue(validation.is_valid_hostname('vpn.example.com'))
        self.assertTrue(validation.is_valid_hostname('xn--bcher-kva.example'))
        self.assertTrue(validation.is_valid_hostname('127.0.0.1'))
        for value in (None, '', 'localhost', '-bad.example', 'bad-.example',
                      'bad example.com', 'example.com\nmalicious', '999.0.0.1'):
            with self.subTest(value=value):
                self.assertFalse(validation.is_valid_hostname(value))

    def test_domain_validation_rejects_ip_addresses(self):
        self.assertTrue(validation.is_valid_domain('vpn.example.com'))
        self.assertFalse(validation.is_valid_domain('127.0.0.1'))
        self.assertFalse(validation.is_valid_domain('example.123'))

    def test_ipv4_validation_rejects_invalid_octets_and_ipv6(self):
        self.assertTrue(validation.is_valid_ipv4('203.0.113.10'))
        self.assertFalse(validation.is_valid_ipv4('999.0.0.1'))
        self.assertFalse(validation.is_valid_ipv4('2001:db8::1'))
        self.assertFalse(validation.is_valid_ipv4(None))

    def test_bounded_int(self):
        self.assertEqual(validation.bounded_int('30', 7, 1, 366), 30)
        self.assertEqual(validation.bounded_int('9999', 7, 1, 366), 366)
        self.assertEqual(validation.bounded_int('-4', 7, 1, 366), 1)
        self.assertEqual(validation.bounded_int('nope', 7, 1, 366), 7)

    def test_secret_comparison_handles_missing_and_unicode_values(self):
        self.assertTrue(validation.secrets_equal('expected', 'expected'))
        self.assertFalse(validation.secrets_equal('wrong', 'expected'))
        self.assertFalse(validation.secrets_equal(None, 'expected'))
        self.assertTrue(validation.secrets_equal('päss', 'päss'))


if __name__ == '__main__':
    unittest.main()
