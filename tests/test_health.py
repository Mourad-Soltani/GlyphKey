"""
Health tests for GlyphKey.
Built by Mourad.Soltani
"""

import math
import unittest
from glyphkey.cli import (
    calculate_entropy,
    generate_password,
    generate_passphrase,
    generate_hex,
    analyze,
    strength_label,
    WORDLIST,
)


class TestGlyphKey(unittest.TestCase):
    def test_entropy_calculation(self):
        bits = calculate_entropy(20, 62)
        expected = 20 * math.log2(62)
        self.assertAlmostEqual(bits, expected, places=5)

    def test_password_generation(self):
        secret, bits = generate_password(16, "alnum")
        self.assertEqual(len(secret), 16)
        self.assertGreater(bits, 90)
        self.assertTrue(all(c.isalnum() for c in secret))

    def test_passphrase(self):
        secret, bits = generate_passphrase(5, "-")
        parts = secret.split("-")
        self.assertEqual(len(parts), 5)
        self.assertTrue(all(w in WORDLIST for w in parts))
        self.assertGreater(bits, 35)

    def test_hex(self):
        secret, bits = generate_hex(16)
        self.assertEqual(len(secret), 32)
        self.assertEqual(bits, 128)

    def test_analyze(self):
        result = analyze("MyP@ssw0rd!")
        self.assertGreater(result["entropy_bits"], 50)
        self.assertIn(result["strength"], ["strong", "very-strong", "excellent"])

    def test_strength_labels(self):
        self.assertEqual(strength_label(20), "very-weak")
        self.assertEqual(strength_label(50), "reasonable")
        self.assertEqual(strength_label(100), "very-strong")
        self.assertEqual(strength_label(150), "excellent")


if __name__ == "__main__":
    unittest.main()
