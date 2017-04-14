import unittest


class DHTestCase(unittest.TestCase):
    def test_dh(self):
        from dh import create_dh_key, calculate_dh_secret
        for _ in range(5):
            alice_pub, alice_priv = create_dh_key()
            bob_pub, bob_priv = create_dh_key()

            alice_sec = calculate_dh_secret(bob_pub, alice_priv)
            bob_priv = calculate_dh_secret(alice_pub, bob_priv)

            self.assertEqual(alice_sec, bob_priv)


if __name__ == '__main__':
    unittest.main()
