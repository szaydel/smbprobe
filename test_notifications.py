import unittest

from notifications import betterstack_description, Data, URL


class TestNotifications(unittest.TestCase):
    def test_betterstack_description(self):
        """Validates expected betterstack template output"""
        expected = ""
        with open("testdata/notifications_betterstack_desc1.txt", "rt") as f:
            expected = f.read()
        data = Data(
            target_address="12.13.14.15",
            target_share="alphashare",
            target_domain="example.com",
            latencies={"login": 1, "read": 2, "write": 3, "ls_dir": 5, "unlink": 4},
            failed_ops=dict(login=1, read=2, write=3, unlink=4, ls_dir=5),
        )

        actual = betterstack_description(data)
        self.assertEqual(actual, expected)

    def test_url_with_subs(self):
        """Validates proper url template rendering"""
        expected_repr = "URL(https://notavaliddomain/{alpha}/{beta}/{gamma}, subs={'alpha': 'first', 'beta': 'second', 'gamma': 'third'})"
        expected_str = "https://notavaliddomain/first/second/third"
        u = URL(
            "https://notavaliddomain/{alpha}/{beta}/{gamma}",
            subs=dict(alpha="first", beta="second", gamma="third"),
        )
        self.assertEqual(u.__str__(), expected_str)
        self.assertEqual(u.__repr__(), expected_repr)
