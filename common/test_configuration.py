import unittest

from common.configuration import probe_config_to_si
from common.constants import DEFAULT_LOOP_INTERVAL


class T(unittest.TestCase):
    def test_probe_config_to_si(self):
        """Validates generation of the ShareInfo classes"""
        addr = "192.168.1.1"
        test_share = "smb01"
        test_domain = "alpha.test.domain"
        username = "test_user"
        password = "testing"
        remote_basedir = "alpha/beta/gamma"
        interval = 7
        probe_config = {
            "address": addr,
            "share": test_share,
            "domain": test_domain,
            "username": username,
            "password": password,
            "remote_basedir": remote_basedir,
            "interval": interval,
        }
        si = probe_config_to_si(probe_config)
        self.assertEqual(si.addr, addr)
        self.assertEqual(si.share, test_share)
        self.assertEqual(si.domain, test_domain)
        self.assertEqual(si.user, username)
        self.assertEqual(si.passwd, password)
        self.assertEqual(si.basedir, remote_basedir)
        self.assertEqual(si.interval, interval)

    def test_probe_config_to_si_default_interval(self):
        """Validates generation of the ShareInfo classes with default interval"""
        addr = "192.168.1.1"
        test_share = "smb01"
        test_domain = "alpha.test.domain"
        username = "test_user"
        password = "testing"
        remote_basedir = "alpha/beta/gamma"
        probe_config = {
            "address": addr,
            "share": test_share,
            "domain": test_domain,
            "username": username,
            "password": password,
            "remote_basedir": remote_basedir,
        }
        si = probe_config_to_si(probe_config)
        self.assertEqual(si.addr, addr)
        self.assertEqual(si.share, test_share)
        self.assertEqual(si.domain, test_domain)
        self.assertEqual(si.user, username)
        self.assertEqual(si.passwd, password)
        self.assertEqual(si.basedir, remote_basedir)
        self.assertEqual(si.interval, DEFAULT_LOOP_INTERVAL)

    def test_probe_config_to_si_with_negative_interval(self):
        """Validates generation of the ShareInfo classes when the interval is invalid"""
        addr = "192.168.1.1"
        test_share = "smb01"
        test_domain = "alpha.test.domain"
        username = "test_user"
        password = "testing"
        remote_basedir = "alpha/beta/gamma"
        interval = -10
        probe_config = {
            "address": addr,
            "share": test_share,
            "domain": test_domain,
            "username": username,
            "password": password,
            "remote_basedir": remote_basedir,
            "interval": interval,
        }
        with self.assertRaises(RuntimeError):
            probe_config_to_si(probe_config)
