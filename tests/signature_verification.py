"""Real OMS cryptographic regressions using an ephemeral, explicitly test-only CA."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'05_skill_eval'))
from signature_verify import verify_skill,VERIFIER
class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.skill=self.root/'skill';self.skill.mkdir();(self.skill/'SKILL.md').write_text('Synthetic harmless Skill')
        self.trust=self.root/'trust';self.trust.mkdir()
        key=ec.generate_private_key(ec.SECP256R1())
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'AgentShield TEST ONLY')])
        now=datetime.datetime.now(datetime.timezone.utc)
        cert=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),critical=False).sign(key,hashes.SHA256())
        pem=cert.public_bytes(serialization.Encoding.PEM);(self.trust/'root.crt').write_bytes(pem)
        self.key=self.root/'key.pem';self.key.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));self.key.chmod(0o600)
        (self.trust/'trust-lock.json').write_text(json.dumps({'publisher':'TEST ONLY','revision':'test','certificate':'root.crt','sha256':hashlib.sha256(pem).hexdigest()}))
    def tearDown(self):self.temp.cleanup()
    def sign(self):
        p=subprocess.run([str(VERIFIER),'sign','certificate',str(self.skill),'--signature',str(self.skill/'skill.oms.sig'),'--private_key',str(self.key),'--signing_certificate',str(self.trust/'root.crt'),'--certificate_chain',str(self.trust/'root.crt'),'--no-ignore-git-paths'],capture_output=True,text=True,timeout=20)
        self.assertEqual(p.returncode,0,p.stderr[-500:])
    def verify(self):return verify_skill(self.skill,trust_dir=self.trust)
    def test_unsigned(self):self.assertEqual(self.verify()['status'],'unsigned')
    def test_valid_signature(self):
        self.sign();r=self.verify();self.assertEqual(r['status'],'verified');self.assertEqual(r['publisher'],'TEST ONLY');self.assertFalse(r['safety_checked'])
    def test_tampering(self):
        self.sign();(self.skill/'SKILL.md').write_text('Modified');self.assertEqual(self.verify()['status'],'invalid')
    def test_unsigned_addition(self):
        self.sign();(self.skill/'new.py').write_text('print(1)');self.assertEqual(self.verify()['status'],'invalid')
    def test_deleted_signed_file(self):
        (self.skill/'extra.txt').write_text('signed');self.sign();(self.skill/'extra.txt').unlink();self.assertEqual(self.verify()['status'],'invalid')
    def test_wrong_publisher(self):
        self.sign();self.assertEqual(verify_skill(self.skill)['status'],'invalid')
    def test_changed_trust_anchor(self):
        self.sign();(self.trust/'root.crt').write_text('tampered');self.assertEqual(self.verify()['status'],'trust_error')
    def test_symlink_rejected(self):
        (self.skill/'linked').symlink_to(self.key)
        with self.assertRaises(ValueError):self.verify()
if __name__=='__main__':unittest.main()
