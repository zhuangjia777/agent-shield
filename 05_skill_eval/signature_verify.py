"""Strict OMS verification against an operator-pinned publisher trust anchor."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from bundle_manifest import manifest

ROOT = Path(__file__).resolve().parent.parent
TRUST = ROOT / '09_integrations/signatures'
VERIFIER = ROOT / '.venv-integrations/bin/model_signing'
LABELS = {'verified':'签名通过（仍需安全检查）', 'unsigned':'未签名', 'invalid':'签名验证失败',
          'unavailable':'验签器不可用', 'trust_error':'信任证书校验失败', 'error':'验签未完成'}


def verify_snapshot(directory, *, trust_dir=TRUST, verifier=VERIFIER, timeout=45):
    """Input is a private immutable scan snapshot. Never trust certificates in the Skill."""
    root = Path(directory)
    before = manifest(root)
    result = {'format':'OMS', 'status':'unsigned', 'input_hash':before['input_hash'],
              'strict':True, 'safety_checked':False, 'publisher':None}
    sig = root / 'skill.oms.sig'
    if not sig.is_file():
        return result
    result['signature_sha256'] = hashlib.sha256(sig.read_bytes()).hexdigest()
    try:
        trust_dir = Path(trust_dir)
        lock = json.loads((trust_dir/'trust-lock.json').read_text())
        cert = trust_dir/lock['certificate']
        if cert.parent.resolve() != trust_dir.resolve() or cert.is_symlink():
            raise ValueError('invalid trust path')
        if hashlib.sha256(cert.read_bytes()).hexdigest() != lock['sha256']:
            raise ValueError('trust digest mismatch')
        result.update(trust_sha256=lock['sha256'], trust_revision=lock['revision'])
    except (ValueError, KeyError, OSError):
        result['status'] = 'trust_error'
        return result
    if not Path(verifier).is_file():
        result['status'] = 'unavailable'
        return result
    env = {k:v for k,v in os.environ.items() if k in ('PATH','HOME','TMPDIR','LANG','SYSTEMROOT')}
    try:
        run = subprocess.run([str(verifier), 'verify', 'certificate', str(root.resolve()),
                              '--signature', str(sig.resolve()), '--certificate_chain', str(cert.resolve()),
                              '--no-ignore-git-paths', '--no-ignore_unsigned_files'],
                             capture_output=True, text=True, timeout=timeout, env=env)
        result['status'] = 'verified' if run.returncode == 0 else 'invalid'
        result['verifier_exit_code'] = run.returncode
        if manifest(root)['input_hash'] != before['input_hash']:
            result['status'] = 'error'
        if result['status'] == 'verified':
            result['publisher'] = lock['publisher']
    except (OSError, subprocess.TimeoutExpired):
        result['status'] = 'error'
    return result


def verify_skill(directory, **options):
    """Snapshot the full tree; verification never imports or executes Skill code."""
    source = Path(directory)
    original = manifest(source)
    with tempfile.TemporaryDirectory(prefix='agentshield-signature-') as temp:
        snapshot = Path(temp)/'skill'
        snapshot.mkdir()
        for entry in original['entries']:
            dest = snapshot/entry['path']
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source/entry['path'], dest, follow_symlinks=False)
        if manifest(snapshot)['input_hash'] != original['input_hash']:
            raise ValueError('验签输入在建立快照时发生变化。')
        return verify_snapshot(snapshot, **options)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--skill', required=True)
    args = parser.parse_args()
    result = verify_skill(args.skill)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result['status']=='verified' else 1)
