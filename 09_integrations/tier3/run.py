"""Run official NVIDIA Tier 3 paired trials using AgentShield's main private model."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import signal
import shutil
import tempfile
import sys
import time
import uuid
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'03_ai'), str(ROOT/'05_skill_eval')]
from llm import cloud_cfg
from bundle_manifest import manifest

CLI = ROOT/'.venv-evaluator/bin/skillevaluator'
SKILL = ROOT/'10_skills/agentshield-audit'


def model_environment(config):
    """Credentials only in child environment; no inherited third-party provider routes."""
    env = {k:v for k,v in os.environ.items() if k in ('PATH','HOME','TMPDIR','LANG','DOCKER_HOST','DOCKER_CONTEXT','SYSTEMROOT')}
    docker = Path('/Applications/Docker.app/Contents/Resources/bin')
    env['PATH'] = str(CLI.parent)+os.pathsep+(str(docker)+os.pathsep if docker.exists() else '')+env.get('PATH','')
    env.update(SKILL_EVAL_LLM_PROVIDER='openai-compatible', SKILL_EVAL_LLM_BASE_URL=config['base_url'],
               SKILL_EVAL_LLM_MODEL=config['model'], SKILL_EVAL_LLM_API_KEY=config.get('api_key') or 'local-no-key',
               OPENAI_BASE_URL=config['base_url'], OPENAI_API_KEY=config.get('api_key') or 'local-no-key',
               NO_PROXY='*', PYTHONNOUSERSITE='1', DO_NOT_TRACK='1')
    return env


def command(output, model, attempts=1, skill=SKILL):
    return [str(CLI), 'tier3', 'evaluate', str(skill), '--agents', 'opencode', '--env-mode', 'docker',
            '--agent-model', 'opencode=openai/'+model, '--n-attempts', str(attempts), '--n-concurrent', '1',
            '--max-agents', '1', '--results-dir', str(output), '--progress', 'plain']



def paired_complete(report):
    """Require scored coverage for BOTH official conditions, including the baseline."""
    if report.get('execution_status') != 'succeeded':
        return False
    agents = report.get('agents')
    if not isinstance(agents, dict) or not agents:
        return False
    for agent in agents.values():
        if not isinstance(agent, dict) or agent.get('execution_status') != 'succeeded':
            return False
        conditions = agent.get('conditions', {})
        if not isinstance(conditions, dict):
            return False
        for arm in ('with_skill', 'without_skill'):
            condition = conditions.get(arm, {})
            if not isinstance(condition, dict):
                return False
            expected = condition.get('expected_attempts')
            if (condition.get('execution_status') != 'succeeded'
                    or type(expected) is not int or expected < 1
                    or condition.get('scored_attempts') != expected
                    or condition.get('execution_errors')):
                return False
    return True


def _run(execute=False, attempts=1, skill=SKILL):
    if attempts not in range(1,6):
        raise ValueError('attempts must be 1..5')
    cfg = cloud_cfg()
    if not cfg.get('base_url') or not cfg.get('model'):
        raise ValueError('请先配置主模型。')
    env = model_environment(cfg)
    result = {'engine':'NVIDIA SkillEvaluator Tier 3', 'status':'not_run', 'model':cfg['model'],
              'arms':['with_skill','without_skill'], 'attempts':attempts,
              'scope':'已有报告解读、证据核对与不可信输入处理；不测真实攻击或扫描召回率',
              'skill_manifest':manifest(skill)}
    if not CLI.is_file():
        result.update(status='unavailable', reason='请先安装锁定版本的 Tier 3 环境。')
        return result
    lock=json.loads((ROOT/'09_integrations/tier3/component-lock.json').read_text())
    package=ROOT/lock['installed_package'];digest=hashlib.sha256()
    for f in sorted(package.rglob('*')):
        if f.is_file() and '__pycache__' not in f.parts and f.suffix!='.pyc':
            digest.update(f.relative_to(package).as_posix().encode()+b'\0');digest.update(hashlib.sha256(f.read_bytes()).digest())
    if digest.hexdigest()!=lock['installed_package_sha256']:
        result.update(status='unavailable',reason='SkillEvaluator 安装内容与锁文件不一致。');return result
    result['evaluator_revision']=lock['revision']
    validate = subprocess.run([str(CLI),'tier3','validate',str(skill),'--strict','--json'], env=env, capture_output=True, text=True, timeout=30)
    result['dataset_valid'] = validate.returncode == 0
    if not result['dataset_valid']:
        result.update(status='invalid_dataset'); return result
    if not execute:
        return result
    output=ROOT/'reports'/('tier3-'+time.strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:6])
    output.mkdir(mode=0o700)
    result['report']=output.name
    # Full logs stay in ignored local reports. Scrub credentials before persistence.
    try:
        process = subprocess.Popen(command(output,cfg['model'],attempts,skill),env=env,cwd=ROOT,
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        try:
            stdout,stderr=process.communicate(timeout=1800)
        except (subprocess.TimeoutExpired,KeyboardInterrupt):
            os.killpg(process.pid,signal.SIGTERM)
            try:process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.communicate()
            raise
        log=stdout+'\n'+stderr
        for secret in (cfg.get('api_key'), cfg.get('base_url')):
            if secret: log=log.replace(secret,'[REDACTED]')
        (output/'runner.log').write_text(log)
        results=[p for p in output.rglob('result.json') if '_harbor-jobs' not in p.parts]
        complete=[json.loads(p.read_text()) for p in results]
        verified=bool(complete) and all(paired_complete(d) for d in complete)
        # The process finishing alone is not evidence that both arms completed.
        result.update(status='complete' if process.returncode==0 and verified else 'failed', exit_code=process.returncode,
                      official_results=[p.relative_to(output).as_posix() for p in results])
    except subprocess.TimeoutExpired:
        result.update(status='timeout')
    (output/'agentshield-run.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
    for path in output.rglob('*'):
        if path.is_file(): path.chmod(0o600)
    return result

def run(execute=False,attempts=1,case=None):
    if case is None:return _run(execute,attempts)
    dataset=json.loads((SKILL/'evals/evals.json').read_text())
    chosen=[e for e in dataset['evals'] if e['id']==case]
    if not chosen:raise ValueError('未知评测用例。')
    with tempfile.TemporaryDirectory(prefix='agentshield-tier3-') as temp:
        snapshot=Path(temp)/SKILL.name
        shutil.copytree(SKILL,snapshot)
        dataset['evals']=chosen
        (snapshot/'evals/evals.json').write_text(json.dumps(dataset,ensure_ascii=False,indent=2))
        return _run(execute,attempts,snapshot)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--run',action='store_true');p.add_argument('--attempts',type=int,default=1);p.add_argument('--case',choices=['explicit-review','implicit-coverage','contextual-injection','negative-python'])
    args=p.parse_args();result=run(args.run,args.attempts,args.case)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    raise SystemExit(1 if result['status'] in ('failed','timeout','unavailable','invalid_dataset') else 0)
