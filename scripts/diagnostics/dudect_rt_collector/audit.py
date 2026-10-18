"""Replay completed owned-unit evidence; partial observations remain separate."""
import hashlib
import json
from pathlib import Path
import sys


def read(path):return json.loads(Path(path).read_text())


def audit(directory):
    directory=Path(directory)
    d=read(directory/'descriptor.json');unit=read(directory/'unit-plan.json')
    result=read(directory/'result.json');obs=directory/'observations'
    if not result['complete'] or not result['cleanup_confirmed']:
        raise ValueError('incomplete owned execution')
    sys.path.insert(0,unit['analysis'])
    from analysis_runtime import replay
    from analysis_contract import identity
    from dudect_candidate import canonical
    analysis=read(obs/'analysis-binding.json')
    if analysis!=identity('interval-only',unit['packet'],unit['id']):raise ValueError('analysis identity')
    histories=read(obs/'observations.json')
    bindings={n:unit['bindings'][n] for n in unit['cases']}
    decisions=replay(obs,bindings,histories,analysis)
    rawlines=(obs/'native.stdout').read_bytes().splitlines()
    if [json.loads(line) for line in rawlines]!=[r for n in unit['cases'] for r in histories[n]]:
        raise ValueError('native output/history changed')
    journal=[json.loads(x) for x in (directory/'progress.jsonl').read_text().splitlines()]
    acknowledgments=[x for x in journal if x.get('ack_sent')]
    if len(acknowledgments)!=len(decisions) or len(decisions)!=24:raise ValueError('incomplete ACK inventory')
    for i,(r,line,decision) in enumerate(zip(acknowledgments,rawlines,decisions,strict=True)):
        if (r['row_sha256']!=hashlib.sha256(line).hexdigest() or
            r['proof_sha256']!=hashlib.sha256(canonical(decision)).hexdigest() or
            (r['case'],r['look'])!=(i//8,i%8+1)):raise ValueError('ACK evidence differs')
    for i,r in enumerate(journal):
        if r['sequence']!=i+1 or r['generation']!=d['generation'] or not (r['at']<r['until']<=d['end_at']):
            raise ValueError('progress lifecycle')
        if r['phase'] in ('validation','completion') and r['until']>r['at']+10:
            raise ValueError('validation bound')
    scheduler=[json.loads(x) for x in (obs/'scheduler.jsonl').read_text().splitlines()]
    native=read(obs/'native-identity.json')
    for r in scheduler:
        if (r['identity']!=native or r['affinity']!=[d['cpu']] or
            r['policy']!=(0x40000000 | (1 if d['arm']=='B' else 0)) or
            r['priority']!=(1 if d['arm']=='B' else 0) or r['rttime']!=d['rttime'] or r['rtprio']!=d['rtprio']):
            raise ValueError('native scheduler receipt')
    if len(scheduler)!=24:raise ValueError('scheduler inventory')
    for role in ('primary','rescue','controller'):
        c=read(directory/(role+'.context.json'))
        if c['affinity']!=d['housekeeping'] or c['policy']!=0x40000000 or c['priority']!=0:
            raise ValueError('monitor placement')
    if not result.get('supervisor_placement_preserved'):raise ValueError('supervisor placement')
    parent=read(directory/'supervisor.json')
    if parent['affinity']!=d['housekeeping']:raise ValueError('supervisor affinity')
    promoted=read(directory/'native/promoted.json')
    if promoted['pid']!=native['pid']:raise ValueError('same PID exec')
    for role in ('primary','rescue'):
        receipt=read(directory/(role+'.registered.json'))
        if receipt['identity']!=native or receipt['at']>promoted['before']:raise ValueError('registration order')
    if result['native_stop_at']>d['stop_by']:raise ValueError('stop deadline')
    original=read(obs/'decisions.json')
    from dudect_candidate import significant as old_significant
    return dict(id=unit['id'],arm=unit['arm'],cases=len(bindings),looks=len(decisions),
                replay_matches=True,original_detections=sum(old_significant(t) for x in original for t in x['tests']),
                assessment=read(obs/'result.json')['assessment'],scheduler_receipts=len(scheduler))


if __name__=='__main__':
    base=Path(sys.argv[1]);out=Path(sys.argv[2]);rows=[]
    for directory in sorted(base.glob('*/evidence')):
        if not read(directory/'result.json').get('complete'):continue
        row=audit(directory);rows.append(row);print(row['id'],'verified',flush=True)
    out.write_text(json.dumps({'results':rows,'cases':sum(r['cases'] for r in rows),
        'looks':sum(r['looks'] for r in rows),'ci_admission':False},indent=2)+'\n')
