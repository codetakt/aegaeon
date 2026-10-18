"""Build frozen control/signal artifacts before the owned scheduler comparison."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(HERE.parent))
sys.path.insert(0,str(ROOT/'scripts/ci'))
from build_ct_preparation import build as overlay
from prepare_ct_preparation import selftests, invocation_selftests
from ct_preparation_plan import package_unit, overlay_unit
from prepare_dudect_hosted import build
import runtime as rt

BASE='f3c3e2adc0480a076ce7ea986dcc82451ba7dc43'


def prepare(output, slot):
    if slot not in (1,2):raise ValueError('unknown opportunity')
    output.mkdir(parents=True)
    (output/'selftests').mkdir()
    source='git+'+ROOT.as_uri()+'?rev='+BASE+'&shallow=1'
    baseline=rt.read(ROOT/'scripts/ci/dudect-hosted-reliability.json')['packages']
    analysis=build('dudect-analysis',output,source)
    if str(analysis)!=baseline['analysis_package']['path']:raise ValueError('analysis package differs')
    python=Path(subprocess.check_output(['nix','eval','--raw',source+'#dudect-analysis.python'],text=True).strip())/'bin/python'
    packages={}
    units={}
    for compiler in ('gcc','clang'):
        for suite in ('nix','legacy'):
            key=compiler+'-'+suite
            package=build('dudect-analysis-native-'+key,output,source)
            expected=baseline['native_packages'][key]
            if str(package)!=expected['path'] or rt.digest(package/'package.json')!=expected['index_sha256']:
                raise ValueError('native package differs')
            packages[key]=package
        sig=overlay(packages[compiler+'-nix'],output/'builds'/compiler/'signal','signal')
        test=overlay(packages[compiler+'-nix'],output/'builds'/compiler/'selftest','selftest')
        selftests(test['binary'],output/'builds'/compiler/'selftest')
        own={suite:package_unit(packages[compiler+'-'+suite],'dudect_controls') for suite in ('nix','legacy')}
        for dose in (0,16):own['signal'+str(dose)]=overlay_unit(sig,['ct_eq_32','ct_eq_64','ct_eq_128'],'uniform',dose)
        invocation_selftests(own,output/'selftests'/compiler)
        for name,u in own.items():units[compiler+'-'+name]=u
    shutil.copytree(analysis,output/'packages/analysis')
    for key,package in packages.items():shutil.copytree(package,output/'packages'/key)
    closure=subprocess.check_output(['nix','path-info','--recursive','--json',str(analysis),*map(str,packages.values())],text=True)
    (output/'closure.json').write_text(closure)
    packet='owned-scheduler-'+os.environ['GITHUB_RUN_ID']+'-'+str(slot)
    schedule=[]
    keys=[c+'-'+s for c in ('gcc','clang') for s in ('nix','legacy','signal0','signal16')]
    if slot==2:keys.reverse()
    for arm in (('A','B') if slot==1 else ('B','A')):
        for key in keys:
            u=units[key].copy();name=arm+'-'+key
            u.update(id=name,packet=packet,analysis=str(analysis/'libexec/dudect-analysis'),
                arm=arm,maximum_seconds=150,timing=True)
            code='import sys,json;sys.path.insert(0,sys.argv[1]);from analysis_contract import identity;print(json.dumps(identity("interval-only",sys.argv[2],sys.argv[3])))'
            u['analysis_identity']=json.loads(subprocess.check_output([str(python),'-B','-c',code,u['analysis'],packet,name],text=True))
            schedule.append(u)
    rt.write(output/'plan.json',dict(slot=slot,packet=packet,units=schedule,maximum_seconds=1200,gap_seconds=10,
        plan=dict(replacement_trials=0,user='runner',native=2,housekeeping=[0,1],rttime=[60000000,90000000],
                  path='/usr/bin:/bin',python=str(python),implementation={p.name:rt.digest(p) for p in sorted(HERE.glob('*.py'))})))
    (output/'plan.sha256').write_text(rt.digest(output/'plan.json')+'\n')


if __name__=='__main__':
    from hosted import binding,admit
    binding();admit(int(sys.argv[2]))
    prepare(Path(sys.argv[1]).resolve(),int(sys.argv[2]))
