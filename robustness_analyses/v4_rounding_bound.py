#!/usr/bin/env python3
"""Section 4.4: bound on the out-of-spec CVSS v4.0. Scores the four affected
simulation scenarios with each out-of-spec value rounded down (as reported) and up.
Requires: pip install cvss"""
from cvss import CVSS4
S = {'CVE-2016-5804': dict(AV='N',AC='H',AT='P',PR='L',UI='N',VC='L',VI='H',VA='N',SC='M',SI='H',SA='N'),
     'CVE-2012-6437': dict(AV='N',AC='H',AT='P',PR='L',UI='N',VC='H',VI='H',VA='H',SC='M',SI='M',SA='H'),
     'CVE-2023-22784': dict(AV='N',AC='M',AT='N',PR='N',UI='N',VC='M',VI='M',VA='M',SC='L',SI='L',SA='L'),
     'CVE-2024-10313': dict(AV='N',AC='L',AT='P',PR='H',UI='R',VC='H',VI='H',VA='M',SC='N',SI='N',SA='N')}
DOWN = {'AC': {'M': 'H'}, 'UI': {'R': 'A'}, 'imp': {'M': 'L'}}
UP = {'AC': {'M': 'L'}, 'UI': {'R': 'P'}, 'imp': {'M': 'H'}}
def fix(m, r):
    return {k: (r['AC'].get(v, v) if k == 'AC' else r['UI'].get(v, v) if k == 'UI'
                else r['imp'].get(v, v) if k in ('VC','VI','VA','SC','SI','SA') else v) for k, v in m.items()}
for n, m in S.items():
    d, u = (float(CVSS4('CVSS:4.0/' + '/'.join(f'{k}:{x}' for k, x in fix(m, r).items())).base_score) for r in (DOWN, UP))
    print(f'{n}: down {d:.1f}  up {u:.1f}  diff {u-d:+.1f}')
