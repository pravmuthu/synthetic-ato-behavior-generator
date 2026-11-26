#!/usr/bin/env python3
"""Descriptive overlap/shortcut audit for the synthetic ATO V3.2 benchmark.

Outputs experimental diagnostics, not claims about realistic populations or ML accuracy.
Pure standard library; scans activity events without materializing their full table.
"""
import argparse,csv,json,statistics
from collections import Counter,defaultdict
from datetime import datetime
from pathlib import Path

def stream(path):
    with open(path,newline='',encoding='utf-8') as f:
        yield from csv.DictReader(f)

def when(s):return datetime.fromisoformat(s.replace('Z','+00:00'))
def desc(vals):
    vals=sorted(vals)
    if not vals:return None
    return {'n':len(vals),'median':round(statistics.median(vals),1),'mean':round(statistics.mean(vals),1),
            'p90':vals[int(.9*(len(vals)-1))],'min':min(vals),'max':max(vals)}

def audit(root):
    accounts={r['account_id']:r for r in stream(root/'account_reference.csv')}
    sessions={r['session_id']:r for r in stream(root/'sessions.csv')}
    truth={r['session_id']:r['is_successful_ato']=='true' for r in stream(root/'session_ground_truth.csv')}
    eps={r['session_id']:r for r in stream(root/'episode_ground_truth.csv')}
    login={r['session_id']:r for r in stream(root/'authentication_events.csv') if r['login_successful']=='true'}
    per=defaultdict(lambda:{'n':0,'b30':0,'b60':0,'b300':0,'s30':False,'s60':False,'s300':False,
                            'w60':False,'w300':False,'seq':[],'last':0})
    for e in stream(root/'activity_events.csv'):
        sid=e['session_id'];s=per[sid]
        t=int((when(e['event_ts_utc'])-when(sessions[sid]['started_at_utc'])).total_seconds())
        s['n']+=1;s['last']=t
        if len(s['seq'])<5:s['seq'].append(e['category'])
        for cutoff,key in [(30,'b30'),(60,'b60'),(300,'b300')]:
            if t<=cutoff:s[key]+=1
        if e['sensitivity']=='sensitive':
            for cutoff,key in [(30,'s30'),(60,'s60'),(300,'s300')]:
                if t<=cutoff:s[key]=True
        if (e['category'] in ('account_security','access_control','export') or
            (e['resource_type']=='payment_destination' and e['verb']=='update')):
            for cutoff,key in [(60,'w60'),(300,'w300')]:
                if t<=cutoff:s[key]=True
    hist=defaultdict(lambda:defaultdict(list));prefixes=defaultdict(Counter)
    attack_seq=Counter();benign_seq=Counter();by_plat=Counter()
    for sid,s in per.items():
        group='ato' if truth[sid] else ('lookalike' if sid in eps else 'routine')
        for k in ('n','last','b30','b60','b300'):
            hist[group][k].append(s[k])
        if group!='routine':
            seq='>'.join(s['seq'][:3])
            prefixes[group][seq]+=1
            by_plat[(group,sessions[sid]['application_profile'])]+=1
    report={'counts':{'sessions':len(sessions),'positive_ato':sum(truth.values()),'matched_benign':len(eps)-sum(truth.values()),
                      'event_rows':sum(s['n'] for s in per.values())},
            'by_platform':{'|'.join(k):v for k,v in sorted(by_plat.items())},
            'session_behavior_summaries':{g:{k:desc(vals) for k,vals in d.items()} for g,d in hist.items()},
            'early_category_prefix_overlap':{},'simple_rule_diagnostics':[]}
    common=set(prefixes['ato']) & set(prefixes['lookalike'])
    report['early_category_prefix_overlap']={'ATO_distinct_prefixes':len(prefixes['ato']),
                                               'benign_distinct_prefixes':len(prefixes['lookalike']),
                                               'shared_distinct_prefixes':len(common),
                                               'ATO_sessions_with_a_prefix_seen_in_lookalikes':sum(n for seq,n in prefixes['ato'].items() if seq in common),
                                               'benign_sessions_with_a_prefix_seen_in_ATO':sum(n for seq,n in prefixes['lookalike'].items() if seq in common)}
    # Rebuild device/IP histories from strictly earlier SUCCESSFUL logins.
    dev_prior=defaultdict(set);ip_prior=defaultdict(set);is_new_device={};is_new_ip={}
    for sid in sorted(sessions,key=lambda k:(sessions[k]['started_at_utc'],k)):
        a=login[sid];uid=sessions[sid]['user_id']
        is_new_device[sid]=a['device_fingerprint_id'] not in dev_prior[uid]
        is_new_ip[sid]=a['ip_address'] not in ip_prior[uid]
        dev_prior[uid].add(a['device_fingerprint_id']);ip_prior[uid].add(a['ip_address'])
    rules={
        'new_device_at_login':lambda sid:is_new_device[sid],
        'new_IP_at_login':lambda sid:is_new_ip[sid],
        'away_from_home_country':lambda sid:login[sid]['country']!=accounts[sessions[sid]['account_id']]['home_country'],
        'bot_device':lambda sid:login[sid]['device_type']=='bot',
        'hosting_network':lambda sid:login[sid]['network_type']=='hosting',
        'sensitive_event_by_60s':lambda sid:per[sid]['s60'],
        'sensitive_write_export_by_60s':lambda sid:per[sid]['w60'],
        'sensitive_event_by_300s':lambda sid:per[sid]['s300'],
        'sensitive_write_export_by_300s':lambda sid:per[sid]['w300'],
    }
    npos=sum(truth.values());nneg=len(truth)-npos
    for name,fn in rules.items():
        tp=sum(fn(sid) for sid in sessions if truth[sid])
        fp=sum(fn(sid) for sid in sessions if not truth[sid])
        look_fp=sum(fn(sid) for sid in eps if not truth[sid])
        report['simple_rule_diagnostics'].append({'rule':name,'flagged':tp+fp,'TP':tp,'FP':fp,'recall':round(tp/max(npos,1),4),
                                                   'precision':round(tp/max(tp+fp,1),4),'false_positives_per_1000_legitimate_sessions':round(fp/max(nneg,1)*1000,3),
                                                   'benign_lookalikes_flagged':look_fp})
    report['limitations']=['Diagnostics on a synthetic generated world, not predictive ML generalization metrics.',
                           'Overlap in simple signals does not prove there are no multi-feature shortcut combinations.',
                           'No validation against empirical human or attacker telemetry.']
    return report

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--data',required=True);p.add_argument('--report',default=None)
    a=p.parse_args();root=Path(a.data)
    rep=audit(root)
    path=Path(a.report) if a.report else root/'behavioral_overlap_audit.json'
    path.write_text(json.dumps(rep,indent=2)+'\n',encoding='utf-8')
    print('Behavioral overlap audit complete:',path)
    print('Early prefix overlap:',rep['early_category_prefix_overlap'])
    for r in rep['simple_rule_diagnostics']:
        print(r['rule'],f"recall={r['recall']:.3f}",f"precision={r['precision']:.3f}")
if __name__=='__main__':main()
