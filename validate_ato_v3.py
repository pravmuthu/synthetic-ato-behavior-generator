#!/usr/bin/env python3
"""Streaming consistency and simulator-shortcut audit for the V3.2 synthetic ATO benchmark.

No external Python dependencies. Completes on large CSVs with bounded event memory.
"""
import argparse
import csv
import json
import re
from collections import Counter,defaultdict
from datetime import datetime
from pathlib import Path

PUBLIC_FILES=('account_reference.csv','role_assignments.csv','sessions.csv','authentication_events.csv','activity_events.csv')
RESTRICTED_FIELDS={'is_successful_ato','true_objective','lookalike_type','actor_authorized','access_mechanism',
                   'variant','primary_objective','episode_id','action_completed','device_was_familiar_at_login',
                   'first_harmful_action_utc','observed_label'}
OBJ_ACTION={'security_takeover':('account_security','recovery_method'),
            'financial_redirection':('update','payment_destination'),
            'access_control_change':('access_control','delegated_user'),
            'sensitive_data_access':('export','sensitive_records')}
CHECKPOINTS=(30,60,300)

def utc(s):
    return datetime.fromisoformat(s.replace('Z','+00:00'))

def rows(path):
    with path.open(newline='',encoding='utf-8') as f:
        yield from csv.DictReader(f)

def columns(path):
    with path.open(newline='',encoding='utf-8') as f:
        return set(next(csv.reader(f)))

def audit(data):
    errors=[];warnings=[];counts=Counter()
    expected=(*PUBLIC_FILES,'episode_ground_truth.csv','session_ground_truth.csv','observed_training_labels.csv','generation_manifest.json')
    missing=[f for f in expected if not (data/f).is_file()]
    if missing:return {'passed':False,'errors':['Missing: '+', '.join(missing)]}
    for file in PUBLIC_FILES:
        unexpected=RESTRICTED_FIELDS & columns(data/file)
        if unexpected:errors.append('Leaked ground-truth columns in '+file+': '+','.join(sorted(unexpected)))
    manifest=json.loads((data/'generation_manifest.json').read_text())
    platforms=set(manifest['configuration']['platform'] for _ in [0])
    accts={a['account_id']:a for a in rows(data/'account_reference.csv')}
    roles={(r['account_id'],r['user_id']):r['role'] for r in rows(data/'role_assignments.csv')}
    sessions={}
    for s in rows(data/'sessions.csv'):
        sid=s['session_id']
        if sid in sessions:errors.append('Duplicate session ID: '+sid)
        if not re.fullmatch(r'SES-[0-9a-f]{16}',sid):errors.append('Non-opaque session ID '+sid)
        if s['account_id'] not in accts or (s['account_id'],s['user_id']) not in roles:
            errors.append('Orphan account or user in session '+sid)
        elif s['application_profile']!=accts[s['account_id']]['application_profile']:
            errors.append('Profile mismatch '+sid)
        sessions[sid]=s
        counts['sessions']+=1
    truth={}
    for t in rows(data/'session_ground_truth.csv'):
        sid=t['session_id']
        if sid in truth:errors.append('Duplicate truth '+sid)
        truth[sid]=t
        counts['true_ato']+=t['is_successful_ato']=='true'
    if set(truth)!=set(sessions):errors.append('Session truth does not match public sessions')
    epi={}
    epi_by_actor=Counter(); objective_platform=Counter(); obj_variant=Counter()
    for e in rows(data/'episode_ground_truth.csv'):
        sid=e['session_id'];epi[sid]=e
        epi_by_actor[e['actor_authorized']]+=1
        objective_platform[(e['primary_objective'],e['application_profile'],e['actor_authorized'])]+=1
        obj_variant[(e['primary_objective'],e['variant'],e['actor_authorized'])]+=1
        if sid not in sessions:errors.append('Episode with invalid session '+sid)
        if sid in truth and (truth[sid]['is_successful_ato']=='true')!=(e['actor_authorized']=='false'):
            errors.append('Inconsistent authorized/ATO status '+sid)
    counts['episodes']=len(epi)
    observed=Counter()
    for x in rows(data/'observed_training_labels.csv'):
        if x['session_id'] not in sessions:errors.append('Observed label with missing session')
        if x['observed_label']=='confirmed_ato':
            observed['confirmed_ato']+=1
            if truth[x['session_id']]['is_successful_ato']!='true':errors.append('Non-ATO marked confirmed')
        else:observed['unlabeled']+=1
    if sum(observed.values())!=len(sessions):errors.append('Observed training labels incomplete')

    auth_success={};auth_fails=defaultdict(list)
    all_successes=[]
    for a in rows(data/'authentication_events.csv'):
        sid=a['session_id']
        if sid not in sessions:errors.append('Orphan auth '+sid);continue
        if not re.fullmatch(r'DEV-[0-9a-f]{16}',a['device_id']):errors.append('Non-opaque device ID '+sid)
        if a['login_successful']=='true':
            if sid in auth_success:errors.append('Multiple successful logins '+sid)
            auth_success[sid]=a
            all_successes.append((a['event_ts_utc'],sid,a['device_fingerprint_id'],a['ip_address']))
            counts['successful_logins']+=1
            if a['event_ts_utc']!=sessions[sid]['started_at_utc']:errors.append('Login time mismatch '+sid)
        else:
            auth_fails[sid].append(a['event_ts_utc'])
            counts['failed_logins']+=1
    if set(auth_success)!=set(sessions):errors.append('Some sessions have no successful login')
    offsets=Counter()
    for sid,failures in auth_fails.items():
        success=utc(auth_success[sid]['event_ts_utc'])
        for ts in failures:
            d=(success-utc(ts)).total_seconds()
            if d<=0:errors.append('Failed login not before success '+sid)
            offsets[int(d)]+=1
    if len(offsets)<10:warnings.append('Limited failed-login timing variation')

    # Recompute familiarity exclusively from PRECEDING successful logins.
    devs=defaultdict(set);ips=defaultdict(set)
    devfam={};ipfam={};familiar_counts=Counter()
    for ts,sid,fp,ip in sorted(all_successes):
        uid=sessions[sid]['user_id']
        devfam[sid]=fp in devs[uid];ipfam[sid]=ip in ips[uid]
        devs[uid].add(fp);ips[uid].add(ip)
        if sid in epi:
            if str(devfam[sid]).lower()!=epi[sid]['device_was_familiar_at_login']:
                errors.append('Device familiarity mismatch '+sid)
            if str(ipfam[sid]).lower()!=epi[sid]['ip_was_familiar_at_login']:
                errors.append('IP familiarity mismatch '+sid)
            if epi[sid]['actor_authorized']=='false':familiar_counts[('ato','familiar' if devfam[sid] else 'new')]+=1
            else:familiar_counts[('benign','familiar' if devfam[sid] else 'new')]+=1
    if not all(familiar_counts[('ato',k)]>0 and familiar_counts[('benign',k)]>0 for k in ('familiar','new')):
        warnings.append('One device familiarity category absent from attack or lookalike cases')

    # Activity rows are written consecutively for each session (not necessarily chronological between sessions).
    # Keep only one session's event sequence in memory at a time.
    prev_sid=None;seq=[];per_session_event_count=Counter()
    action_counts=Counter(); action_candidates=Counter()
    early_counts=Counter(); highrisk_presence=Counter()
    same_prefix_across_actor=defaultdict(Counter)
    def check_sequence(sid,items):
        if not items:return
        if sid not in sessions:
            errors.append('Orphan activity session '+sid);return
        start=utc(sessions[sid]['started_at_utc'])
        stamps=[utc(e['event_ts_utc']) for e in items]
        if stamps!=sorted(stamps) or stamps[0]<start:
            errors.append('Activity timeline violates session start/order '+sid)
        if [int(e['event_order']) for e in items]!=list(range(1,len(items)+1)):
            errors.append('Activity event order invalid '+sid)
        per_session_event_count['with_activity']+=1
        isato=truth[sid]['is_successful_ato']=='true'
        actor='ato' if isato else 'legit'
        # Summaries at specified checkpoints; never count future events.
        for cutoff in CHECKPOINTS:
            pre=[e for e,t in zip(items,stamps) if (t-start).total_seconds()<=cutoff]
            early_counts[(cutoff,actor)]+=len(pre)
            if any(e['sensitivity']=='sensitive' for e in pre):highrisk_presence[(cutoff,actor)]+=1
        if sid in epi:
            e=epi[sid];oc=e['primary_objective'];categ,res=OBJ_ACTION[oc]
            matching=[a for a in items if a['category']==categ and a['resource_type']==res]
            if (bool(matching)!= (e['action_attempted']=='true')):
                errors.append('Action attempt mismatch '+sid)
            completed=[a for a in matching if a['outcome']=='success']
            if bool(completed)!=(e['action_completed']=='true'):
                errors.append('Action completion mismatch '+sid)
            if e['first_objective_action_utc']!=(matching[0]['event_ts_utc'] if matching else ''):
                errors.append('First action time mismatch '+sid)
            harmed= completed[0]['event_ts_utc'] if isato and completed else ''
            if e['first_harmful_action_utc']!=harmed:errors.append('First harm timestamp mismatch '+sid)
            action_counts[(oc,'ato' if isato else 'benign',e['variant'])]+=1
            # first 3 actions should overlap across benign vs attackers in at least some scenarios.
            prefix='>'.join(a['category'] for a in items[:3])
            same_prefix_across_actor[oc][(actor,prefix)]+=1
        for e in items:
            if e['session_id']!=sid or e['account_id']!=sessions[sid]['account_id'] or e['user_id']!=sessions[sid]['user_id']:
                errors.append('Activity membership mismatch '+sid)
            if e['category']=='access_control' or (e['resource_type']=='payment_destination' and e['verb']=='update'):
                if roles.get((e['account_id'],e['user_id']))!='admin' and e['outcome']=='success':
                    errors.append('Unauthorized permissions success '+sid)
    for e in rows(data/'activity_events.csv'):
        sid=e['session_id'];counts['activity_events']+=1
        if prev_sid is not None and sid!=prev_sid:
            check_sequence(prev_sid,seq)
            seq=[]
        seq.append(e);prev_sid=sid
    if prev_sid is not None:check_sequence(prev_sid,seq)
    if per_session_event_count['with_activity']!=len(sessions):errors.append('Sessions missing events or event rows not grouped by session')
    if len(set(epi))!=len(epi):errors.append('Duplicate episodes')
    for obj in OBJ_ACTION:
        for k in ('true','false'):
            if any(obj_variant[(obj,v,k)]==0 for v in ('completed','blocked','quiet')):
                errors.append('Objective/actor missing variant '+obj+'/'+k)
        if manifest['configuration']['platform']=='all' and manifest['configuration']['cases_per_objective']>=3:
            for p in ('marketplace','business_banking','saas'):
                for actor in ('true','false'):
                    if objective_platform[(obj,p,actor)]==0:errors.append(f'Missing {obj}/{p}/{actor}')
    country_by_actor=defaultdict(set);device_by_actor=defaultdict(set);network_by_actor=defaultdict(set)
    for sid,a in auth_success.items():
        actor='ato' if truth[sid]['is_successful_ato']=='true' else 'legit'
        country_by_actor[actor].add(a['country']);device_by_actor[actor].add(a['device_type']);network_by_actor[actor].add(a['network_type'])
    for feature,name in [(country_by_actor,'country'),(device_by_actor,'device_type'),(network_by_actor,'network_type')]:
        outside=feature['ato']-feature['legit']
        if outside:errors.append(f'Attacker-only {name} categories: {sorted(outside)}')
    # Findings are model-agnostic tests, NOT evidence of absence of all predictive shortcuts.
    if epi_by_actor['false']!=epi_by_actor['true']:
        warnings.append('ATO and deliberately constructed benign lookalike counts differ')
    pos=counts['true_ato']
    if pos<100:warnings.append('Too few positive examples for robust ML confidence intervals')
    warnings.append('Synthetic-generator-specific templates and statistical artifacts may remain. External validity is not established.')
    return {
        'passed':not errors,
        'counts':dict(counts),'ground_truth':dict(epi_by_actor),
        'observed_training_labels':dict(observed),
        'ato_prevalence_per_successful_login':round(pos/max(1,counts['sessions']),7),
        'objective_platform_counts':{'|'.join(k):v for k,v in sorted(objective_platform.items())},
        'objective_variant_counts':{'|'.join(k):v for k,v in sorted(obj_variant.items())},
        'device_familiarity':{'|'.join(k):v for k,v in sorted(familiar_counts.items())},
        'failed_login_unique_offsets':len(offsets),
        'actor_category_overlap':{'country':sorted(country_by_actor['ato']&country_by_actor['legit']),
                                  'device_type':sorted(device_by_actor['ato']&device_by_actor['legit']),
                                  'network_type':sorted(network_by_actor['ato']&network_by_actor['legit'])},
        'events_by_checkpoint':{'|'.join(map(str,k)):v for k,v in sorted(early_counts.items())},
        'sensitive_event_session_presence_by_checkpoint':{'|'.join(map(str,k)):v for k,v in sorted(highrisk_presence.items())},
        'checks':['Public schema excludes explicit ground-truth labels','Session/auth/event identifiers match',
                  'Timestamps respect login visibility and event order','Account roles and application profiles consistent',
                  'Ground-truth action outcomes and event times match','Reconstructed device/IP familiarity checked',
                  'No attacker-exclusive device, country, or network categories'],
        'warnings':warnings,'errors':errors[:100]
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--data',required=True)
    p.add_argument('--report',default=None)
    a=p.parse_args()
    res=audit(Path(a.data))
    if a.report:
        dest=Path(a.report);dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(json.dumps(res,indent=2)+'\n',encoding='utf-8')
    print(('PASS' if res['passed'] else 'FAIL')+' ATO V3.2 validation')
    print('counts:',res.get('counts'))
    print('warnings:',res.get('warnings'))
    print('errors:',res.get('errors'))
    if not res['passed']:raise SystemExit(1)
if __name__=='__main__':main()
