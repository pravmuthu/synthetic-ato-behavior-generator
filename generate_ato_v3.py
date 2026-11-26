#!/usr/bin/env python3
"""Synthetic multi-application ATO research generator, v3.2.

CAUTION: Synthetic observations encode simulated hypotheses, not empirical estimates
of fraud, user behavior, attack prevalence, or model effectiveness.

Designed for Python 3.11+, using only the Python standard library.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import random
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = '3.2.0-research-simulation'
START = datetime(2026, 1, 1, tzinfo=timezone.utc)
OBJECTIVES = ('security_takeover','financial_redirection','access_control_change','sensitive_data_access')
PLATFORMS = ('marketplace','business_banking','saas')
COUNTRIES = {'US':(-6,('Austin','Chicago','Seattle','Boston','Atlanta','San Francisco')),
             'GB':(0,('London','Manchester','Bristol')),
             'IN':(5.5,('Bengaluru','Mumbai','Chennai','Delhi')),
             'DE':(1,('Berlin','Munich','Hamburg')),
             'CA':(-5,('Toronto','Vancouver','Ottawa')),
             'AU':(10,('Sydney','Melbourne')),
             'JP':(9,('Tokyo','Osaka')),
             'FR':(1,('Paris','Lyon'))}
COUNTRY_WEIGHTS = (42,14,12,11,9,6,4,2)
EVENTS = {
 'home':('navigation','view','dashboard','ordinary'),
 'routine':('read','view','work_queue','ordinary'),
 'routine_detail':('read','view','work_item','ordinary'),
 'routine_write':('update','update','work_item','ordinary'),
 'profile':('navigation','view','profile','ordinary'),
 'security':('navigation','view','security_settings','sensitive'),
 'security_read':('read','view','recovery_methods','sensitive'),
 'security_write':('account_security','update','recovery_method','sensitive'),
 'financial':('read','view','financial_history','ordinary'),
 'destination':('read','view','payment_destination','sensitive'),
 'financial_write':('update','update','payment_destination','sensitive'),
 'team':('navigation','view','user_management','ordinary'),
 'team_read':('read','view','permissions','sensitive'),
 'role_write':('access_control','create','delegated_user','sensitive'),
 'search':('search','search','records','ordinary'),
 'record':('read','view','sensitive_record','sensitive'),
 'export':('export','export','sensitive_records','sensitive'),
 'help':('navigation','view','support','ordinary'),
 'notification':('read','view','notifications','ordinary'),
 'settings':('navigation','view','preferences','ordinary'),
}
# Common action names across domains. Each profile additionally supplies specific raw labels.
OBJECTIVE_PATHS = {
 'security_takeover':(['profile','security','security_read'],'security_write'),
 'financial_redirection':(['financial','destination'],'financial_write'),
 'access_control_change':(['team','team_read'],'role_write'),
 'sensitive_data_access':(['search','record'],'export'),
}
ROUTINE_PATHS = [
 ['home','routine','routine_detail','routine_write'],
 ['home','notification','routine','routine_detail'],
 ['home','search','record','routine'],
 ['home','routine','search','record'],
 ['home','profile','settings','routine'],
 ['home','financial','routine','routine_detail'],
 ['home','team','routine','notification'],
 ['home','help','routine','routine_detail'],
 ['home','security','security_read','routine'],
 ['home','destination','financial','routine'],
]
AUTH_COLUMNS = ['auth_event_id','session_id','event_ts_utc','login_successful','device_id','device_fingerprint_id',
                'ip_address','country','city','network_type','device_type','os_family','browser_family',
                'mfa_method','mfa_result']
SESSION_COLUMNS = ['session_id','account_id','user_id','application_profile','started_at_utc']
EVENT_COLUMNS = ['event_id','session_id','account_id','user_id','event_ts_utc','event_order','category',
                 'verb','resource_type','resource_id','sensitivity','outcome','raw_event_type','application_profile']
TRUTH_COLUMNS = ['session_id','is_successful_ato','episode_id','true_objective','lookalike_type']
EP_COLUMNS = ['episode_id','session_id','actor_authorized','primary_objective','access_mechanism','variant',
              'action_attempted','action_completed','first_objective_action_utc','first_harmful_action_utc',
              'device_was_familiar_at_login','ip_was_familiar_at_login','application_profile']


def iso(t:datetime)->str:
    return t.isoformat(timespec='seconds').replace('+00:00','Z')


def csv_writer(path, cols):
    f=path.open('w',newline='',encoding='utf-8')
    w=csv.DictWriter(f,fieldnames=cols,extrasaction='raise',lineterminator='\n')
    w.writeheader()
    return f,w


def unique_id(rng, prefix):
    return '%s-%016x'%(prefix,rng.getrandbits(64))


def choose(rng, choices, weights=None):
    return rng.choices(choices,weights=weights,k=1)[0]


def sample_location(rng, country=None):
    country=country or choose(rng,list(COUNTRIES),COUNTRY_WEIGHTS)
    return country,rng.choice(COUNTRIES[country][1])


def parse_args():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', default='ato_v3_data')
    p.add_argument('--seed',type=int,default=42)
    p.add_argument('--accounts',type=int,default=2500)
    p.add_argument('--days',type=int,default=90)
    p.add_argument('--cases-per-objective',type=int,default=90,
                   help='successful ATO sessions per objective; matching benign look-alikes are also generated')
    p.add_argument('--platform',choices=['all',*PLATFORMS],default='all')
    p.add_argument('--stealth',type=float,default=0.5,help='0..1: more familiar infrastructure/ordinary navigation')
    p.add_argument('--benign-complexity',type=float,default=0.5,help='0..1: more legitimate hard negatives')
    p.add_argument('--unlabeled-rate',type=float,default=0.05,
                   help='fraction of positives masked in observed training labels ONLY')
    args=p.parse_args()
    if not(0<=args.stealth<=1 and 0<=args.benign_complexity<=1 and 0<=args.unlabeled_rate<=1):
        p.error('stealth, benign-complexity and unlabeled-rate must all be 0..1')
    if args.days<14 or args.accounts<40 or args.cases_per_objective<3:
        p.error('use days>=14, accounts>=40, cases-per-objective>=3')
    nprofiles=3 if args.platform=='all' else 1
    # Prefer one episode per independent account; enforce it so case counts mean independent compromised accounts.
    if args.accounts < 8*args.cases_per_objective*nprofiles/(3 if nprofiles==3 else 1):
        p.error('Not enough accounts for distinct attack AND benign episode accounts. Increase --accounts or reduce --cases-per-objective.')
    return args


class SyntheticWorld:
    def __init__(self,args):
        self.a=args
        self.r=random.Random(args.seed)
        self.out=Path(args.out)
        self.out.mkdir(parents=True,exist_ok=True)
        profiles=json.loads((Path(__file__).parent/'platform_profiles.json').read_text(encoding='utf-8'))
        self.platforms=list(PLATFORMS) if args.platform=='all' else [args.platform]
        self.raw={p:profiles[p]['raw_event_types'] for p in self.platforms}
        self.users=[]
        self.accounts=[]
        self.by_profile=defaultdict(list)
        self.schedules=[]
        self.registered_ips={}  # ip -> geo tuple, prevents geolocation contradictions
        self.next_ip=0
        self.used_accounts=set()
        self.observed_devices=defaultdict(set)
        self.observed_ips=defaultdict(set)
        self.known_devices=defaultdict(list)
        self.known_ips=defaultdict(list)
        self.agency_fingerprints=[]
        self.counts=Counter()
        self.platform_objective=Counter()
        self.variant_counts=Counter()
        self.ato_devices=Counter()
        self.ato_ip_familiar=Counter()
        self.fail_offsets=set()
        self.positions=Counter()
        self.device_types_by_ato=defaultdict(Counter)
        self.country_by_ato=defaultdict(Counter)

    def ip(self,geo):
        # RFC 2544 benchmark range 198.18.0.0/15: not assigned to real Internet hosts.
        # Limit loops by ~130,000 possible addresses.
        self.next_ip+=1
        n=(self.next_ip*7919+1777) % 130560
        ip='198.%d.%d.%d'%(18+(n//65280), (n%65280)//255, 1+n%255)
        self.registered_ips[ip]=geo
        return ip

    def device(self,kind=None,fp=None):
        kind=kind or choose(self.r,['desktop','mobile','tablet','bot'],[0.63,0.30,0.06,0.01])
        osname=choose(self.r, {'desktop':['Windows','macOS','Linux'], 'mobile':['Android','iOS'],
                               'tablet':['Android','iPadOS'], 'bot':['Linux','Windows']}[kind])
        browser=choose(self.r, ['Chrome','Edge','Safari','Firefox'] if kind!='bot' else ['Chrome','Firefox','HeadlessChrome'])
        return {'device_id':unique_id(self.r,'DEV'),'fp':fp or unique_id(self.r,'FP'),
                'kind':kind,'os':osname,'browser':browser}

    def build_population(self):
        r=self.r; a=self.a
        acc_file,accw=csv_writer(self.out/'account_reference.csv', ['account_id','application_profile','home_country','home_city','activity_profile','created_at_utc'])
        role_file,rolew=csv_writer(self.out/'role_assignments.csv', ['account_id','user_id','role','valid_from_utc','valid_to_utc'])
        # Assign platform in a mixed order; no platform/label structure in identifiers.
        platforms=(self.platforms* (a.accounts//len(self.platforms)+1))[:a.accounts]
        r.shuffle(platforms)
        for p in platforms:
            aid=unique_id(r,'ACC')
            country,city=sample_location(r)
            activity_profile=choose(r,['busy','steady','occasional'],[0.28,0.35,0.37])
            rec={'account_id':aid,'platform':p,'country':country,'city':city,'profile':activity_profile}
            self.accounts.append(rec)
            accw.writerow({'account_id':aid,'application_profile':p,'home_country':country,'home_city':city,
                          'activity_profile':activity_profile,'created_at_utc':iso(START-timedelta(days=r.randint(5,1000)))})
            nusers=choose(r,[1,2,3,4],[0.2,0.42,0.28,0.10])
            roles=['admin']+[choose(r,['manager','staff'],[.44,.56]) for _ in range(nusers-1)]
            for role in roles:
                uid=unique_id(r,'USR')
                dev=self.device()
                geo=(country,city)
                user={'user_id':uid,'account':rec,'role':role,'geo':geo,'device':dev,
                      'home_ip':self.ip(geo),'mfa':r.random()<0.79, 'visits':0,
                      'activity_multiplier':r.uniform(.65,1.25),
                      'preferred_paths':r.sample(range(len(ROUTINE_PATHS)),3)}
                self.users.append(user)
                self.by_profile[p].append(user)
                rolew.writerow({'account_id':aid,'user_id':uid,'role':role,'valid_from_utc':iso(START),'valid_to_utc':''})
        acc_file.close();role_file.close()
        self.counts['accounts']=len(self.accounts)
        self.counts['users']=len(self.users)

        # Explicit benign shared agency-style device fingerprint and office IP across unrelated accounts.
        # The same fingerprint is observable cross-account but is not an attack-only indicator.
        for plat in self.platforms:
            eligible=[u for u in self.by_profile[plat] if u['role']=='admin']
            r.shuffle(eligible)
            for start in range(0,min(len(eligible)//7*7,max(7,len(eligible)//45*7)),7):
                group=eligible[start:start+7]
                if len(group)<4: continue
                fp=unique_id(r,'FP');geo=group[0]['geo'];ip=self.ip(geo)
                for user in group:
                    user['agency']={'device':self.device('desktop',fp),'ip':ip,'geo':geo}
                self.counts['agency_groups']+=1

    def build_schedule(self):
        r=self.r;a=self.a
        # Each account has ordinary history BEFORE any special case. All users have an early baseline.
        for user in self.users:
            t=START+timedelta(days=r.choice([0,1]),hours=r.randint(5,21),minutes=r.randint(0,59),seconds=r.randint(0,59))
            self.schedules.append((t,user,None,None,None,'baseline'))
            profile=user['account']['profile']
            base={'busy':.67,'steady':.44,'occasional':.14}[profile]*user['activity_multiplier']
            for day in range(a.days):
                weekday=(START+timedelta(days=day)).weekday()<5
                p=min(.89,base*(1 if weekday else .68))
                if r.random()>p: continue
                n=1+(r.random()<(.32 if profile=='busy' else .10))+(r.random()<(.08 if profile=='busy' else .018))
                country=user['geo'][0];tz=COUNTRIES[country][0]
                for _ in range(n):
                    localhour=choose(r,list(range(24)),[.4,.25,.12,.1,.1,.2,.4,1.2,3,5,6,6,5,5,5,5,5,4,3,2,1,.7,.5,.4])
                    t=START+timedelta(days=day,hours=localhour-tz,minutes=r.randint(0,59),seconds=r.randint(0,59))
                    if START<=t<START+timedelta(days=a.days):
                        self.schedules.append((t,user,None,None,None,'routine'))
        # Distinct account per episode across the entire world, covering four objectives × actors × platforms.
        # Shuffled objective/variant pairing avoids fixed scenario blocks.
        for oi,obj in enumerate(OBJECTIVES):
            for i in range(a.cases_per_objective):
                p=self.platforms[(i+oi)%len(self.platforms)]
                variant=('completed','blocked','quiet')[(i%len(self.platforms)+i//len(self.platforms)+oi)%3]
                for actor in ('unauthorized','legitimate'):
                    available=[u for u in self.by_profile[p] if u['account']['account_id'] not in self.used_accounts
                               and (u['role']=='admin' if obj in ('financial_redirection','access_control_change') else True)]
                    if not available:
                        raise RuntimeError('Insufficient independent eligible accounts: increase --accounts')
                    user=r.choice(available)
                    self.used_accounts.add(user['account']['account_id'])
                    day=r.randint(3,a.days-2)
                    country=user['geo'][0];tz=COUNTRIES[country][0]
                    t=START+timedelta(days=day,hours=r.randint(6,22)-tz,minutes=r.randint(0,59),seconds=r.randint(0,59))
                    if not START<=t<START+timedelta(days=a.days):
                        t=START+timedelta(days=day,hours=r.randint(9,16))
                    self.schedules.append((t,user,obj,actor,variant,'episode'))
        # Stable chronological ordering, no sorted output by attack status, IDs are randomly assigned.
        self.schedules.sort(key=lambda x:x[0])
        self.counts['scheduled_sessions']=len(self.schedules)

    def select_login(self,user,kind,actor):
        r=self.r
        is_ato=actor=='unauthorized';a=self.a
        if kind=='baseline':
            device=user['device'];geo=user['geo'];ip=user['home_ip']
            return device,ip,geo,'residential',device['fp'] in self.observed_devices[user['user_id']],ip in self.observed_ips[user['user_id']]
        prev_devs=self.known_devices[user['user_id']]
        prev_ips=self.known_ips[user['user_id']]
        # All categories (familiar, new, agency, unfamiliar VPN) exist in both classes.
        familiar_prob=(0.42+0.46*a.stealth) if is_ato else .81
        base_dev=user['device']
        if prev_devs and r.random()<familiar_prob:
            device=r.choice(prev_devs)
        elif user.get('agency') and r.random()<(.13 if is_ato else .17):
            device=user['agency']['device']
        else:
            device=self.device(kind=choose(r,['desktop','mobile','tablet','bot'],[.59,.32,.07,.02] if is_ato else [.61,.30,.07,.02]))
        prior_dev=device['fp'] in self.observed_devices[user['user_id']]
        home_prob=(.36+.49*a.stealth) if is_ato else .80
        if prev_ips and r.random()<home_prob:
            ip,geo,network=r.choice(prev_ips)
        elif user.get('agency') and r.random()<(.13 if is_ato else .16):
            ip=user['agency']['ip'];geo=user['agency']['geo'];network='office'
        else:
            if r.random()<(.69+.22*a.stealth if is_ato else .86):
                geo=user['geo']
            else:
                c=choose(r,list(COUNTRIES),COUNTRY_WEIGHTS)
                geo=sample_location(r,c)
            ip=self.ip(geo)
            network=choose(r,['residential','mobile','office','vpn','hosting'],[.55,.22,.10,.10,.03] if not is_ato else [.48,.18,.12,.16,.06])
        return device,ip,geo,network,prior_dev,ip in self.observed_ips[user['user_id']]

    def routine_events(self,user):
        r=self.r;a=self.a
        profile=user['account']['profile']
        m= {'busy':r.randint(8,18),'steady':r.randint(5,13),'occasional':r.randint(2,8)}[profile]
        # Bounded correlated navigation fragments, role-constrained operations.
        keys=['home']
        while len(keys)<m:
            if r.random()<.012+.050*a.benign_complexity and user['role']=='admin':
                path=r.choice([['profile','security','security_read','security_write'],
                               ['financial','destination','financial_write'],
                               ['team','team_read','role_write'],
                               ['search','record','record','export']])
            else:
                path=ROUTINE_PATHS[r.choice(user['preferred_paths'])] if r.random()<.74 else r.choice(ROUTINE_PATHS)
            if user['role']!='admin':
                path=[k for k in path if k not in ('financial_write','role_write')]
            keys+=path[1:] if path[0]=='home' else path
        return keys[:m]

    def episode_events(self,user,obj,actor,variant):
        r=self.r;a=self.a
        is_ato=actor=='unauthorized'
        if is_ato and variant=='quiet' and r.random()<.30+.45*a.stealth:
            # Some takeover sessions are observationally indistinguishable from ordinary work.
            # This prevents perfect separability from scripted attack prefixes.
            return [k if k!=OBJECTIVE_PATHS[obj][1] else 'routine_detail' for k in self.routine_events(user)]
        prefix,action=OBJECTIVE_PATHS[obj]
        # Both authorized and unauthorized actors may start with ordinary work.
        path=['home']
        if r.random()<(.48+.36*a.stealth if is_ato else .72):
            path+=r.choice(ROUTINE_PATHS)[1:r.randint(2,4)]
        # Mix ordering of safe exploration, with real prerequisite actions preserved.
        path+=prefix[:]
        for _ in range(r.randint(0,2)):
            path.insert(r.randint(1,len(path)),r.choice(['routine','notification','help','search','routine_detail']))
        if obj=='sensitive_data_access':
            path+=['record']*r.randint(0,4)
        if variant!='quiet':
            path.append(action)
        # Continue sessions after suspicious attempts, including quiet sessions.
        if r.random()<.72:
            path+=r.choice(ROUTINE_PATHS)[1:r.randint(2,5)]
        if r.random()<.3:
            path+=['home','routine','routine_detail']
        return path

    def emit(self):
        a=self.a;r=self.r
        sf,sw=csv_writer(self.out/'sessions.csv',SESSION_COLUMNS)
        af,aw=csv_writer(self.out/'authentication_events.csv',AUTH_COLUMNS)
        ef,ew=csv_writer(self.out/'activity_events.csv',EVENT_COLUMNS)
        tf,tw=csv_writer(self.out/'session_ground_truth.csv',TRUTH_COLUMNS)
        epf,epw=csv_writer(self.out/'episode_ground_truth.csv',EP_COLUMNS)
        obsf,obsw=csv_writer(self.out/'observed_training_labels.csv',['session_id','observed_label'])
        sample_ids=set()
        for idx,(t,user,obj,actor,variant,kind) in enumerate(self.schedules):
            sid=unique_id(r,'SES')
            while sid in sample_ids:sid=unique_id(r,'SES')
            sample_ids.add(sid)
            account=user['account'];p=account['platform'];uid=user['user_id'];aid=account['account_id']
            is_ato=actor=='unauthorized';is_ep=obj is not None
            sw.writerow({'session_id':sid,'account_id':aid,'user_id':uid,'application_profile':p,'started_at_utc':iso(t)})
            self.counts['sessions']+=1
            self.counts[f'sessions_{p}']+=1
            dev,ip,geo,network,prior_dev,prior_ip=self.select_login(user,kind,actor)
            self.device_types_by_ato['ato' if is_ato else 'legit'][dev['kind']]+=1
            self.country_by_ato['ato' if is_ato else 'legit'][geo[0]]+=1
            # Authentication failure probabilities overlap, offsets are non-fixed.
            failprob=(.075+.09*(1-a.stealth)) if is_ato else .09
            if r.random()<failprob:
                nfail=choose(r,[1,2,3,4],[.56,.28,.13,.03])
                offsets=sorted(r.sample(range(8,650),nfail),reverse=True)
                for offset in offsets:
                    mr=choose(r,['not_attempted','failed'],[.76,.24])
                    aw.writerow({'auth_event_id':unique_id(r,'AUTH'),'session_id':sid,'event_ts_utc':iso(t-timedelta(seconds=offset)),
                                 'login_successful':'false','device_id':dev['device_id'],'device_fingerprint_id':dev['fp'],
                                 'ip_address':ip,'country':geo[0],'city':geo[1],'network_type':network,
                                 'device_type':dev['kind'],'os_family':dev['os'],'browser_family':dev['browser'],
                                 'mfa_method':('none' if mr=='not_attempted' else choose(r,['sms','email','authenticator'])),
                                 'mfa_result':mr})
                    self.counts['failed_logins']+=1
                    self.fail_offsets.add(offset)
            # MFA is a user attribute: same user generally has consistent enrollment across sessions.
            mfa_method=choose(r,['sms','email','authenticator'],[.20,.16,.64]) if user['mfa'] and r.random()<.60 else 'none'
            aw.writerow({'auth_event_id':unique_id(r,'AUTH'),'session_id':sid,'event_ts_utc':iso(t),
                         'login_successful':'true','device_id':dev['device_id'],'device_fingerprint_id':dev['fp'],
                         'ip_address':ip,'country':geo[0],'city':geo[1],'network_type':network,
                         'device_type':dev['kind'],'os_family':dev['os'],'browser_family':dev['browser'],
                         'mfa_method':mfa_method,'mfa_result':('success' if mfa_method!='none' else 'not_required')})
            self.counts['successful_logins']+=1
            self.observed_devices[uid].add(dev['fp'])
            self.observed_ips[uid].add(ip)
            if dev not in self.known_devices[uid]:self.known_devices[uid].append(dev)
            ip_entry=(ip,geo,network)
            if ip_entry not in self.known_ips[uid]:self.known_ips[uid].append(ip_entry)
            # Keep device-memory lists bounded per user; historical familiarity remains in observed sets.
            if len(self.known_devices[uid])>8:self.known_devices[uid]=self.known_devices[uid][-8:]
            if len(self.known_ips[uid])>8:self.known_ips[uid]=self.known_ips[uid][-8:]
            keys=self.episode_events(user,obj,actor,variant) if is_ep else self.routine_events(user)
            # Overlapping timing distributions for normal, attack, and legitimate hard negatives.
            now=t;first_objective_action='';first_harm='';action_attempted=False;action_completed=False
            objective_write=OBJECTIVE_PATHS[obj][1] if obj else None
            for order,key in enumerate(keys,1):
                # When stealthy, attackers slow down; legitimately slow reading and bulk activity also occur.
                timebase=choose(r,['fast','typical','slow'],[.14,.61,.25] if not is_ato else
                                [.20*(1-a.stealth)+.10,.52,.18+.20*a.stealth])
                gap={'fast':r.randint(2,15),'typical':r.randint(10,75),'slow':r.randint(65,220)}[timebase]
                if order==1:gap=r.randint(1,17)
                now+=timedelta(seconds=gap)
                category,verb,resource,sensitivity=EVENTS[key]
                is_write=key in ('security_write','financial_write','role_write','export','routine_write')
                if key in ('financial_write','role_write') and user['role']!='admin':
                    # Routine journeys should already enforce it; defensive fallback.
                    outcome='permission_denied'
                elif key==objective_write and is_ep and variant=='blocked':
                    outcome=choose(r,['verification_required','permission_denied'],[.85,.15])
                elif key==objective_write and is_ep and variant=='completed':
                    outcome='success'
                elif is_write and r.random()<.014:
                    outcome='verification_required'
                else:
                    outcome='success'
                if is_ep and key==objective_write:
                    action_attempted=True
                    first_objective_action=first_objective_action or iso(now)
                    if outcome=='success':
                        action_completed=True
                        if is_ato:first_harm=first_harm or iso(now)
                raw=self.raw[p].get(key, self.raw[p].get('routine', 'work_item_viewed'))
                resource_id= '%s-%05d'%(resource.upper().replace(' ','_')[:7],r.randrange(1500))
                ew.writerow({'event_id':unique_id(r,'EVT'),'session_id':sid,'account_id':aid,'user_id':uid,
                             'event_ts_utc':iso(now),'event_order':order,'category':category,'verb':verb,
                             'resource_type':resource,'resource_id':resource_id,'sensitivity':sensitivity,
                             'outcome':outcome,'raw_event_type':raw,'application_profile':p})
                self.counts['activity_events']+=1
                if (now-t).total_seconds()<=30:self.positions['events_by_30s']+=1
                if (now-t).total_seconds()<=60:self.positions['events_by_60s']+=1
                if (now-t).total_seconds()<=300:self.positions['events_by_300s']+=1
            eid=unique_id(r,'EP') if is_ep else ''
            label='true' if is_ato else 'false'
            tw.writerow({'session_id':sid,'is_successful_ato':label,'episode_id':eid,
                         'true_objective':obj or '','lookalike_type':obj if is_ep and not is_ato else ''})
            masked=is_ato and r.random()<a.unlabeled_rate
            obsw.writerow({'session_id':sid,'observed_label':'confirmed_ato' if is_ato and not masked else 'unlabeled'})
            self.counts['masked_ato']+=int(masked)
            if is_ep:
                epw.writerow({'episode_id':eid,'session_id':sid,'actor_authorized':'false' if is_ato else 'true',
                             'primary_objective':obj,'access_mechanism':
                             (('familiar_device' if prior_dev else 'new_device')+'_'+('familiar_ip' if prior_ip else 'new_ip')+'_'+
                              choose(r,['credential_compromise','token_replay','recovery_abuse'],[.63,.26,.11]))
                             if is_ato else 'authorized_access',
                             'variant':variant,'action_attempted':str(action_attempted).lower(),
                             'action_completed':str(action_completed).lower(),
                             'first_objective_action_utc':first_objective_action,
                             'first_harmful_action_utc':first_harm,
                             'device_was_familiar_at_login':str(prior_dev).lower(),
                             'ip_was_familiar_at_login':str(prior_ip).lower(),'application_profile':p})
                self.counts['episodes']+=1
                self.counts['ato_sessions']+=int(is_ato)
                self.counts['benign_lookalikes']+=int(not is_ato)
                self.platform_objective[(p,obj,'ato' if is_ato else 'benign')]+=1
                self.variant_counts[(obj,variant,'ato' if is_ato else 'benign')]+=1
                if is_ato:
                    self.ato_devices['familiar' if prior_dev else 'new']+=1
                    self.ato_ip_familiar['familiar' if prior_ip else 'new']+=1
                    self.counts['ato_objective_completed']+=int(action_completed)
            if idx>0 and idx%50000==0:
                print(f"  {idx:,}/{len(self.schedules):,} sessions; {self.counts['activity_events']:,} events",flush=True)
        for f in (sf,af,ef,tf,epf,obsf):f.close()

    def manifest(self):
        a=self.a
        files=['account_reference.csv','role_assignments.csv','sessions.csv','authentication_events.csv',
               'activity_events.csv','episode_ground_truth.csv','session_ground_truth.csv','observed_training_labels.csv']
        manifest={'generator_version':VERSION,'seed':a.seed,'configuration':{k:v for k,v in vars(a).items() if k!='out'},
                  'start_utc':iso(START),'end_exclusive_utc':iso(START+timedelta(days=a.days)),
                  'counts':dict(sorted(self.counts.items())),
                  'platform_objective_episode_counts':{'|'.join(k):v for k,v in sorted(self.platform_objective.items())},
                  'objective_variant_counts':{'|'.join(k):v for k,v in sorted(self.variant_counts.items())},
                  'ato_device_familiarity':dict(self.ato_devices), 'ato_ip_familiarity':dict(self.ato_ip_familiar),
                  'device_type_counts':{k:dict(v) for k,v in self.device_types_by_ato.items()},
                  'country_counts':{k:dict(v) for k,v in self.country_by_ato.items()},
                  'unique_failed_login_time_offsets':len(self.fail_offsets),
                  'event_checkpoint_counts':dict(self.positions),'output_files':files,
                  'training_label_definition':'confirmed_ato = visible positive; unlabeled = mixture of normal and masked positive',
                  'session_truth_definition':'true only when unauthorized actor controls a successfully authenticated session',
                  'limitations':['All data and event probabilities are synthetic, not calibrated to production.',
                                 'Application profiles are illustrative; no real institution telemetry was used.',
                                 'Attack and benign journeys share templates but remain simulator-dependent.',
                                 'Independent seeds help within-simulator validation, not external validity.',
                                 'Session takeover via mid-session hijacking is out of scope for this version.'],
                  'privacy':'All identities and IPs synthetic; IPs use 198.18.0.0/15 benchmark space.'}
        path=self.out/'generation_manifest.json'
        path.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({'out':str(self.out.resolve()),'counts':manifest['counts'],
                          'ato_device_familiarity':manifest['ato_device_familiarity']},indent=2))


def main():
    a=parse_args()
    world=SyntheticWorld(a)
    world.build_population()
    world.build_schedule()
    world.emit()
    world.manifest()

if __name__=='__main__':main()
