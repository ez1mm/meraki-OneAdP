#!/usr/bin/env python
import asyncio
import os
import logging
import sys
import tqdm.asyncio

import meraki
import meraki.aio

import config 

from argparse import ArgumentParser
from datetime import datetime

BOLD = '\033[1m'
ENDC = '\033[0m'
BLUE = '\033[94m'
CYAN = '\033[96m'
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
PURPLE = '\033[35m'
LGRAY = '\033[97m'
DGRAY = '\033[90m'

async def aGetOrgs(aiodash, org_name=None, org_id=None):
    if org_id:
        result = await aiodash.organizations.getOrganization(org_id)
        logger.debug(f"organizations: {CYAN}{result}{ENDC}")
        return result
    elif org_name:
        organizations = await aiodash.organizations.getOrganizations()
        for result in organizations:
            if result['name'] == org_name and result['api']['enabled']:
                logger.debug(f"organizations: {CYAN}{result}{ENDC}")
                return result
    else:
        organizations = await aiodash.organizations.getOrganizations()
        result = [ org for org in organizations if org['api']['enabled']]
        logger.debug(f"organizations: {CYAN}{result}{ENDC}")
        return result


async def aGetAdpAcls(aiodash, org_id):
    result = await aiodash.organizations.getOrganizationAdaptivePolicyAcls(org_id)
    logger.debug(f"aGetAdpAcls: {CYAN}{result}{ENDC}")
    return 'acls', org_id, result


async def aCreateAdpAcl(aiodash, org_id, name, rules, ip_version, description=None):
    result = await aiodash.organizations.createOrganizationAdaptivePolicyAcl(org_id,
                                                                             name,
                                                                             rules,
                                                                             ip_version,
                                                                             description=description)
    logger.debug(f"aCreateAdpAcl: {BLUE}{result}{ENDC}")


async def aGetAdpGroups(aiodash, org_id):
    result = await aiodash.organizations.getOrganizationAdaptivePolicyGroups(org_id)
    logger.debug(f"aGetAdpGroups: {CYAN}{result}{ENDC}")
    return 'groups', org_id, result


async def aCreateAdpGroups(aiodash, org_id, name, sgt, description=None, policyObjects=[]):
    result = await aiodash.organizations.createOrganizationAdaptivePolicyGroup(org_id,
                                                                               name,
                                                                               sgt,
                                                                               description=description,
                                                                               policyObjects=policyObjects)
    logger.debug(f"aCreateAdpGroups: {BLUE}{result}{ENDC}")


async def aGetAdpPolicies(aiodash, org_id):
    result = await aiodash.organizations.getOrganizationAdaptivePolicyPolicies(org_id)
    logger.debug(f"aGetAdpPolicies: {CYAN}{result}{ENDC}")
    return 'policies', org_id, result


async def aCreateAdpPolicies(aiodash, org_id, src_group, dst_group, acls=[], last_entry_rules="default"):
    result = await aiodash.organizations.createOrganizationAdaptivePolicyPolicy(org_id,
                                                                            src_group,
                                                                            dst_group,
                                                                            acls=acls,
                                                                            last_entry_rules=last_entry_rules)
    logger.debug(f"aCreateAdpPolicies: {BLUE}{result}{ENDC}")


async def aGetAdpSettings(aiodash, org):
    # get the AdP settings, add to the org dict, return org
    result = await aiodash.organizations.getOrganizationAdaptivePolicySettings(org['id'])
    logger.debug(f"getAdpSettings: {CYAN}{result}{ENDC}")
    return 'settings', org, result


async def aGetAdp(aiodash, org_id):
    acls = await aGetAdpAcls(aiodash, org_id)
    policies = await aGetAdpPolicies(aiodash, org_id)
    groups = await aGetAdpGroups(aiodash, org_id)
    return acls, policies, groups


async def adpOrgs(aiodash, golden_org, orgs):
    # get settings for destination networks, then prune for AdP Enabled
    dest_orgs = {}
    if config.ADP_ORGS:
        tasks = [aGetAdpSettings(aiodash, org) for org in orgs 
                 if org['name'] in config.ADP_ORGS]
    else:
        tasks = [aGetAdpSettings(aiodash, org) for org in orgs 
                 if org['id'] != golden_org['id']]

    print(f"Getting Adaptive Policy Networks for {len(tasks)} Destination Orgs")
    for t in tqdm.tqdm(asyncio.as_completed(tasks), total=len(tasks), colour='green'):
        op, org, result = await t
        try:
            dest_orgs[org['id']]
        except:
            dest_orgs[org['id']] = {}

        dest_orgs[org['id']][op] = result
        dest_orgs[org['id']]['org'] = org

    # prune to AdP Enabled 
    # adp_orgs = {key: dest_orgs[key] for key in dest_orgs if dest_orgs[key]['settings']['enabledNetworks']} 
    adp_orgs = {}
    for key in dest_orgs:
        if dest_orgs[key]['settings']['enabledNetworks']:
            adp_orgs[key] = dest_orgs[key]
        else:
            print(f"{RED}AdP disabled for all networks in {YELLOW}{dest_orgs[key]['org']['name']}{RED} skipping{ENDC}")
    logger.debug(f"adp_orgs: {BLUE}{adp_orgs}{ENDC}")
    return adp_orgs


async def aiomain():
    async with meraki.aio.AsyncDashboardAPI(
        api_key=os.getenv("APIKEY"),
        base_url="https://api.meraki.com/api/v1",
        output_log=output_log,
        log_file_prefix=__file__[:-3],
        print_console=True,
        inherit_logging_config=False,
        use_iterator_for_get_pages=False,
        suppress_logging=suppress_logging,
    ) as aiodash:
        
        orgs = await aGetOrgs(aiodash)

        # prep Golden Org data
        for org in orgs:
            if org_name == org['name']:
                golden_org = org

        g_org_acls, g_org_policies, g_org_groups = await aGetAdp(aiodash, golden_org['id'])

        print(f"Adaptive Policy Golden Org: {YELLOW}{org_name} - {golden_org['id']}{ENDC}")
        print(f"Getting Golden Org Groups/ACLs/Policies - One Policy to rule them all...")
        # Ash nazg durbatulûk, ash nazg gimbatul, ash nazg thrakatulûk, agh burzum-ishi krimpatul.
        print(f"Policies: {len(g_org_policies[2])} | Groups: {len(g_org_groups[2])} | ACLs: {len(g_org_acls[2])}\n")

        adp_orgs = await adpOrgs(aiodash, golden_org, orgs)

        # get any existing AdP for destinations to later check if they differ from golden
        if adp_orgs:
            check_tasks = []
            check_tasks.extend(aGetAdpGroups(aiodash, oid) for oid in adp_orgs)
            check_tasks.extend(aGetAdpAcls(aiodash, oid) for oid in adp_orgs)
            check_tasks.extend(aGetAdpPolicies(aiodash, oid) for oid in adp_orgs)
            
            print(f"\nGetting Destination Org Groups/ACLs/Policies for {len(adp_orgs)} Org(s)")
            for check in tqdm.tqdm(asyncio.as_completed(check_tasks), total=len(check_tasks), colour='green'):
                op, oid, result = await check
                adp_orgs[oid][op] = result
    
        # clone across orgs
            create_tasks = []

            for a_org in adp_orgs:
                if (len(adp_orgs[a_org]['acls']) or len(adp_orgs[a_org]['policies'])) > 0 or len(adp_orgs[a_org]['groups']) > 2:
                    print(f"{RED}Destination Org {YELLOW}{adp_orgs[a_org]['org']['name']}{RED} already has custom AdP config skipping{ENDC}")
                    adp_orgs[a_org]['adp'] = 'custom'
                    continue
                else:
                    adp_orgs[a_org]['adp'] = 'None'
                    # action batches won't quite work for org level stuff, async FTW
                    # Groups, ACLs first - no dependencies
                    # TODO: build out diff of custom groups/acls for remediation/alerting
                    for group in g_org_groups[2]:
                        if not group['isDefaultGroup']:
                            create_tasks.append(aCreateAdpGroups(aiodash, a_org,
                                                                group['name'], group['sgt'],
                                                                description=group['description'],
                                                                policyObjects=group['policyObjects']))

                    for acl in g_org_acls[2]:
                        create_tasks.append(aCreateAdpAcl(aiodash, a_org,
                                                        acl['name'], acl['rules'],
                                                        acl['ipVersion'], description=acl['description']))

        # no error checking on creates currently
            if create_tasks:
                print("Cloning Groups and ACLs to Destination Orgs")
                for create in tqdm.tqdm(asyncio.as_completed(create_tasks), total=len(create_tasks), colour='green'):
                    await create
            
            # prepare policies, take golden policies and update with new Group/ACL IDs.
            get_policy_task = []

            for a_org in adp_orgs:
                if not adp_orgs[a_org]['adp'] == 'custom':
                    # this could use a rework
                    update_task = []

                    groups = update_task.append(aGetAdpGroups(aiodash, a_org))
                    acls =  update_task.append(aGetAdpAcls(aiodash, a_org))

                    print(f"Updating Policy IDs")
                    for ut in tqdm.tqdm(asyncio.as_completed(update_task), total=len(update_task), colour='green'):
                        op, oid, result = await ut
                        adp_orgs[oid][op] = result
                    
                    # build golden hashes and map to new IDs.
                    group_hash = {g['sgt']: g['groupId'] for g in adp_orgs[a_org]['groups']}
                    logger.debug(f"group_hash: {PURPLE}{group_hash}{ENDC}")
                    acl_hash = {a['name']: a['aclId'] for a in adp_orgs[a_org]['acls']}
                    logger.debug(f"acl_hash: {PURPLE}{acl_hash}{ENDC}")

                    for pol in g_org_policies[2]:
                        pol['sourceGroup']['id'] = group_hash[pol['sourceGroup']['sgt']]
                        pol['destinationGroup']['id'] = group_hash[pol['destinationGroup']['sgt']]
                        if pol['acls']:
                            for p in pol['acls']:
                                p['id'] = acl_hash[p['name']]
                        
                        policies_res = get_policy_task.append(aCreateAdpPolicies(aiodash, a_org,
                                                    pol['sourceGroup'], pol['destinationGroup'],
                                                    acls=pol['acls'], last_entry_rules=pol['lastEntryRule']))

            if get_policy_task:
                print(f"Cloning Policies to Destination Orgs")
                for p in tqdm.tqdm(asyncio.as_completed(get_policy_task), total=len(get_policy_task), colour='green'):
                    await p


if __name__ == '__main__':
    start_time = datetime.now()
    parser = ArgumentParser(description = 'Select options.')

    parser.add_argument('-o', type = str,
                        help = 'Organization name for operation')
    parser.add_argument("--log", action = "store_true",
                        help = 'Log to file')
    parser.add_argument("-v", action = "store_true",
                        help = 'verbose')
    parser.add_argument("-d", action="store_true",
                        help="debug")
    args = parser.parse_args()

    logging.getLogger(__name__)
    logger = logging.getLogger(__name__)

    if not (args.o or config.GOLDEN_ORG):
        print(f"{RED}Must define a Golden Org in config.py or with -o option{ENDC}")
        sys.exit()
    else:
        if args.o:
            org_name = args.o
        else:
            org_name = config.GOLDEN_ORG

    if args.v or args.d:
        logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            fmt="%(asctime)s %(name)12s: %(levelname)8s > %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        handler_console = logging.StreamHandler()
        handler_console.setFormatter(formatter)

        if args.v:
            handler_console.setLevel(logging.INFO)
        else:
            handler_console.setLevel(logging.DEBUG)

        logger.addHandler(handler_console)
        logger.propagate = False

    if args.log:
        suppress_logging = False
        output_log = True
    elif args.v or args.d:
        suppress_logging = False
        output_log = False
    else:
        suppress_logging = True
        output_log = False

    asyncio.run(aiomain())

    end_time = datetime.now()
    print(f'\nScript complete, total runtime {end_time - start_time}')
