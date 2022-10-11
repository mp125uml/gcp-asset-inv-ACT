#!/usr/bin/env python3
"""
Script to get a list of service accounts and their IAM policy
with GCP asset inventory
"""
import os
import json
import codecs
import csv
import argparse
import base64
# import re
from google.cloud import asset_v1
from google.cloud import storage
from google.api_core.exceptions import GoogleAPIError
import proto
import googleapiclient.errors
from datetime import datetime

# Declare as global because this is used in so many places for logic, etc
act_file_no = os.getenv('ACT_FILE_NO')

def get_all_sas(org_id):
    """
    Get a list of Service Account and return them as a list of dictionaries
    """
    scope = f"organizations/{org_id}"
    asset_types = ['iam.googleapis.com/ServiceAccount']
    query = "NOT name:(sandbox OR nonprod)"
    client = asset_v1.AssetServiceClient()
    try:
        response = client.search_all_resources(request={
            "scope": scope,
            "query": query,
            "asset_types": asset_types
        })
    except (GoogleAPIError, googleapiclient.errors.HttpError) as err:
        print(f'API Error: {err}')
        exit(0)
        # raise RuntimeError(f'Error fetching Asset Inventory entries: {e}')
    # all_sas = {}
    # for resource in response:
    #     # print(resource.name.split('/')[-1])
    #     gcp_sas_list.append(resource.name.split('/')[-1])
    ## converting protobuf to dictionary
    # https://github.com/googleapis/python-vision/issues/70#issuecomment-749135327
    serializable_assets = [proto.Message.to_dict(asset) for asset in response]
    # proto_contents = json.loads(serializable_assets)
    return serializable_assets


def get_iam_policies(svc_account, org_id):
    """
    Given a service account get all the IAM policies attached to
    that service account
    """
    scope = f"organizations/299390918745"
    query = f"policy:{svc_account}"
    client = asset_v1.AssetServiceClient()
    try:
        response = client.search_all_iam_policies(request={
            "scope": scope,
            "query": query
        })
    except (GoogleAPIError, googleapiclient.errors.HttpError) as err:
        print(f'API Error: {err}')
        exit(0)
    sa_permissions = {}
    for policy in response:
        sa_permissions["resource"] = policy.resource
        sa_permissions["project"] = policy.project
        # sa_permissions["bindings"] = MessageToDict(policy.policy)
        sa_permissions["asset_type"] = policy.asset_type
        sa_permissions["organization"] = policy.organization
        # print(sa_permissions)
        # print(policy)

    return sa_permissions


def get_all_iam_policies(org_id):
    """
    Given a service account get all the IAM policies attached to
    that service account
    """
    scope = f"organizations/{org_id}"
    client = asset_v1.AssetServiceClient()
    try:
        response = client.search_all_iam_policies(request={"scope": scope})
    except (GoogleAPIError, googleapiclient.errors.HttpError) as err:
        print(f'API Error: {err}')
        exit(0)
    ## converting protobuf to dictionary
    # https://github.com/googleapis/python-vision/issues/70#issuecomment-749135327
    serializable_assets = [proto.Message.to_dict(asset) for asset in response]
    return serializable_assets


def upload_content_gcp_bucket(gcp_bucket, dest_filename, file_contents):
    """Uploads a file to the bucket by using it's contents"""
    storage_client = storage.Client()
    bucket = storage_client.bucket(gcp_bucket)
    blob = bucket.blob(dest_filename)

    blob.upload_from_string(file_contents)


def upload_file_gcp_bucket(gcp_bucket, dest_filename, source_file):
    """Uploads a file to the bucket."""
    storage_client = storage.Client()
    bucket = storage_client.bucket(gcp_bucket)
    blob = bucket.blob(dest_filename)

    blob.upload_from_filename(source_file)


def import_json_as_dictionary(filename):
    """
    Given a json file import it and return the contents as a dictionary
    """
    try:
        # Check if file is utf-8 encoded
        codecs.open(filename, encoding="utf-8", errors="strict").readline()
        utf_8 = True
        utf_16 = False
    except UnicodeDecodeError:
        utf_8 = False

    if not utf_8:
        try:
            # Check if file is utf-16-le encoded
            codecs.open(filename, encoding="utf-16-le",
                        errors="strict").readline()
            utf_16 = True
        except UnicodeDecodeError:
            utf_16 = False

    if utf_16:
        with open(filename, 'r', encoding='utf-16-le') as json_file_handler:
            data = json_file_handler.read()
            json_contents = json.loads(data.encode().decode('utf-8-sig'))
    elif utf_8:
        with open(filename, 'r') as json_file_handler:
            data = json_file_handler.read()
            json_contents = json.loads(data)
    else:
        print("Unable to determine file encoding, it's not utf-8 or utf-16-le")
        exit(0)

    return json_contents


def get_uid_from_email(sa_email, all_sas_dictionary):
    '''
    Given an email address and all the service accounts get the uid
    from the email attribute
    '''
    # pattern = "^sa-(.*)-(.*)-(.*)-(.*)@(.*)$"
    for svc_account in all_sas_dictionary:
        # print(svc_account)
        ## Looks like gcloud assets --format json and
        # python client libraries uses different
        # formatting for keys, gcloud uses camelCase
        # and api use under_scores, manually checking
        # for both to support both use cases
        if 'additional_attributes' in svc_account:
            current_email = svc_account['additional_attributes']['email']
            if current_email == sa_email:
                uid = svc_account['additional_attributes']['uniqueId']
                break
                # match = re.search(pattern, current_email)
                # if match:
                #     # print(match.groups())
                #     _env, _scope, app_id, _app, _domain_name = match.groups()
                #     break
                ## Uncomment below if you want to use the Description of the
                ## service account to get the appID
                # if 'display_name' in svc_account:
                #     if svc_account['display_name']:
                #         app_id = svc_account['display_name']
                #         # print(svc_account)
                #     else:
                #         app_id = sa_email
                #     ## Stop traversing the dictionary we
                #     ## determined the service account
                #     break
        elif 'additionalAttributes' in svc_account:
            current_email = svc_account['additionalAttributes']['email']
            if current_email == sa_email:
                uid = svc_account['additionalAttributes']['uniqueId']
                break
                # match = re.search(pattern, current_email)
                # if match:
                #     _env, _scope, app_id, _app, _domain_name = match.groups()
                #     break
                ## Uncomment below if you want to use the Description of the
                ## service account to get the appID
                # if 'displayName' in svc_account:
                #     app_id = svc_account['displayName']
                #     ## Stop traversing the dictionary we
                #     ## found service account
                #     break
    else:

        ## the email is not customer owned but a gcp owned agent
        ## service account, so marking it as such
        uid = "gcp_owned"

    return uid


def get_policy_for_identity(identity_info,
                            iam_policy=None,
                            binding=None,
                            org_id=None):
    """
    Get Iam policies with the iam-policy-analyze api, which also shows
    group inherited policies. If user-a is part of group-a, then a policy
    that is using the group will be listed for user-a
    """
    principal_policy = {}
    if identity_info['sa_type'] == "serviceAccount" or org_id is None:
        if 'assetType' in iam_policy:
            rsc_type = iam_policy['assetType'].split('/')[-1]
        elif 'asset_type' in iam_policy:
            rsc_type = iam_policy['asset_type'].split('/')[-1]
        rsc_name = iam_policy['resource'].split('/')[-1]
        rsc = f"{rsc_type}_({rsc_name})"
        role = binding['role'].replace('roles/', '') # <-
        # new fields - file 251
        if act_file_no == "file-251":
            principal_policy[identity_info['email']] = {
                "RECORD_TYPE": "S",
                "UNIQUE_ID": identity_info['uid'],
                "SOR": "",
                "ID_LOCATION": "Production",
                "NAME": "",
                "STATUS": "A",
                "PRIV_IND": "3",
                "CERT_TYPE": "APPL",
                "CERT_ENTITY": "GCP",
                "LAST_NAME": "",
                "EMP_ID": "",
                "TID": "",
                "AU": "", #need to find labels here - file 251
                "OWNING_APPL": "GCP",
                "LAST_LOGIN": ""
                # remove entitlement - file 251
            }
        elif act_file_no == "file-252":
            principal_policy[identity_info['email']] = {
	      # entitlement only - file 252
                "Entitlement": [f"{role}_{rsc}"]
            }
        else:
            principal_policy[identity_info['email']] = {
                "Entitlement": [f"{role}_{rsc}"],
                "UNIQUE_ID": identity_info['uid']
            }


    else:
        client = asset_v1.AssetServiceClient()
        parent = f"organizations/{org_id}"

        # Build analysis query
        analysis_query = asset_v1.IamPolicyAnalysisQuery()
        analysis_query.scope = parent
        analysis_query.identity_selector.identity = f"user:{identity_info['email']}"
        analysis_query.options.expand_groups = True
        analysis_query.options.output_group_edges = True

        response = client.analyze_iam_policy(
            request={"analysis_query": analysis_query})

        for policy in proto.Message.to_dict(
                response)["main_analysis"]["analysis_results"]:
            # print (json.dumps(policy, indent=2, default=str))
            rsc_type = policy['attached_resource_full_name'].split('/')[-2]
            rsc_name = policy['attached_resource_full_name'].split('/')[-1]
            role = policy['iam_binding']['role'].replace('roles/', '')
            rsc = f"{rsc_type}_({rsc_name})"
            if policy['identity_list']['group_edges']:
                group_name = policy['identity_list']['group_edges'][0][
                    'source_node'].replace(':', '_')
                add_info = f'via_{group_name}'
                entitlement = f"{role}_{rsc}_{add_info}"
            else:
                entitlement = f"{role}_{rsc}"

            ## Skip the "Policy Resource"
            if rsc_type != "Policy":
                if identity_info['email'] in principal_policy:
                    if os.getenv("ACT_FILE_NO") == "file-251":
                        principal_policy[identity_info['email']]
                            #["Entitlement"].append(entitlement)
                    else:
                        principal_policy[identity_info['email']]["Entitlement"].append(entitlement)
                else:
                    if act_file_no == "file-251":
                       principal_policy[identity_info['email']] = {
                           "RECORD_TYPE": "S",
                           "UNIQUE_ID": identity_info['uid'],
                           "SOR": "",
                           "ID_LOCATION": "Production",
                           "NAME": "",
                           "STATUS": "A",
                           "PRIV_IND": "3",
                           "CERT_TYPE": "APPL",
                           "CERT_ENTITY": "GCP",
                           "LAST_NAME": "",
                           "EMP_ID": "",
                           "TID": "",
                           "AU": "", #need to find labels here - file 251
                           "OWNING_APPL": "GCP",
                           "LAST_LOGIN": ""
                           # remove entitlement - file 251
                       }
                    elif act_file_no == "file-252":
                       principal_policy[identity_info['email']] = {
                          # entitlement only - file 252
                            "Entitlement": [entitlement]
                        }
                    else:
                       principal_policy[identity_info['email']] = {
                            "Entitlement": [entitlement],
                            "UNIQUE_ID": identity_info['uid']
                       }
            # print (json.dumps(policy, indent=2, default=str))

    return principal_policy[identity_info['email']]


def get_identity_info(member):
    """
    Create an identity dictionary to start populating information
    about the identity
    """
    identity_info = {}
    ignored_sa_types = set(
        ('projectOwner', 'projectEditor', 'projectViewer', 'group'))
    colon_counter = member.count(':')
    if colon_counter == 1:
        sa_type, sa_name = member.split(':')
        sa_other = "notUsed"
    elif colon_counter == 2:
        sa_other, sa_type, sa_name = member.split(':')
    else:
        ## Usually no colons means it's allUsers,
        # which is not in email format
        sa_name = member
        sa_type = member
        sa_other = "notUsed"

    if sa_type not in ignored_sa_types and sa_other != "deleted":
        if sa_type != "allUsers":
            f_name = sa_name.split('@')[0]
            l_name = sa_name.split('@')[0]
        else:
            f_name = l_name = sa_name
        
        identity_info['sa_type'] = sa_type
        identity_info['email'] = sa_name
        identity_info['first_name'] = f_name
        identity_info['last_name'] = l_name
    else:
        identity_info["sa_type"] = "notUsed"

    return identity_info


def parse_assets_output(all_iam_policies_dictionary,
                        all_sas_dictionary,
                        gcp_org_id=None):
    """
    Take input from `gcloud asset search-all-iam-policies` and
    `gcloud asset search-all-resources --asset-types='iam.googleapis.com/ServiceAccount'`
    and produce a dictionary of those files merged
    """
    output_dict = {}
    # ignored_sa_accounts = set(('deleted'))
    for iam_policy in all_iam_policies_dictionary:
        # Skip the Policy Resource type
        if iam_policy['asset_type'] != "orgpolicy.googleapis.com/Policy":
            if iam_policy['policy']['bindings']:
                for binding in iam_policy['policy']['bindings']:
                    for member in binding['members']:
                        # print(member)
                        identity = get_identity_info(member)
                        if identity[
                                'sa_type'] == 'user' and gcp_org_id is not None:
                            identity['uid'] = identity['email']
                            if identity['email'] not in output_dict:
                                identity_policy = get_policy_for_identity(
                                    identity,
                                    iam_policy=None,
                                    org_id=gcp_org_id)
                                # print(identity_policy)
                                output_dict[identity['email']] = identity_policy

                        elif identity['sa_type'] != 'notUsed':
                            if identity['sa_type'] == 'user':
                                identity['uid'] = identity['email']
                            else:
                                identity['uid'] = get_uid_from_email(
                                    identity['email'], all_sas_dictionary)
                            if identity['uid'] != 'gcp_owned':
                                identity_policy = get_policy_for_identity(
                                    identity,
                                    iam_policy=iam_policy,
                                    binding=binding,
                                    org_id=None)
                                # print(identity_policy)
                                if identity['email'] in output_dict:
                                    # print(output_dict)
                                    if act_file_no == "file-251":
                                        output_dict[identity['email']]
                                    elif act_file_no == "file-252":
                                        ['Entitlement'].append(
                                            identity_policy['Entitlement'][0])
                                    else:
                                        output_dict[identity['email']]
                                        
                                else:
                                    output_dict[
                                        identity['email']] = identity_policy

    # print (json.dumps(output_dict, indent=2, default=str))
    return output_dict

def csv_for_251(csv_file, csv_columns, dictionary):
         try:
             with open(csv_file, 'w') as csvfile:
                 writer = csv.DictWriter(csvfile, fieldnames=csv_columns, delimiter='|')
                 writer.writeheader()
                 for _sa, sa_value in dictionary.items():
                     writer.writerow(sa_value)
         except IOError:
             print("I/O error, can't write out CSV file") 

def csv_for_252(csv_file, csv_columns, dictionary):

         header = ["RESOURCE_TYPE","UNIQUE_ID", "SOR", "RESOURCE_LOCATION", "NAME", "STATUS", "PRIV_IND", "CERT_TYPE", "CERT_ENTITY", "DESCRIPTION", "OWNING_APPL"]
   
         try:
             with open(csv_file, 'w') as csvfile:
                 writer = csv.writer(csvfile, delimiter="|")
                 writer.writerow(header)
                 role = "Role"
                 sor = ""
                 status = "A"
                 priv_ind = "3"
                 cert_type = "APPL"
                 cert_entity = "GCP"
                 description = ""
                 owning_appl = "GCP"
                 for _sa, sa_value in dictionary.items():
                     for i in sa_value['Entitlement']:
                         unique_id = "_".join(i.split("_", 2)[:2])
                         resource_location = i.split("_", 2)[-1].replace("(","").replace(")","")
                         resource_location = resource_location.split('@')[0].replace('@','')
                         name = i.split('@')[0].replace('@','').replace("(","").replace(")","")
                         writer.writerow([role, unique_id, sor, resource_location, name, status, priv_ind, cert_type, cert_entity,
                                                                                                  description, owning_appl])
         except IOError:
             print("I/O error, can't write out CSV file")

def csv_for_253(csv_file, csv_columns, dictionary):
         header = ["UNIQUE_ID", "SOR", "ID_LOCATION", "PRIV_IND", "ATTR_NAME1", "ATTR_VALUE1", "ATTR_NAME2", "ATTR_VALUE2", "ATTR_CONTROL", "LOCATION", "ENTITLEMENT STATUS", "OWNING_APPLICATION"]

         try:
                with open(csv_file, 'w') as csvfile:
                    writer = csv.writer(csvfile, delimiter="|")
                    writer.writerow(header)
                    sor = ""
                    id_location = "Production"
                    status = "A"
                    priv_ind = "3"
                    attr_name1 = "Role"
                    attr_name2 = ""
                    attr_value2 = ""
                    attr_control = ""
                    entitlement_status = "A"
                    owning_application = "GCP"
                    for _sa, sa_value in dictionary.items():
                        for i in sa_value['Entitlement']:
                            unique_id = sa_value['UNIQUE_ID']
                            attr_value1 = "_".join(i.split("_", 2)[:2]).replace('(\'','').replace('\',)','')
                            location = i.split("_", 2)[-1].replace("(","").replace(")","")
                            location = location.split('@')[0].replace('@','')
                            name = i.split('@')[0].replace('@','').replace("(","").replace(")","")
                            writer.writerow([unique_id, sor, id_location, priv_ind, attr_name1, attr_value1, attr_name2, attr_value2,
                                                               attr_control, location, entitlement_status, owning_application])

         except IOError:
             print("I/O error, can't write out CSV file")

def csv_for_255(csv_file, csv_columns, dictionary):

         header = ["DATE_STAMP", "OWNING_APPLICATION", "HASH_ALGORITHM", "FILE_FORMAT", "T251_ROWS", "T251_HASH", "T252_ROWS",                                                                          "T252_HASH", "T253_ROWS", "T253_HASH", "T254_ROWS", "T254_HASH"]
         
         try:
             with open(csv_file, 'w') as csvfile:
                 writer = csv.writer(csvfile, delimiter="|")
                 writer.writerow(header)
                 timestamp = datetime.today().strftime('%Y/%m/%d %H:%M:%S')
                 owning_app = "GCP"
                 hash_algorithm = ""
                 
                 #T-251 Rows
                 count = 1
                 for _sa, sa_value in dictionary.items():
                     count += 1
                     t251_rows = count
                 t251_hash = ""
                 
                 #T-251 Rows
                 count = 1
                 for _sa, sa_value in dictionary.items():
                     for i in sa_value['Entitlement']: 
                         count += 1
                         t252_rows = count
                 t252_hash = ""

                 #T-253 Rows
                 count = 1
                 for _sa, sa_value in dictionary.items():
                     for i in sa_value['Entitlement']:
                         count += 1
                         t253_rows = count
                 t253_hash = ""

                 # I was not requested to do T-254
                 t254_rows = ""
                 t254_hash = ""

                 file_format = "ASCII-CRLF" #Determined this with Linux `file` command
                 writer.writerow([timestamp, owning_app, hash_algorithm, file_format, t251_rows, t251_hash, t252_rows, t252_hash, 
                                                                                         t253_rows, t253_hash, t254_rows, t254_hash])

         except IOError:
             print("I/O error, can't write out CSV file")

def write_dictionary_to_csv(dictionary, filename):
    # Creating the dictionary. A dictionary of *some* values is always needed
    # Logic per ACT file
    if act_file_no == 'file-251':
        print(act_file_no + "1")
        csv_columns = [
            'RECORD_TYPE',
            'UNIQUE_ID',
            'SOR',
            'ID_LOCATION',
            'NAME',
            'STATUS',
            'PRIV_IND',
            'CERT_TYPE',
            'CERT_ENTITY',
            'LAST_NAME',
            'EMP_ID',
            'TID',
            'AU',
            'OWNING_APPL',
            'LAST_LOGIN'
        ]
        csv_file = filename
    elif act_file_no == 'file-252':
        csv_columns = [ 'Entitlement' ] 
        csv_file = filename
    elif act_file_no == 'file-253':
        csv_columns = [ 'Entitlement', 'UNIQUE_ID' ]
        csv_file = filename
    else:
        csv_columns = []
        csv_file = filename

    if act_file_no == 'file-251':
        csv_for_251(csv_file, csv_columns, dictionary)
    elif act_file_no == 'file-252':
        csv_for_252(csv_file, csv_columns, dictionary)
    elif act_file_no == 'file-253':
        csv_for_253(csv_file, csv_columns, dictionary)
    else:
        csv_for_255(csv_file, csv_columns, dictionary)
		
                

def cf_entry_event(event, context):
    """ Event Entry point for the cloudfunction"""
    print(
        """This Function was triggered by messageId {} published at {} to {}""".
        format(context.event_id, context.timestamp, context.resource["name"]))

    if 'data' in event:
        data = base64.b64decode(event['data']).decode('utf-8')
        print(f"data received from trigger: {data}")

    try:
        run_remote()
        return "Remote mode finished successfully"
    except:
        print("Remote mode failed")
        exit(0)


def cf_entry_http(request):
    """ HTTP Entry point for the cloudfunction"""
    print(f"This Function was triggered by request {request}")

    # if 'data' in event:
    #     data = base64.b64decode(event['data']).decode('utf-8')
    #     print(f"data received from trigger: {data}")
    try:
        run_remote()
        return "Remote mode finished successfully"
    except:
        print("Remote mode failed")
        exit(0)


def run_local(iam_json_filename, sas_json_filename, csv_filename, gcs_bucket):
    """
    Execute the script in local mode, this expect json files to be passed in
    """
    print('Script running in local mode')
    ## We are in local mode, read in local json files
    all_iam_policies = import_json_as_dictionary(iam_json_filename)
    all_svc_accts = import_json_as_dictionary(sas_json_filename)

    ## Write out CSV from the Dictionary
    merged_iam_sa_dictionary = parse_assets_output(all_iam_policies,
                                                   all_svc_accts)
    write_dictionary_to_csv(merged_iam_sa_dictionary, csv_filename)
    print(f"Wrote results to {csv_filename}")

    if gcs_bucket:
        upload_file_gcp_bucket(gcs_bucket, csv_filename, csv_filename)
        print(f"Uploaded file {csv_filename} to {gcs_bucket}")


def run_remote():
    """
    Execute the script in remote mode, this gets the data using APIs
    """
    print('Script running in remote mode')
    if os.getenv("GCP_ORG_ID"):
        gcp_org_id = os.getenv("GCP_ORG_ID")
    else:
        print("Pass in GCP ORG ID by setting an env var " +
              "called 'GCP_ORG_ID'")
        exit(0)
    if os.getenv("GCS_BUCKET_NAME"):
        gcs_bucket = os.getenv("GCS_BUCKET_NAME")
    else:
        print("Pass in GCS Bucket by setting an env var " +
              "called 'GCS_BUCKET_NAME'")
        exit(0)
    # 10/10 - Added for new formats and files
    if act_file_no:
        csv_filename = "out-" + act_file_no + ".csv"
    else:
        print("Pass in ACT filename by setting an env var" +
              "called 'ACT_FILE_NO'")
        exit(0)
    # 10/10 - Removed for new formats and files
    #if os.getenv("CSV_OUTPUT_FILE"):
    #    csv_filename = os.getenv("CSV_OUTPUT_FILE")
    #else:
    #   print("Pass in output filename by setting an env var " +
    #          "called 'CSV_OUTPUT_FILE'")
    #    exit(0)

    all_iam_policies = get_all_iam_policies(gcp_org_id)
    all_svc_accts = get_all_sas(gcp_org_id)
    merged_iam_sa_dictionary = parse_assets_output(all_iam_policies,
                                                   all_svc_accts, gcp_org_id)
    csv_file_full_path = f"/tmp/{csv_filename}"
    write_dictionary_to_csv(merged_iam_sa_dictionary, csv_file_full_path)
    print(f"Wrote results to {csv_file_full_path}")
    upload_file_gcp_bucket(gcs_bucket, csv_filename, csv_file_full_path)
    print(f"Uploaded file {csv_file_full_path} to {gcs_bucket}")


if __name__ == "__main__":
    CMD_DESC = (
        "Script to parse the output of gcloud asset inventory. "
        "It has two modes: remote\n or local. In local mode it expects 2 "
        "input files. The first one is the output\n of `gcloud asset "
        "search-all-iam-policies`. The second one is output of "
        "`gcloud asset search-all-resources "
        "--asset-types='iam.googleapis.com/ServiceAccount'`. In remote mode "
        "it makes the corresponding API calls to get the data. It parses the "
        "input and creates a CSV file with the merged info. It can optionally "
        "upload the results to a GCS Bucket. *NOTE*: Google Managed/Agent "
        "service accounts are not included.")
    parser = argparse.ArgumentParser(description=CMD_DESC)
    ## Create a mutually exclusive parser group
    # to make sure only one mode is used
    # either remote or local, you can't use both
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-r',
                       '--remote',
                       action='store_const',
                       dest='mode',
                       const='remote',
                       help='run in remote mode reading from apis (default)')
    group.add_argument(
        '-l',
        '--local',
        action='store_const',
        dest='mode',
        const='local',
        help='run in local mode reading from passed in json files')
    parser.set_defaults(mode='remote')
    parser.add_argument('-g',
                        '--gcs_bucket',
                        help='upload results to gcs bucket')
    parser.add_argument(
        '-i',
        '--iam_file',
        help='file containing all the iam policies (only in local mode)')
    parser.add_argument(
        '-s',
        '--sas_file',
        help='file containing all the service accounts (only in local mode)')
    parser.add_argument('-o',
                        '--output_file',
                        help='name of file to write results to')
    args = parser.parse_args()

    ## If --remote is passed ignore the local variables
    if args.mode == 'remote' and (args.iam_file or args.sas_file):
        print("-r is specified but local files are passed in " +
              "either switch to local mode or remove the file arguements")
        exit(0)

    if args.mode == 'remote':
        run_remote()

    if args.mode == 'local':
        IAM_JSON_FILENAME = args.iam_file
        SAS_JSON_FILENAME = args.sas_file
        if args.output_file:
            CSV_FILENAME = args.output_file
        else:
            CSV_FILENAME = IAM_JSON_FILENAME.replace('json', 'csv')
        if args.gcs_bucket:
            GCS_BUCKET = args.gcs_bucket
        else:
            GCS_BUCKET = ""
        run_local(IAM_JSON_FILENAME, SAS_JSON_FILENAME, CSV_FILENAME,
                  GCS_BUCKET)
