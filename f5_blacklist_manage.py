#!/usr/bin/env python3

import os
import sys
import argparse
import requests
from requests.auth import HTTPBasicAuth
import ipaddress

DEBUG = os.getenv("DEBUG", "0") == "1"

requests.packages.urllib3.disable_warnings()

# 
DEFAULT_DATA_GROUPS = {
    "IP.TMP_Blocklist": "Temporary Blocked IPs",
    "IP.PERS_Blocklist": "Permanently Blocked IPs",
    "IP.STOR_Blocklist": "Stored Blocked IPs"
}

def connect():
    url = os.getenv("F5_API_URL")
    username = os.getenv("F5_API_LOGIN")
    password = os.getenv("F5_API_PASSWORD")
    if not all([url, username, password]):
        print("❌ Environment variables F5_API_URL, F5_API_LOGIN, F5_API_PASSWORD must be set.")
        sys.exit(1)
    session = requests.Session()
    session.auth = HTTPBasicAuth(username, password)
    session.verify = False
    session.headers.update({'Content-Type': 'application/json'})
    return session, url.rstrip('/')


def disconnect(session):
    session.close()


def check_ip(session, base_url, ip, data_groups):

    found_in = []
    username = os.getenv("F5_API_LOGIN")
    password = os.getenv("F5_API_PASSWORD")

    for dg_name in data_groups:
        url = f"{base_url}/mgmt/tm/ltm/data-group/internal/{dg_name}"
        headers = {'Content-Type': 'application/json'}
        auth = HTTPBasicAuth(username, password)

        resp = session.get(url, headers=headers, auth=auth, verify=False, timeout=15)
        if resp.status_code != 200:
            print(f"[ERROR] Failed to query data group '{dg_name}': {resp.status_code}")
            continue
        dg_data = resp.json()

        for record in dg_data.get("records", []):
           record_ip = record.get('name', '')
           if '/' in record_ip:
              record_ip = record_ip.split('/')[0]
           if record_ip == ip:
                found_in.append(dg_name)
                break
           else:
               if DEBUG == 1:
                  print(f"  - {record['name']}")
    return found_in

def delete_ip(session, base_url, ip, data_groups):

    username = os.getenv("F5_API_LOGIN")
    password = os.getenv("F5_API_PASSWORD")

    for dg_name in data_groups:
        if dg_name not in DEFAULT_DATA_GROUPS:
            print(f"⛔ '{dg_name}' is not in the list of allowed Data Groups. Skipping.")
            continue

        url = f"{base_url}/mgmt/tm/ltm/data-group/internal/{dg_name}"
        headers = {'Content-Type': 'application/json'}
        auth = HTTPBasicAuth(username, password)

        resp = session.get(url, headers=headers, auth=auth, verify=False, timeout=15)
        if resp.status_code != 200:
            print(f"❌ Failed to fetch data group '{dg_name}': {resp.status_code}")
            continue

        dg_data = resp.json()
        new_records = [r for r in dg_data.get('records', []) if r.get('name', '').split('/')[0] != ip]

        if DEBUG == 1:
            print(f"===============================")
            print(f"'{new_records}'")
            print(f"===============================")

        if len(new_records) == len(dg_data.get('records', [])):
            print(f"ℹ️ IP {ip} not found in data group '{dg_name}', skipping.")
            continue
        else:
            update_resp = session.put(url, json={'records': new_records}, headers=headers, auth=auth, verify=False, timeout=15)
            if update_resp.status_code == 200:
                print(f"✅ IP {ip} removed from data group '{dg_name}'.")
            else:
                print(f"❌ Failed to update data group '{dg_name}': {update_resp.status_code}")


def main():
    parser = argparse.ArgumentParser(
        description="F5 IP checker/deleter for Data Groups",
        usage="python3 %(prog)s <IP> <check|delete> [--group GROUP|all]"
    )
    parser.add_argument("ip", help="IP address to check or delete")
    parser.add_argument("action", choices=["check", "delete"], help="Action to perform")
    parser.add_argument("--group", help="Specify a single data group name or 'all'", default="all")
    args = parser.parse_args()

    # Check IP format
    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        print(f"❌ Invalid IP address format: {args.ip}")
        parser.print_help()
        sys.exit(2)

    # Check group name if all not set
    if args.group != "all" and args.group not in DEFAULT_DATA_GROUPS:
        print(f"❌ Invalid group name: {args.group}")
        print("✅ Available groups are:")
        for name, comment in DEFAULT_DATA_GROUPS.items():
            print(f"  - {name}: {comment}")
        parser.print_help()
        sys.exit(2)

    # Connect to F5
    session, base_url = connect()

    try:
        data_groups = list(DEFAULT_DATA_GROUPS.keys()) if args.group == "all" else [args.group]

        if args.action == "check":
            found_in = check_ip(session, base_url, args.ip, data_groups)
            if found_in:
                print(f"✅ IP {args.ip} found in data groups:")
                for entry in found_in:
                    description = DEFAULT_DATA_GROUPS.get(entry, "(no description)")
                    print(f"  - {description}: [{entry}]")
            else:
                print(f"❌ IP {args.ip} not found in any specified data groups.")

        elif args.action == "delete":
            delete_ip(session, base_url, args.ip, data_groups)

    finally:
        disconnect(session)

if __name__ == "__main__":
    main()

