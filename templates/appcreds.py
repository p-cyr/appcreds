#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import sys
from typing import List, Optional

try:
    import openstack
except ImportError:
    print("Missing openstacksdk. Install with: pip install openstacksdk", file=sys.stderr)
    sys.exit(1)

try:
    import yaml
    HAS_YAML = True
except Exception:
    HAS_YAML = False

def connect(cloud=None):
    return openstack.connect(cloud=cloud)

def parse_duration_to_iso8601(expr: str) -> str:
    expr = expr.strip().lower()
    if not expr:
        raise ValueError("Empty duration string.")
    delta = dt.timedelta()
    number = ""
    for ch in expr:
        if ch.isdigit():
            number += ch
        elif ch in ("d", "h", "m"):
            if not number:
                raise ValueError(f"Invalid duration near '{ch}'")
            value = int(number)
            if ch == "d":
                delta += dt.timedelta(days=value)
            elif ch == "h":
                delta += dt.timedelta(hours=value)
            elif ch == "m":
                delta += dt.timedelta(minutes=value)
            number = ""
        else:
            raise ValueError(f"Unsupported character '{ch}' in duration.")
    if number:
        delta += dt.timedelta(hours=int(number))
    expires = (dt.datetime.utcnow() + delta).replace(microsecond=0)
    return expires.isoformat() + "Z"

def load_access_rules(path: str):
    ext = os.path.splitext(path)[1].lower()
    with open(path, "r", encoding="utf-8") as f:
        data = f.read()
    if ext in (".yaml", ".yml"):
        if not HAS_YAML:
            raise RuntimeError("PyYAML required. Install with pip install pyyaml.")
        rules = yaml.safe_load(data)
    else:
        rules = json.loads(data)
    if not isinstance(rules, list):
        raise ValueError("Access rules must be a JSON/YAML list.")
    return rules

def create_app_cred(conn, name, description, roles, expires_at, expires_in,
                    secret, unrestricted, access_rules_path):

    if expires_in and expires_at:
        raise ValueError("Choose only one of --expires-in or --expires-at.")

    if expires_in:
        expires_at = parse_duration_to_iso8601(expires_in)

    if access_rules_path:
        access_rules = load_access_rules(access_rules_path)
    else:
        access_rules = []  # Keystone requires an array here

    appcred = conn.identity.create_application_credential(
        user=conn.current_user_id,
        name=name,
        description=description,
        roles=roles,
        expires_at=expires_at,
        secret=secret,
        unrestricted=unrestricted,
        access_rules=access_rules
    )

    return {
        "id": appcred.id,
        "name": appcred.name,
        "description": getattr(appcred, "description", None),
        "project_id": getattr(appcred, "project_id", None),
        "user_id": getattr(appcred, "user_id", None),
        "expires_at": getattr(appcred, "expires_at", None),
        "secret": getattr(appcred, "secret", None),
        "roles": roles,
        "unrestricted": unrestricted,
        "access_rules": access_rules
    }

def find_app_cred(conn, identifier, name):
    if identifier:
        try:
            obj = conn.identity.get_application_credential(identifier, user=conn.current_user_id)
        except TypeError:
            obj = conn.identity.get_application_credential(identifier)
        if not obj:
            raise ValueError(f"No credential found with ID '{identifier}'.")
        return obj

    if name:
        try:
            items = conn.identity.application_credentials(user=conn.current_user_id)
        except TypeError:
            items = conn.identity.application_credentials()
        for item in items:
            if item.name == name:
                return item
        raise ValueError(f"No credential found with name '{name}'.")

    raise ValueError("Specify --id or --name.")

def delete_app_cred(conn, identifier, name, hard_fail):
    obj = find_app_cred(conn, identifier, name)
    try:
        conn.identity.delete_application_credential(
            application_credential=obj,
            user=conn.current_user_id,
            ignore_missing=not hard_fail
        )
    except TypeError:
        try:
            conn.identity.delete_application_credential(
                application_credential=obj,
                ignore_missing=not hard_fail
            )
        except TypeError:
            conn.identity.delete_application_credential(
                obj, conn.current_user_id,
                ignore_missing=not hard_fail
            )
    return obj.id, obj.name

def list_app_creds(conn):
    try:
        return list(conn.identity.application_credentials(user=conn.current_user_id))
    except TypeError:
        return list(conn.identity.application_credentials())

def show_app_cred(conn, identifier, name):
    obj = find_app_cred(conn, identifier, name)
    return {
        "id": obj.id,
        "name": obj.name,
        "description": getattr(obj, "description", None),
        "project_id": getattr(obj, "project_id", None),
        "user_id": getattr(obj, "user_id", None),
        "expires_at": getattr(obj, "expires_at", None),
        "unrestricted": getattr(obj, "unrestricted", None)
    }

def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--cloud")

    parser = argparse.ArgumentParser(description="Manage OpenStack app credentials")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("create", parents=[common])
    pc.add_argument("--name", required=True)
    pc.add_argument("--description")
    pc.add_argument("--roles")
    pc.add_argument("--expires-at")
    pc.add_argument("--expires-in")
    pc.add_argument("--secret")
    pc.add_argument("--unrestricted", action="store_true")
    pc.add_argument("--access-rules")

    pd = sub.add_parser("delete", parents=[common])
    g = pd.add_mutually_exclusive_group(required=True)
    g.add_argument("--id")
    g.add_argument("--name")
    pd.add_argument("--hard-fail", action="store_true")

    sub.add_parser("list", parents=[common])
    ps = sub.add_parser("show", parents=[common])
    s = ps.add_mutually_exclusive_group(required=True)
    s.add_argument("--id")
    s.add_argument("--name")
    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()
    cloud = args.cloud or os.getenv("OS_CLOUD")
    conn = connect(cloud)

    try:
        if args.cmd == "create":
            roles = [{"name": r.strip()} for r in args.roles.split(",")] if args.roles else None
            result = create_app_cred(conn, args.name, args.description,
                                     roles, args.expires_at, args.expires_in,
                                     args.secret, args.unrestricted,
                                     args.access_rules)
            print(json.dumps(result, indent=2))
            print("\nSecret is shown only once!", file=sys.stderr)

        elif args.cmd == "delete":
            cid, cname = delete_app_cred(conn, args.id, args.name, args.hard_fail)
            print(f"Deleted credential id={cid} name={cname}")

        elif args.cmd == "list":
            for cred in list_app_creds(conn):
                print(f"{cred.id}\t{cred.name}\texpires_at={cred.expires_at}")

        elif args.cmd == "show":
            print(json.dumps(show_app_cred(conn, args.id, args.name), indent=2))

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(3)

if __name__ == "__main__":
    main()
