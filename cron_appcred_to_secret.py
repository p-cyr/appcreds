#!/usr/bin/env python3
"""
Create an OpenStack Application Credential from a clouds.yaml cloud and
store the result (id + secret + metadata) in a Kubernetes Secret.

Enhancements:
- APP_CRED_NO_EXPIRY=true will ignore APP_CRED_EXPIRES_AT / APP_CRED_EXPIRES_IN
  and create a non-expiring application credential.

Environment variables:
  OS_CLOUD                    # cloud name from clouds.yaml
  APP_CRED_NAME              # e.g., cicd-token
  APP_CRED_ROLES             # CSV, e.g., member,reader
  APP_CRED_DESCRIPTION       # optional
  APP_CRED_EXPIRES_AT        # optional, ISO8601 UTC e.g. 2026-06-01T00:00:00Z
  APP_CRED_EXPIRES_IN        # optional, e.g., 90d, 24h, 30m, 7d12h
  APP_CRED_NO_EXPIRY         # optional, true|false; if true => no expiry
  APP_CRED_SECRET            # optional, supply your own secret (otherwise server generates)
  APP_CRED_UNRESTRICTED      # optional, true|false; defaults false
  ACCESS_RULES_PATH          # optional, path to JSON/YAML list of access rules

  OUTPUT_SECRET_NAME         # k8s Secret name to create/patch
  OUTPUT_SECRET_NAMESPACE    # k8s namespace for Secret; defaults to POD_NAMESPACE
  POD_NAMESPACE              # usually injected via fieldRef

Mounts:
  /etc/openstack/clouds.yaml # clouds.yaml with the selected OS_CLOUD
  (optional) custom CA via REQUESTS_CA_BUNDLE or verify in clouds.yaml if needed
"""

import os, sys, json, argparse, datetime as dt
from typing import Optional, List

# OpenStack SDK
try:
    import openstack
except ImportError:
    print("Missing openstacksdk. pip install openstacksdk", file=sys.stderr)
    sys.exit(1)

# Optional YAML for access rules
try:
    import yaml
    HAS_YAML = True
except Exception:
    HAS_YAML = False

# Kubernetes Python client (in-cluster)
try:
    from kubernetes import client as k8s, config as k8s_config
except ImportError:
    print("Missing kubernetes client. pip install kubernetes", file=sys.stderr)
    sys.exit(1)


def parse_bool(v: Optional[str]) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


def parse_duration_to_iso8601(expr: str) -> str:
    expr = expr.strip().lower()
    if not expr:
        raise ValueError("Empty duration string.")
    delta = dt.timedelta()
    num = ""
    for ch in expr:
        if ch.isdigit():
            num += ch
        elif ch in ("d", "h", "m"):
            if not num:
                raise ValueError(f"Invalid duration near '{ch}'")
            val = int(num)
            if ch == "d":
                delta += dt.timedelta(days=val)
            elif ch == "h":
                delta += dt.timedelta(hours=val)
            elif ch == "m":
                delta += dt.timedelta(minutes=val)
            num = ""
        else:
            raise ValueError(f"Unsupported character '{ch}'")
    if num:
        delta += dt.timedelta(hours=int(num))
    return (dt.datetime.utcnow() + delta).replace(microsecond=0).isoformat() + "Z"


def load_access_rules(path: Optional[str]):
    if not path:
        return []
    ext = os.path.splitext(path)[1].lower()
    with open(path, "r", encoding="utf-8") as f:
        data = f.read()
    if ext in (".yaml", ".yml"):
        if not HAS_YAML:
            raise RuntimeError("PyYAML required for YAML access rules.")
        rules = yaml.safe_load(data)
    else:
        rules = json.loads(data)
    if not isinstance(rules, list):
        raise ValueError("Access rules must be a list of rule objects.")
    return rules


def connect_openstack(cloud: Optional[str]):
    # openstacksdk reads /etc/openstack/clouds.yaml & OS_CLOUD automatically
    return openstack.connect(cloud=cloud)


def create_app_credential(
    conn,
    name: str,
    roles: Optional[List[dict]],
    description: Optional[str],
    expires_at: Optional[str],
    expires_in: Optional[str],
    secret: Optional[str],
    unrestricted: bool,
    access_rules_path: Optional[str],
):

    """
    Create an application credential. If no_expiry is True, expires_* are ignored.
    """
    if no_expiry:
        expires_at = None
        expires_in = None
    else:
        # Normal validation
        if expires_at and expires_in:
            raise ValueError("Use only one of APP_CRED_EXPIRES_AT or APP_CRED_EXPIRES_IN.")
        if expires_in:
            expires_at = parse_duration_to_iso8601(expires_in)
        # Empty strings -> treat as None
        if expires_at and not expires_at.strip():
            expires_at = None

    access_rules = load_access_rules(access_rules_path)

    # Some keystone deployments require roles as objects; we already pass objects
    appcred = conn.identity.create_application_credential(
        user=conn.current_user_id,
        name=name,
        description=description,
        roles=roles,
        expires_at=expires_at,
        secret=secret,
        unrestricted=unrestricted,
        access_rules=access_rules,
    )
    return {
        "id": appcred.id,
        "name": appcred.name,
        "description": getattr(appcred, "description", None),
        "project_id": getattr(appcred, "project_id", None),
        "user_id": getattr(appcred, "user_id", None),
        "expires_at": getattr(appcred, "expires_at", None),
        "secret": getattr(appcred, "secret", None),  # shown only now
        "roles": roles,
        "unrestricted": unrestricted,
        "access_rules": access_rules,
    }


def upsert_secret(namespace: str, secret_name: str, payload: dict):
    """
    Upsert a Secret using stringData to avoid manual base64.
    """
    k8s_config.load_incluster_config()  # use Pod's SA token & CA; recommended in-cluster.  # noqa
    api = k8s.CoreV1Api()
    md = k8s.V1ObjectMeta(name=secret_name, namespace=namespace)
    body = k8s.V1Secret(
        api_version="v1",
        kind="Secret",
        metadata=md,
        type="Opaque",
        string_data={
            "id": payload.get("id") or "",
            "name": payload.get("name") or "",
            "secret": payload.get("secret") or "",
            "project_id": payload.get("project_id") or "",
            "user_id": payload.get("user_id") or "",
            "expires_at": payload.get("expires_at") or "",
            "unrestricted": str(payload.get("unrestricted", False)).lower(),
            # store structured bits as JSON strings:
            "roles.json": json.dumps(payload.get("roles") or []),
            "access_rules.json": json.dumps(payload.get("access_rules") or []),
        },
    )
    try:
        api.read_namespaced_secret(secret_name, namespace)
        # Patch (stringData merges and server encodes to data)
        api.patch_namespaced_secret(secret_name, namespace, body)
        print(f"Patched Secret '{namespace}/{secret_name}'.")
    except k8s.exceptions.ApiException as e:
        if e.status == 404:
            api.create_namespaced_secret(namespace, body)
            print(f"Created Secret '{namespace}/{secret_name}'.")
        else:
            raise


def main():
    # Read config from env
    cloud = os.getenv("OS_CLOUD")
    name = os.getenv("APP_CRED_NAME", "cicd-token")
    roles_csv = os.getenv("APP_CRED_ROLES", "")
    roles = [{"name": r.strip()} for r in roles_csv.split(",") if r.strip()] or None
    desc = os.getenv("APP_CRED_DESCRIPTION") or None
    """
    Create an application credential. If no_expiry is True, expires_* are ignored.
    """
    if no_expiry:
        expires_at = None
        expires_in = None
    else:
        expires_at = os.getenv("APP_CRED_EXPIRES_AT") or None
        expires_in = os.getenv("APP_CRED_EXPIRES_IN") or None
    fi
    secret = os.getenv("APP_CRED_SECRET") or None
    unrestricted = parse_bool(os.getenv("APP_CRED_UNRESTRICTED", "false"))
    access_rules_path = os.getenv("ACCESS_RULES_PATH") or None

    secret_name = os.getenv("OUTPUT_SECRET_NAME", "openstack-appcred")
    ns = os.getenv("OUTPUT_SECRET_NAMESPACE") or os.getenv("POD_NAMESPACE", "default")

    conn = connect_openstack(cloud)
    result = create_app_credential(
        conn,
        name=name,
        roles=roles,
        description=desc,
        expires_at=expires_at,
        expires_in=expires_in,
        secret=secret,
        unrestricted=unrestricted,
        access_rules_path=access_rules_path,
    )
    # Never print the secret to stdout in cluster logs; only write it to the k8s Secret.
    safe_result = {k: v for k, v in result.items() if k != "secret"}
    print(json.dumps({**safe_result, "message": "Stored in Kubernetes Secret."}, indent=2))
    upsert_secret(ns, secret_name, result)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)