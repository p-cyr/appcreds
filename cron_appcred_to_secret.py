#!/usr/bin/env python3
"""
Create an OpenStack Application Credential and upsert it into a Kubernetes Secret.

Key behaviors
-------------
- Optional expiry:
  * Unset/empty or tokens like "none", "null", "false", "disabled", "off", "n/a", "never"
    (case-insensitive) => **no expiry**.
  * APP_CRED_EXPIRES_IN: duration such as 90d, 12h, 30m, or combos like 7d12h (strict).
  * APP_CRED_EXPIRES_AT: absolute ISO8601 UTC timestamp (e.g., 2026-06-01T00:00:00Z).
  * If both are set to meaningful values, the script fails fast with a clear error.

- Roles are passed as objects (e.g., [{"name": "member"}]) to satisfy Keystone schemas that
  require role objects rather than strings.

- Uses openstacksdk and requires 'user=conn.current_user_id' for app-cred create on many SDKs.

- Upserts a Kubernetes Secret using in-cluster config, **not** printing the secret to stdout.

Environment
-----------
  OS_CLOUD                    -> cloud name in clouds.yaml
  APP_CRED_NAME               -> application credential name (default: "cicd-token")
  APP_CRED_ROLES              -> comma-separated role names, e.g. "member,reader" (optional)
  APP_CRED_DESCRIPTION        -> optional text
  APP_CRED_EXPIRES_IN         -> "90d", "12h", "30m", "7d12h", or "none"
  APP_CRED_EXPIRES_AT         -> ISO8601 UTC, or "false" / "none"
  APP_CRED_SECRET             -> optional custom secret (server generates if omitted)
  APP_CRED_UNRESTRICTED       -> "true"/"false" (default false)
  ACCESS_RULES_PATH           -> optional JSON or YAML file with access rules list
  APP_CRED_IF_EXISTS          -> "fail" (default) | "skip" | "replace"

  OUTPUT_SECRET_NAME          -> target Kubernetes Secret name (default: "openstack-appcred")
  OUTPUT_SECRET_NAMESPACE     -> defaults to POD_NAMESPACE (or "default" if not set)
  POD_NAMESPACE               -> injected from downward API (metadata.namespace)

Notes
-----
- Mount your clouds.yaml (and optional CA) in the container. openstacksdk auto-discovers
  /etc/openstack/clouds.yaml and honors OS_CLOUD.
"""
import re, os, sys, json, argparse, datetime as dt
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

NO_EXPIRY_TOKENS = {"none", "null", "false", "disabled", "off", "n/a", "never"}
DURATION_RE = re.compile(r"^(?=.{2,50}$)(\d+[dhm])+$", re.IGNORECASE)
# Examples: 90d, 12h, 30m, 7d12h, 10m30m (weird but acceptable). Adjust as you like.


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

def is_no_expiry(val: Optional[str]) -> bool:
    if val is None:
        return True  # treat unset as "no expiry"
    s = str(val).strip().lower()
    return (not s) or (s in NO_EXPIRY_TOKENS)

def is_duration(val: Optional[str]) -> bool:
    if not val:
        return False
    return bool(DURATION_RE.match(val.strip()))

def normalize_optional_expiry(env_expires_in: Optional[str], env_expires_at: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """
    Return (norm_in, norm_at, mode) where:
      - norm_in: duration string or None
      - norm_at: ISO string or None (we don't validate ISO format here)
      - mode: one of {"none","duration","absolute"}

    Rules:
      - Unset/empty or tokens in NO_EXPIRY_TOKENS => no expiry.
      - If both are set to meaningful values, raise.
      - Only pass a value to the duration parser if it matches DURATION_RE.
    """
    si = (env_expires_in or "").strip()
    sa = (env_expires_at or "").strip()

    # Decide each side independently
    in_none = is_no_expiry(si)
    at_none = is_no_expiry(sa)

    # If both sides present (and not interpreted as "no expiry"), it's a conflict
    if not in_none and not at_none:
        raise ValueError("Use only one of APP_CRED_EXPIRES_IN or APP_CRED_EXPIRES_AT, not both.")

    # Prefer absolute if provided and not “no expiry”
    if not at_none:
        return (None, sa, "absolute")

    # Else look at duration
    if not in_none:
        if is_duration(si):
            return (si, None, "duration")
        # At this point, user passed a non-duration string (e.g., 'none', 'n/a', '90x')
        raise ValueError(f"Invalid APP_CRED_EXPIRES_IN='{env_expires_in}'. "
                         f"Expected something like '90d', '12h', '30m', or combos like '7d12h'.")

    # No expiry
    return (None, None, "none")

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


# -------------------------
# Discovery / Delete helpers
# -------------------------

def list_app_creds_for_user(conn):
    """List app creds for the current user; be explicit with user param; fallback if needed."""
    try:
        return list(conn.identity.application_credentials(user=conn.current_user_id))
    except TypeError:
        return list(conn.identity.application_credentials())

def find_existing_app_credential(conn, name: str):
    """
    Return an existing application credential (resource) that matches the given name
    for the current user (and, if available, same project_id), or None if not found.
    """
    project_id = getattr(conn, "current_project_id", None)
    creds = list_app_creds_for_user(conn)
    for ac in creds:
        try:
            same_name = (ac.name == name)
            print(f"comparing '{ac.name}' with '{name}'")
            same_proj = (project_id is None) or (getattr(ac, "project_id", None) == project_id)
            if same_name and same_proj:
                return ac
        except Exception:
            # Be tolerant if resource object lacks some attrs
            if ac.name == name:
                return ac
    return None

def delete_app_credential(conn, appcred):
    """
    Robust delete across SDK variants.
    """
    try:
        conn.identity.delete_application_credential(
            application_credential=appcred,
            user=conn.current_user_id,
            ignore_missing=False,
        )
    except TypeError:
        try:
            conn.identity.delete_application_credential(
                application_credential=appcred,
                ignore_missing=False,
            )
        except TypeError:
            # positional fallback (older SDKs)
            conn.identity.delete_application_credential(appcred, conn.current_user_id, ignore_missing=False)

# -------------------------
# clouds.yaml generation
# -------------------------

def resolve_clouds_entry_name() -> str:
    # Prefer explicit entry name; else reuse OS_CLOUD; else 'mycloud'
    return (os.getenv("CLOUDS_ENTRY_NAME")
            or os.getenv("OS_CLOUD")
            or "mycloud").strip()

def read_custom_ca_if_requested() -> tuple[Optional[str], Optional[str]]:
    """
    If CLOUDS_INCLUDE_CA=true and CLOUDS_CA_FILE points to a readable PEM,
    return (pem_text, verify_path) where verify_path is CLOUDS_VERIFY_PATH (or CA file path).
    """
    if not parse_bool(os.getenv("CLOUDS_INCLUDE_CA", "false")):
        return (None, None)
    ca_path = os.getenv("CLOUDS_CA_FILE")
    if not ca_path:
        raise RuntimeError("CLOUDS_INCLUDE_CA=true but CLOUDS_CA_FILE is not set")
    try:
        with open(ca_path, "r", encoding="utf-8") as f:
            pem = f.read()
        verify_path = os.getenv("CLOUDS_VERIFY_PATH", ca_path)
        return (pem, verify_path)
    except Exception as e:
        raise RuntimeError(f"Failed to read CA from '{ca_path}': {e}")

def build_clouds_yaml_text(auth_url: str,
                           appcred_id: str,
                           appcred_secret: str,
                           entry_name: str,
                           region_name: Optional[str],
                           interface: Optional[str],
                           verify_path: Optional[str]) -> str:
    """
    Build a valid clouds.yaml with a single entry using v3applicationcredential auth.
    Use PyYAML if available; else compose minimal YAML text safely.
    """
    clouds_obj = {
        "clouds": {
            entry_name: {
                "auth_type": "v3applicationcredential",
                "auth": {
                    "auth_url": auth_url,
                    "application_credential_id": appcred_id,
                    "application_credential_secret": str(appcred_secret),
                }
            }
        }
    }
    if region_name:
        clouds_obj["clouds"][entry_name]["region_name"] = region_name
    if interface:
        clouds_obj["clouds"][entry_name]["interface"] = interface
    if verify_path:
        clouds_obj["clouds"][entry_name]["verify"] = verify_path
    #if cacert:
    #    clouds_obj["clouds"][entry_name]["cacert"] = cacert

    if HAS_YAML:
        return yaml.safe_dump(clouds_obj, sort_keys=False)
    # Fallback: manual YAML (simple and safe for this shape)
    lines = []
    lines.append("clouds:")
    lines.append(f"  {entry_name}:")
    lines.append(f"    auth_type: v3applicationcredential")
    lines.append(f"    auth:")
    lines.append(f"      auth_url: {auth_url}")
    lines.append(f"      application_credential_id: {appcred_id}")
    lines.append(f"      application_credential_secret: \"{appcred_secret}\"")
    if region_name:
        lines.append(f"    region_name: {region_name}")
    if interface:
        lines.append(f"    interface: {interface}")
    if verify_path:
        lines.append(f"    verify: {verify_path}")
    #if cacert:
    #    lines.append(f"    cacert: {cacert}")
    #    lines.append(f"    tls-insecure: true")
    return "\n".join(lines) + "\n"

def create_app_credential(
    conn,
    name: str,
    roles: Optional[List[dict]],
    description: Optional[str],
    expires_in: Optional[str],
    expires_at: Optional[str],
    secret: Optional[str],
    unrestricted: bool,
    access_rules_path: Optional[str],
    on_exists: Optional[str],
):
    # Check if an app-cred with this name already exists
    existing = find_existing_app_credential(conn, name)
    if existing is not None:
        msg = f"Application credential with name '{name}' already exists (id={existing.id})."
        if on_exists == "fail":
            raise RuntimeError(msg + " Set APP_CRED_IF_EXISTS=skip or replace if desired.")
        elif on_exists == "skip":
            print("[exists] " + msg + " Skipping creation.", file=sys.stderr)
            # We cannot recover the secret; just return minimal info
            return {
                "id": existing.id,
                "name": existing.name,
                "description": getattr(existing, "description", None),
                "project_id": getattr(existing, "project_id", None),
                "user_id": getattr(existing, "user_id", None),
                "expires_at": getattr(existing, "expires_at", None),
                "secret": None,
                "roles": roles,
                "unrestricted": unrestricted,
                "access_rules": load_access_rules(access_rules_path) if access_rules_path else [],
                "_skip_secret_update": True,  # sentinel for caller
            }
        elif on_exists == "replace":
            print("[exists] " + msg + " Replacing it (delete then create).", file=sys.stderr)
            delete_app_credential(conn, existing)
        else:
            raise RuntimeError(f"Unknown APP_CRED_IF_EXISTS='{on_exists}'. Use fail|skip|replace.")
    # Normalize expiry intent
    norm_in, norm_at, mode = normalize_optional_expiry(expires_in, expires_at)

    # Optional breadcrumb (comment out if not desired)
    print(f"[expiry] mode={mode} in='{norm_in}' at='{norm_at}'", file=sys.stderr)

    if mode == "duration":
        norm_at = parse_duration_to_iso8601(norm_in)

    access_rules = load_access_rules(access_rules_path)

    # Some keystone deployments require roles as objects; we already pass objects
    appcred = conn.identity.create_application_credential(
        user=conn.current_user_id,
        name=name,
        description=description,
        roles=roles,            # e.g., [{"name": "member"}]
        expires_at=norm_at,     # None => no expiry
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
        "_skip_secret_update": False,
    }


def upsert_secret_with_clouds(namespace: str,
                              secret_name: str,
                              payload: dict,
                              clouds_yaml_text: Optional[str],
                              ca_pem: Optional[str]):
    """
    Upsert Secret using stringData with:
      - clouds.yaml (if provided),
      - custom-ca.pem (if provided),
      - and metadata JSON keys for convenience.
    """
    k8s_config.load_incluster_config()
    api = k8s.CoreV1Api()

    string_data = {
        # Metadata / convenience
        "id": payload.get("id") or "",
        "name": payload.get("name") or "",
        "secret": payload.get("secret") or "",
        "project_id": payload.get("project_id") or "",
        "user_id": payload.get("user_id") or "",
        "expires_at": payload.get("expires_at") or "",
        "unrestricted": str(payload.get("unrestricted", False)).lower(),
        "roles.json": json.dumps(payload.get("roles") or []),
        "access_rules.json": json.dumps(payload.get("access_rules") or []),
    }
    if clouds_yaml_text:
        string_data["clouds.yaml"] = clouds_yaml_text
    if ca_pem:
        string_data["custom-ca.pem"] = ca_pem

    body = k8s.V1Secret(
        api_version="v1",
        kind="Secret",
        metadata=k8s.V1ObjectMeta(name=secret_name, namespace=namespace),
        type="Opaque",
        string_data=string_data,
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
    expires_at = os.getenv("APP_CRED_EXPIRES_AT") or None
    expires_in = os.getenv("APP_CRED_EXPIRES_IN") or None
    secret = os.getenv("APP_CRED_SECRET") or None
    unrestricted = parse_bool(os.getenv("APP_CRED_UNRESTRICTED", "false"))
    access_rules_path = os.getenv("ACCESS_RULES_PATH") or None
    on_exists = (os.getenv("APP_CRED_IF_EXISTS", "fail") or "fail").strip().lower()

    secret_name = os.getenv("OUTPUT_SECRET_NAME", "openstack-appcred")
    ns = os.getenv("OUTPUT_SECRET_NAMESPACE") or os.getenv("POD_NAMESPACE", "default")

        # clouds.yaml entry parameters
    clouds_entry_name = resolve_clouds_entry_name()
    region_override = os.getenv("CLOUDS_REGION_NAME")
    interface_override = os.getenv("CLOUDS_INTERFACE")
    #ca_pem, verify_path = read_custom_ca_if_requested()
    #cacert_override = os.getenv("APP_CRED_CA_CERT")

    try:
        conn = connect_openstack(cloud)
        creds = list_app_creds_for_user(conn)
        for cred in creds:
            print(f"{cred.id} - {cred.name} (Expires: {cred.expires_at})")
        result = create_app_credential(
            conn,
            name=name,
            roles=roles,
            description=desc,
            expires_in=expires_in,
            expires_at=expires_at,
            secret=secret,
            unrestricted=unrestricted,
            access_rules_path=access_rules_path,
            on_exists=on_exists,
        )

        # Never print the secret to stdout in cluster logs; only write it to the k8s Secret.
        if result.get("_skip_secret_update"):
            safe = {k: v for k, v in result.items() if k not in ("secret", "_skip_secret_update")}
            print(json.dumps({**safe, "message": "Existing app-cred found; skipped creation and Secret update."}, indent=2))
            sys.exit(0)

        # Build clouds.yaml using connection config + new credential
        auth_url = conn.config.auth["auth_url"]
        region_name = region_override or getattr(conn.config, "region_name", None)
        interface = interface_override or getattr(conn.config, "interface", None)
        #cacert = cacert_override or getattr(conn.config, "cacert", None)

        clouds_yaml_text = build_clouds_yaml_text(
            auth_url=auth_url,
            appcred_id=result["id"],
            appcred_secret=result["secret"],
            entry_name=clouds_entry_name,
            region_name=region_name,
            interface=interface,
        #    cacert=cacert,
            verify_path=verify_path,
        )

        # Log safe summary (do not print secret)
        safe = {k: v for k, v in result.items() if k not in ("secret", "_skip_secret_update")}
        print(json.dumps({**safe, "message": "Created app-cred and wrote clouds.yaml to Secret."}, indent=2))

        # Upsert Secret with clouds.yaml (+ optional custom CA) and metadata JSON keys
        upsert_secret_with_clouds(ns, secret_name, result, clouds_yaml_text, ca_pem)

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()