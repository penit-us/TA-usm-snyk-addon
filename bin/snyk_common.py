"""
Shared logic for all Snyk modular inputs (snyk_audit_logs, snyk_issues, snyk_projects).

Each *_helper.py file owns only the input-specific bits:
  - which input parameters it reads
  - the endpoint URL / query params
  - how to pull the record list out of a page's JSON (varies per endpoint)
  - sourcetype and default lookback window

Everything else (OAuth, account lookup, retry/backoff, pagination walking,
checkpointing) lives here so it's written and fixed exactly once.
"""

import json
import time
import logging
import datetime
import urllib.parse
import urllib.request
import urllib.error

from solnlib import conf_manager, log
from solnlib.modular_input.checkpointer import FileCheckpointer

ADDON_NAME = "TA-usm-snyk-addon"
SNYK_TOKEN_URL = "https://api.snyk.io/oauth2/token"
SNYK_API_BASE = "https://api.snyk.io"


def logger_for_input(input_name: str) -> logging.Logger:
    return log.Logs().get_logger(f"{ADDON_NAME.lower()}_{input_name}")


def get_account(session_key: str, account_name: str) -> dict:
    """Returns {group_id, client_id, client_secret} for the named Account entry."""
    cfm = conf_manager.ConfManager(
        session_key,
        ADDON_NAME,
        realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-ta_usm_snyk_addon_account",
    )
    account_conf_file = cfm.get_conf("ta_usm_snyk_addon_account")
    account = account_conf_file.get(account_name)
    return {
        "group_id": account.get("group_id"),
        "client_id": account.get("client_id"),
        "client_secret": account.get("client_secret"),
    }


def get_oauth_token(client_id: str, client_secret: str, logger: logging.Logger) -> str:
    """OAuth2 client_credentials grant. Returns an access_token string."""
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }).encode("utf-8")

    req = urllib.request.Request(
        SNYK_TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            f"OAuth token request failed: HTTP {e.code} {e.read().decode('utf-8', 'ignore')}"
        )

    access_token = data.get("access_token")
    if not access_token:
        raise RuntimeError("No access_token in OAuth response")
    return access_token


def api_get(url: str, token: str, logger: logging.Logger, timeout: int = 60) -> dict:
    """Single GET against the Snyk REST API, with one automatic retry on 429."""
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/vnd.api+json",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            retry_after = int(e.headers.get("Retry-After", "5"))
            logger.warning(f"Rate limited by Snyk API, retrying in {retry_after}s")
            time.sleep(retry_after)
            return api_get(url, token, logger, timeout=timeout)
        body = e.read().decode("utf-8", "ignore")
        raise RuntimeError(f"GET {url} failed: HTTP {e.code} {body}")


def paginate(start_url: str, token: str, logger: logging.Logger, extract_items, page_limit: int = 0):
    """
    Walks Snyk's cursor-based pagination (links.next), yielding one record at a time.

    `extract_items(page)` is a caller-supplied function that pulls the record
    list out of a page's JSON body. This differs per endpoint -- e.g. Audit
    Logs nests records under data.items, while other endpoints may return a
    flat data[] array -- so each input helper supplies its own extractor
    rather than this shared function guessing the shape.
    """
    next_url = start_url
    pages_fetched = 0

    while next_url:
        page = api_get(next_url, token, logger)

        for record in extract_items(page):
            yield record

        pages_fetched += 1
        if page_limit and pages_fetched >= page_limit:
            break

        next_link = page.get("links", {}).get("next")
        if not next_link:
            break
        next_url = next_link if next_link.startswith("http") else SNYK_API_BASE + next_link


def get_checkpointer(checkpoint_dir: str) -> FileCheckpointer:
    return FileCheckpointer(checkpoint_dir)


def get_orgs_for_group(group_id: str, token: str, version: str, logger: logging.Logger):
    """Returns [{'id': org_id, 'name': org_name}, ...] for a group, via the Orgs API."""
    url = f"{SNYK_API_BASE}/rest/groups/{group_id}/orgs?version={version}&limit=100"
    orgs = []
    for record in paginate(url, token, logger, lambda page: page.get("data", [])):
        orgs.append({
            "id": record.get("id"),
            "name": record.get("attributes", {}).get("name", record.get("id")),
        })
    return orgs


def get_orgs_cached(checkpointer: FileCheckpointer, cache_key: str, group_id: str, token: str,
                     version: str, logger: logging.Logger, max_age_hours: int = 24):
    """
    Returns a group's org list, re-discovering via the API only if the cached
    copy is missing or older than max_age_hours. Avoids hitting the Orgs API
    on every single run for groups whose org list rarely changes.
    """
    state = checkpointer.get(cache_key) or {}
    now = time.time()

    if state and (now - state.get("fetched_at", 0)) < max_age_hours * 3600:
        return state.get("orgs", [])

    orgs = get_orgs_for_group(group_id, token, version, logger)
    checkpointer.update(cache_key, {"fetched_at": now, "orgs": orgs})
    return orgs


def get_projects_for_org(org_id: str, token: str, version: str, logger: logging.Logger):
    """Returns [{'id': project_id, 'name': project_name}, ...] for an org."""
    url = f"{SNYK_API_BASE}/rest/orgs/{org_id}/projects?version={version}&limit=100"
    projects = []
    for record in paginate(url, token, logger, lambda page: page.get("data", [])):
        projects.append({
            "id": record.get("id"),
            "name": record.get("attributes", {}).get("name", record.get("id")),
        })
    return projects


KV_COLLECTION_NAME = "snyk_group_org_project"


def _kv_service(session_key: str):
    """
    Connects to the local Splunk management port using the modular input's
    session key -- standard pattern for on-box REST/KV Store calls from
    within a running input, no separate credentials needed.
    """
    import splunklib.client as sclient
    return sclient.Service(token=session_key, app=ADDON_NAME)


def discover_group(session_key: str, group_id: str, token: str, version: str, logger: logging.Logger):
    """
    Live-discovers this group's orgs and projects via the Snyk API, and
    upserts the current (group_id, org_id, project_id) associations into the
    snyk_group_org_project KV Store collection. batch_save replaces any
    existing row with the same _key, so the collection always reflects only
    the latest known state -- no history accumulates.

    Returns [{"id", "name", "projects": [...]}] for the group's orgs, so
    callers that need the org/project list for their own collection loop
    (Issues, Projects) can use this single call instead of a separate
    discovery round-trip.

    Discovery failures are logged and swallowed rather than raised, since a
    KV Store or Orgs/Projects API hiccup here should not take down the
    primary Audit Logs / Issues collection that triggered it.
    """
    discovered_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    orgs_with_projects = []

    try:
        orgs = get_orgs_for_group(group_id, token, version, logger)
    except Exception as e:
        logger.warning(f"discover_group: org discovery failed for group={group_id}: {e}")
        return orgs_with_projects

    records = []
    for org in orgs:
        org_id = org["id"]
        try:
            projects = get_projects_for_org(org_id, token, version, logger)
        except Exception as e:
            logger.warning(f"discover_group: project discovery failed for org={org_id}: {e}")
            projects = []

        orgs_with_projects.append({**org, "projects": projects})

        if not projects:
            records.append({
                "_key": f"{group_id}_{org_id}_none",
                "group_id": group_id,
                "org_id": org_id,
                "org_name": org.get("name", org_id),
                "project_id": "",
                "project_name": "",
                "discovered_at": discovered_at,
            })
        else:
            for project in projects:
                records.append({
                    "_key": f"{group_id}_{org_id}_{project['id']}",
                    "group_id": group_id,
                    "org_id": org_id,
                    "org_name": org.get("name", org_id),
                    "project_id": project["id"],
                    "project_name": project.get("name", project["id"]),
                    "discovered_at": discovered_at,
                })

    if records:
        try:
            service = _kv_service(session_key)
            service.kvstore[KV_COLLECTION_NAME].data.batch_save(*records)
        except Exception as e:
            logger.warning(f"discover_group: KV Store update failed for group={group_id}: {e}")

    return orgs_with_projects


def get_orgs_from_kv(session_key: str, group_id: str, logger: logging.Logger):
    """
    Reads this group's distinct orgs from the KV Store inventory (populated by
    discover_group). Returns [] if the collection has no rows for this group
    yet -- callers should treat that as "not discovered yet", not "zero orgs".
    """
    try:
        service = _kv_service(session_key)
        query = json.dumps({"group_id": group_id})
        rows = service.kvstore[KV_COLLECTION_NAME].data.query(query=query)
    except Exception as e:
        logger.warning(f"get_orgs_from_kv: KV Store query failed for group={group_id}: {e}")
        return []

    seen = {}
    for row in rows:
        org_id = row.get("org_id")
        if org_id and org_id not in seen:
            seen[org_id] = {"id": org_id, "name": row.get("org_name", org_id)}
    return list(seen.values())


def get_orgs_with_fallback(session_key: str, group_id: str, token: str, version: str,
                            logger: logging.Logger):
    """
    Returns this group's orgs, preferring the KV Store inventory (fast, no
    live API call). Falls back to a live discover_group() call -- which also
    (re)populates the KV Store for next time -- only when the KV Store has no
    rows yet for this group (e.g. a brand-new group, or discovery hasn't run
    for it yet). This is the function Issues and Projects should call; they
    should not call discover_group() directly.
    """
    orgs = get_orgs_from_kv(session_key, group_id, logger)
    if orgs:
        return orgs

    logger.info(f"No KV Store inventory yet for group={group_id}; falling back to live discovery.")
    orgs_with_projects = discover_group(session_key, group_id, token, version, logger)
    return [{"id": o["id"], "name": o.get("name")} for o in orgs_with_projects]
