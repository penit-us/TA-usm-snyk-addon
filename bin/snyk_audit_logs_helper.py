import json
import logging
import time
import datetime
import urllib.parse
import urllib.request
import urllib.error

import import_declare_test
from solnlib import conf_manager, log
from solnlib.modular_input.checkpointer import FileCheckpointer
from splunklib import modularinput as smi


ADDON_NAME = "TA-usm-snyk-addon"
SNYK_TOKEN_URL = "https://api.snyk.io/oauth/token"
SNYK_API_BASE = "https://api.snyk.io"


def logger_for_input(input_name: str) -> logging.Logger:
    return log.Logs().get_logger(f"{ADDON_NAME.lower()}_{input_name}")


def get_account(session_key: str, account_name: str):
    """Returns a dict with group_id, client_id, client_secret for the named account."""
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


def get_oauth_token(client_id: str, client_secret: str, logger: logging.Logger):
    """Performs the OAuth2 client_credentials grant. Returns an access_token string."""
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


def api_get(url: str, token: str, logger: logging.Logger, timeout=60):
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


def validate_input(definition: smi.ValidationDefinition):
    version = definition.parameters.get("version", None)
    if not version:
        raise ValueError("version is required, e.g. 2026-03-25")


def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    for input_name, input_item in inputs.inputs.items():
        normalized_input_name = input_name.split("/")[-1]
        logger = logger_for_input(normalized_input_name)

        try:
            session_key = inputs.metadata["session_key"]
            log_level = conf_manager.get_log_level(
                logger=logger,
                session_key=session_key,
                app_name=ADDON_NAME,
                conf_name="ta_usm_snyk_addon_settings",
            )
            logger.setLevel(log_level)
            log.modular_input_start(logger, normalized_input_name)

            # --- Input parameters -----------------------------------------------
            version = input_item.get("version")
            updated_after_param = (input_item.get("updated_after") or "").strip()
            page_limit_raw = (input_item.get("page_limit") or "").strip()
            page_limit = int(page_limit_raw) if page_limit_raw else 0
            index = input_item.get("index") or "default"
            account_name = input_item.get("account")

            # --- Account credentials ---------------------------------------------
            account = get_account(session_key, account_name)
            group_id = account["group_id"]
            client_id = account["client_id"]
            client_secret = account["client_secret"]

            if not (group_id and client_id and client_secret):
                logger.error(
                    f"Account '{account_name}' is missing group_id/client_id/client_secret. "
                    f"Check Configuration > Account."
                )
                continue

            # --- Checkpoint (per input stanza + group) ----------------------------
            checkpointer = FileCheckpointer(inputs.metadata["checkpoint_dir"])
            checkpoint_key = f"{normalized_input_name}_{group_id}"
            state = checkpointer.get(checkpoint_key) or {}

            default_lookback = (
                datetime.datetime.utcnow() - datetime.timedelta(hours=24)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            updated_after = state.get("last_updated_after") or updated_after_param or default_lookback
            run_started_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            # --- OAuth2 token exchange ---------------------------------------------
            access_token = get_oauth_token(client_id, client_secret, logger)

            # --- Paginated collection ------------------------------------------------
            next_url = (
                f"{SNYK_API_BASE}/rest/groups/{group_id}/audit_logs/search"
                f"?version={version}&from={updated_after}&limit=100"
            )

            event_count = 0
            pages_fetched = 0
            sourcetype = "snyk:audit_log"

            while next_url:
                page = api_get(next_url, access_token, logger)

                for record in page.get("data", []):
                    event_writer.write_event(
                        smi.Event(
                            data=json.dumps(record, ensure_ascii=False, default=str),
                            index=index,
                            sourcetype=sourcetype,
                            source=f"snyk://group/{group_id}/audit_logs",
                        )
                    )
                    event_count += 1

                pages_fetched += 1
                if page_limit and pages_fetched >= page_limit:
                    break

                next_link = page.get("links", {}).get("next")
                if not next_link:
                    break
                next_url = next_link if next_link.startswith("http") else SNYK_API_BASE + next_link

            # --- Advance checkpoint only after a fully successful pull ---------------
            checkpointer.update(checkpoint_key, {"last_updated_after": run_started_at})

            log.events_ingested(
                logger,
                input_name,
                sourcetype,
                event_count,
                index,
                account=account_name,
            )
            log.modular_input_end(logger, normalized_input_name)

        except Exception as e:
            log.log_exception(
                logger, e, "snyk_audit_logs_error",
                msg_before=f"Exception raised while collecting Snyk audit logs for {normalized_input_name}: "
            )
