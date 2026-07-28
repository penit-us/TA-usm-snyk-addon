import json
import datetime

import import_declare_test
from solnlib import conf_manager, log
from splunklib import modularinput as smi

import snyk_common as sc

INPUT_TYPE = "snyk_audit_logs"
SOURCETYPE = "snyk:audit:log"
DEFAULT_LOOKBACK_HOURS = 24


def extract_items(page: dict):
    """Audit Logs nests its record list under data.items (confirmed against Snyk docs)."""
    return page.get("data", {}).get("items", [])


def validate_input(definition: smi.ValidationDefinition):
    version = definition.parameters.get("version", None)
    if not version:
        raise ValueError("version is required, e.g. 2026-03-25")


def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    for input_name, input_item in inputs.inputs.items():
        normalized_input_name = input_name.split("/")[-1]
        logger = sc.logger_for_input(normalized_input_name)

        try:
            session_key = inputs.metadata["session_key"]
            log_level = conf_manager.get_log_level(
                logger=logger,
                session_key=session_key,
                app_name=sc.ADDON_NAME,
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
            account = sc.get_account(session_key, account_name)
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
            checkpointer = sc.get_checkpointer(inputs.metadata["checkpoint_dir"])
            checkpoint_key = f"{normalized_input_name}_{group_id}"
            state = checkpointer.get(checkpoint_key) or {}

            default_lookback = (
                datetime.datetime.utcnow() - datetime.timedelta(hours=DEFAULT_LOOKBACK_HOURS)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            updated_after = state.get("last_updated_after") or updated_after_param or default_lookback
            run_started_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            # --- OAuth2 token exchange ---------------------------------------------
            access_token = sc.get_oauth_token(client_id, client_secret, logger)

            # --- Opportunistic discovery: refresh KV Store org/project inventory ---
            sc.discover_group(session_key, group_id, access_token, version, logger)

            # --- Paginated collection ------------------------------------------------
            start_url = (
                f"{sc.SNYK_API_BASE}/rest/groups/{group_id}/audit_logs/search"
                f"?version={version}&from={updated_after}&limit=100"
            )

            event_count = 0
            for record in sc.paginate(start_url, access_token, logger, extract_items, page_limit=page_limit):
                event_writer.write_event(
                    smi.Event(
                        data=json.dumps(record, ensure_ascii=False, default=str),
                        index=index,
                        sourcetype=SOURCETYPE,
                        source=f"snyk://group/{group_id}/audit_logs",
                    )
                )
                event_count += 1

            # --- Advance checkpoint only after a fully successful pull ---------------
            checkpointer.update(checkpoint_key, {"last_updated_after": run_started_at})

            log.events_ingested(
                logger, input_name, SOURCETYPE, event_count, index, account=account_name,
            )
            log.modular_input_end(logger, normalized_input_name)

        except Exception as e:
            log.log_exception(
                logger, e, "snyk_audit_logs_error",
                msg_before=f"Exception raised while collecting Snyk audit logs for {normalized_input_name}: "
            )
