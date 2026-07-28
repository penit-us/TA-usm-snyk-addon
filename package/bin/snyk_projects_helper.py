import json
import datetime

import import_declare_test
from solnlib import conf_manager, log
from splunklib import modularinput as smi

import snyk_common as sc

INPUT_TYPE = "snyk_projects"
SOURCETYPE = "snyk:rest:project"


def extract_items(page: dict):
    """Projects follows standard JSON:API -- data is a flat array of {id, type, attributes}."""
    return page.get("data", [])


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

            checkpointer = sc.get_checkpointer(inputs.metadata["checkpoint_dir"])

            # --- OAuth2 token exchange ---------------------------------------------
            access_token = sc.get_oauth_token(client_id, client_secret, logger)

            # --- Orgs for this group: KV Store first, live discovery as fallback ----
            orgs = sc.get_orgs_with_fallback(session_key, group_id, access_token, version, logger)

            if not orgs:
                logger.warning(f"No orgs found for group {group_id}; nothing to collect.")
                log.modular_input_end(logger, normalized_input_name)
                continue

            # --- Collect projects per org ---------------------------------------------
            for org in orgs:
                org_id = org["id"]
                checkpoint_key = f"{normalized_input_name}_{org_id}"
                run_started_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

                start_url = f"{sc.SNYK_API_BASE}/rest/orgs/{org_id}/projects?version={version}&limit=100"
                if updated_after_param:
                    start_url += f"&updated_after={updated_after_param}"

                event_count = 0
                try:
                    for record in sc.paginate(
                        start_url, access_token, logger, extract_items, page_limit=page_limit
                    ):
                        event_writer.write_event(
                            smi.Event(
                                data=json.dumps(record, ensure_ascii=False, default=str),
                                index=index,
                                sourcetype=SOURCETYPE,
                                source=f"snyk://group/{group_id}/org/{org_id}/projects",
                            )
                        )
                        event_count += 1
                except Exception as e:
                    logger.error(f"org={org_id}: {e}")
                    continue

                checkpointer.update(checkpoint_key, {"last_run_at": run_started_at})
                log.events_ingested(
                    logger, input_name, SOURCETYPE, event_count, index, account=account_name,
                )

            log.modular_input_end(logger, normalized_input_name)

        except Exception as e:
            log.log_exception(
                logger, e, "snyk_projects_error",
                msg_before=f"Exception raised while collecting Snyk projects for {normalized_input_name}: "
            )
