# Copyright (c) 2025-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# src/app.py
import time
from collections.abc import Iterator
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import requests
import json
from urllib.parse import quote


from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.params import Params, Param, OnPollParams
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.asset import BaseAsset, AssetField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.models.container import Container
from soar_sdk.models.artifact import Artifact


logger = getLogger()


# ========================================
# 1. PARAMS
# ========================================
class CreateAlertParams(Params):
    entity: str = Param(description="Entity (domain/email/etc)", required=True)
    brand: str = Param(description="Brand name", required=False)
    source: str = Param(description="Source system", required=False)


class GetAlertParams(Params):
    id: str = Param(description="Alert ID", required=False)
    entity: str = Param(description="Entity", required=False)


class GetAllAlertsParams(Params):
    search_key: str = Param(description="Search term", required=False)
    queue_state: str = Param(
        description="Queue state",
        required=False,
        value_list=[
            "doppel_review",
            "needs_confirmation",
            "actioned",
            "taken_down",
            "monitoring",
            "archived",
        ],
    )
    product: str = Param(
        description="Product",
        required=False,
        value_list=[
            "domains",
            "social_media",
            "mobile_apps",
            "ecommerce",
            "crypto",
            "email",
            "paid_ads",
            "telco",
            "darkweb",
        ],
    )
    created_before: str = Param(description="ISO timestamp", required=False)
    created_after: str = Param(description="ISO timestamp", required=False)
    last_activity_timestamp: str = Param(description="ISO timestamp", required=False)
    tags: str = Param(description="Comma-separated tags", required=False)
    page: int = Param(description="Page number (0-based)", required=False, default=0)
    page_size: int = Param(
        description="Number of alerts per page", required=False, default=100
    )


class UpdateAlertParams(Params):
    id: str = Param(description="Alert ID", required=False)
    entity: str = Param(description="Entity", required=False)
    queue_state: str = Param(
        description="New queue state",
        required=False,
        value_list=[
            "doppel_review",
            "needs_confirmation",
            "actioned",
            "taken_down",
            "monitoring",
            "archived",
        ],
    )
    entity_state: str = Param(
        description="New entity state",
        required=False,
        value_list=["active", "down", "parked"],
    )
    comment: str = Param(description="Comment to add", required=False)
    tag_action: str = Param(description="add/remove", required=False)
    tag_name: str = Param(description="Tag name", required=False)


# ========================================
# 2. ASSET
# ========================================
class Asset(BaseAsset):
    doppel_api_key: str = AssetField(
        sensitive=True, description="Doppel API Key", required=True
    )
    user_api_key: str = AssetField(
        sensitive=True, description="Optional User API Key", required=False
    )
    org_code: str = AssetField(description="Optional Organization Code", required=False)
    historical_polling_days: int = AssetField(
        description="Number of days to look back for initial polling (default: 30)",
        required=False,
        default=30,
    )


# ========================================
# 3. CUSTOM ACTION OUTPUTS
# ========================================
class BaseAlertOutput(ActionOutput):
    """Base output model for Doppel Alerts"""

    id: str | None = OutputField(example_values=["TST-123"])
    entity: str | None = OutputField(example_values=["example.com"])
    severity: str | None = OutputField(example_values=["high", "medium"])
    queue_state: str | None = OutputField(example_values=["doppel_review"])
    entity_state: str | None = OutputField(example_values=["active", "down"])
    doppel_link: str | None = OutputField(
        example_values=["https://app.doppel.com/alert/TST-123"]
    )


class CreateAlertOutput(BaseAlertOutput):
    success: bool = OutputField(example_values=[True])


class GetAlertOutput(BaseAlertOutput):
    pass


class GetAllAlertsOutput(BaseAlertOutput):
    pass


class UpdateAlertOutput(BaseAlertOutput):
    success: bool = OutputField(example_values=[True])


# ========================================
# 4. APP
# ========================================
app = App(
    name="Doppel",
    app_type="generic",
    logo="logo.svg",
    logo_dark="logo_dark.svg",
    product_vendor="Doppel",
    product_name="doppel",
    publisher="Doppel",
    appid="88e88f59-5c78-457b-9d81-1f41f9fd2096",
    min_phantom_version="6.4.0",
    fips_compliant=True,
    asset_cls=Asset,
)


# ========================================
# 5. API HELPER
# ========================================
def _make_request(
    asset: Asset,
    method: str,
    endpoint: str,
    params: dict | None = None,
    data: dict | None = None,
) -> tuple[bool, int, dict, str]:
    url = f"https://api.doppel.com/v1{endpoint}"
    headers = {
        "x-api-key": asset.doppel_api_key.strip() if asset.doppel_api_key else "",
        "Content-Type": "application/json",
    }
    if asset.user_api_key:
        headers["x-user-api-key"] = asset.user_api_key.strip()
    if asset.org_code:
        headers["x-organization-code"] = asset.org_code.strip()

    logger.info(f"API CALL: {method} {endpoint}")

    for attempt in range(3):
        try:
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=data,
                timeout=30,
            )
            logger.info(f"API RESPONSE: status={resp.status_code}")

            if resp.status_code == 429:
                logger.warning(f"Rate-limited, retry {attempt + 1}/3")
                time.sleep(10)
                continue

            if resp.ok:
                try:
                    json_body = resp.json()
                    return True, resp.status_code, json_body, ""
                except ValueError as exc:
                    logger.error(f"Invalid JSON response: {exc}")
                    return False, resp.status_code, {}, f"Invalid JSON response: {exc}"
            else:
                err = resp.text[:1000]
                try:
                    json_err = resp.json()
                    err = json_err.get("message") or json_err.get("error") or err
                except ValueError:
                    pass
                logger.error(f"HTTP {resp.status_code}: {err}")
                return False, resp.status_code, {}, f"HTTP {resp.status_code}: {err}"

        except Exception as exc:
            logger.error(f"Request failed (attempt {attempt + 1}): {exc}")
            if attempt < 2:
                time.sleep(2**attempt)
            else:
                return False, 0, {}, f"Request failed: {exc}"

    return False, 0, {}, "Max retries exceeded"


# ========================================
# 6. TEST CONNECTIVITY
# ========================================
@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    ok, status_code, data, error = _make_request(
        asset, "GET", "/alerts", params={"page_size": 1}
    )
    if ok:
        logger.info("Connectivity test passed")
    else:
        logger.error(f"Connectivity test failed: {error}")
        raise ActionFailure(error)


# ========================================
# 7. ACTIONS
# ========================================
@app.action(
    description="Create a new alert in Doppel for a specific entity.",
    action_type="generic",
    read_only=False,
)
def create_alert(
    params: CreateAlertParams, asset: Asset, soar: SOARClient
) -> CreateAlertOutput:
    logger.info("create_alert started")
    payload = {"entity": params.entity}
    if params.brand:
        payload["brand"] = params.brand
    if params.source:
        payload["source"] = params.source

    ok, status_code, data, error = _make_request(asset, "POST", "/alert", data=payload)
    if not ok or not data:
        raise ActionFailure(f"Failed to create alert. HTTP {status_code}: {error}")

    logger.info(f"Alert created: {data.get('id')}")
    return CreateAlertOutput(
        id=data.get("id"),
        entity=data.get("entity"),
        severity=data.get("severity"),
        queue_state=data.get("queue_state"),
        entity_state=data.get("entity_state"),
        doppel_link=data.get("doppel_link"),
    )


@app.action(
    description="Fetch details of a specific Doppel alert by its ID or entity.",
    action_type="investigate",
    read_only=True,
)
def get_alert(params: GetAlertParams, asset: Asset, soar: SOARClient) -> GetAlertOutput:
    logger.info("get_alert started")
    if (params.id and params.entity) or not (params.id or params.entity):
        raise ActionFailure(
            "Invalid parameters: Provide exactly one of 'id' or 'entity'"
        )

    query_params = params.model_dump(exclude_none=True)
    ok, status_code, data, error = _make_request(
        asset, "GET", "/alert", params=query_params
    )

    if not ok or not data:
        identifier = params.id or params.entity
        raise ActionFailure(
            f"No alert found for {identifier}. HTTP {status_code}: {error}"
        )

    alert_data = data[0] if isinstance(data, list) and len(data) > 0 else data
    logger.info(f"Alert found: {alert_data.get('id')}")

    return GetAlertOutput(
        id=alert_data.get("id"),
        entity=alert_data.get("entity"),
        severity=alert_data.get("severity"),
        queue_state=alert_data.get("queue_state"),
        entity_state=alert_data.get("entity_state"),
        doppel_link=alert_data.get("doppel_link"),
    )


@app.action(
    description="Retrieve multiple Doppel alerts based on search criteria and filters.",
    action_type="investigate",
    read_only=True,
)
def get_all_alerts(
    params: GetAllAlertsParams, asset: Asset, soar: SOARClient
) -> list[GetAllAlertsOutput]:
    logger.info("get_all_alerts started")
    query_params = params.model_dump(exclude_none=True)

    ok, status_code, data, error = _make_request(
        asset, "GET", "/alerts", params=query_params
    )
    if not ok:
        raise ActionFailure(f"Failed to fetch alerts. HTTP {status_code}: {error}")

    alerts = data.get("alerts", []) if isinstance(data, dict) else []
    logger.info(f"Fetched {len(alerts)} alerts")

    return [
        GetAllAlertsOutput(
            id=alert.get("id"),
            entity=alert.get("entity"),
            severity=alert.get("severity"),
            queue_state=alert.get("queue_state"),
            entity_state=alert.get("entity_state"),
            doppel_link=alert.get("doppel_link"),
        )
        for alert in alerts
    ]


@app.action(
    description="Update an existing Doppel alert's queue state, entity state or comment.",
    action_type="generic",
    read_only=False,
)
def update_alert(
    params: UpdateAlertParams, asset: Asset, soar: SOARClient
) -> UpdateAlertOutput:
    logger.info("update_alert started")
    if (params.id and params.entity) or not (params.id or params.entity):
        raise ActionFailure(
            "Invalid parameters: Provide exactly one of 'id' or 'entity'"
        )

    query_params = {"id": params.id} if params.id else {"entity": params.entity}
    payload = params.model_dump(exclude={"id", "entity"}, exclude_none=True)

    if not payload:
        raise ActionFailure("No fields provided to update")

    ok, status_code, data, error = _make_request(
        asset, "PUT", "/alert", params=query_params, data=payload
    )
    if not ok or not data:
        raise ActionFailure(f"Failed to update alert. HTTP {status_code}: {error}")

    logger.info(f"Alert updated for {params.id or params.entity}")
    return UpdateAlertOutput(
        id=data.get("id"),
        entity=data.get("entity"),
        severity=data.get("severity"),
        queue_state=data.get("queue_state"),
        entity_state=data.get("entity_state"),
        doppel_link=data.get("doppel_link"),
    )


# ========================================
# 8. HELPER FUNCTIONS
# ========================================
def get_existing_container(soar: SOARClient, sdi: str) -> dict | None:
    try:
        encoded_sdi = quote(sdi, safe="")
        response = soar.get(
            f'rest/container?_filter_source_data_identifier="{encoded_sdi}"'
        )
        data = response.json()
        containers = data.get("data", [])
        return containers[0] if containers else None
    except Exception as e:
        logger.error(f"Failed to query container for SDI {sdi}: {e}")
        return None


def update_container(soar: SOARClient, container_id: int, container: Container) -> bool:
    update_payload = {
        "name": container.name,
        "severity": container.severity.lower()
        if isinstance(container.severity, str)
        else "medium",
        "description": container.description,
        "label": container.label,
        "run_automation": container.run_automation,
    }
    try:
        response = soar.post(f"rest/container/{container_id}", json=update_payload)
        data = response.json()
        return data.get("success", False) and data.get("id") == container_id
    except Exception as e:
        logger.error(f"Failed to update container {container_id}: {e}")
        return False


def get_existing_artifact(soar: SOARClient, sdi: str, container_id: int) -> dict | None:
    try:
        encoded_sdi = quote(sdi, safe="")
        response = soar.get(
            f'rest/artifact?_filter_source_data_identifier="{encoded_sdi}"&_filter_container={container_id}'
        )
        data = response.json()
        artifacts = data.get("data", [])
        return artifacts[0] if artifacts else None
    except Exception as e:
        logger.error(f"Failed to query artifact for SDI {sdi}: {e}")
        return None


def update_artifact(soar: SOARClient, artifact_id: int, artifact: Artifact) -> bool:
    sanitized_cef = {k: v for k, v in artifact.cef.items() if v is not None}
    update_payload = {
        "name": artifact.name,
        "label": artifact.label,
        "type": artifact.type,
        "cef": sanitized_cef,
        "description": artifact.description,
        "run_automation": artifact.run_automation,
    }
    try:
        response = soar.post(f"rest/artifact/{artifact_id}", json=update_payload)
        data = response.json()
        return data.get("success", False) and data.get("id") == artifact_id
    except Exception as e:
        logger.error(f"Failed to update artifact {artifact_id}: {e}")
        return False


# ========================================
# 9. ON POLL
# ========================================
@app.on_poll()
def on_poll(
    params: OnPollParams, asset: Asset, soar: SOARClient
) -> Iterator[Container | Artifact]:
    logger.info("DOPPEL POLLING STARTED")

    is_manual = params.is_manual_poll()

    now_utc = datetime.now(ZoneInfo("UTC"))
    state = asset.ingest_state or {}

    # Determine start timestamp for querying alerts
    if is_manual:
        start_ts = (now_utc - timedelta(days=asset.historical_polling_days)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        logger.info(
            f"Manual Poll: Fetching historical data since {start_ts} ({asset.historical_polling_days} days)"
        )
    else:
        # Scheduled poll: use saved last_poll_time or fallback to historical on first run
        last_poll_time = state.get("last_poll_time")
        if not last_poll_time:
            start_ts = (
                now_utc - timedelta(days=asset.historical_polling_days)
            ).strftime("%Y-%m-%dT%H:%M:%S")
            logger.info(
                f"Scheduled Poll (first run): Fetching historical data since {start_ts}"
            )
        else:
            start_ts = last_poll_time
            logger.info(
                f"Scheduled Poll: Fetching alerts with activity since {start_ts}"
            )

    base_params = {"last_activity_timestamp": start_ts, "page_size": 100}

    page = 0
    containers_added = containers_updated = containers_failed = 0
    artifacts_added = artifacts_updated = artifacts_failed = 0
    audit_artifacts_added = audit_artifacts_skipped = audit_artifacts_failed = 0
    total_processed = 0

    while True:
        query_params = base_params.copy()
        query_params["page"] = page

        success, status_code, resp, error = _make_request(
            asset, "GET", "/alerts", params=query_params
        )
        if not success:
            logger.error(f"API failed on page {page}: {error}")
            break

        alerts = resp.get("alerts", []) if isinstance(resp, dict) else []
        logger.info(f"Page {page}: {len(alerts)} alerts")

        if not alerts:
            break

        for alert in alerts:
            alert_id = alert.get("id", "unknown")
            entity = alert.get("entity", "unknown")
            unique_sdi = alert_id

            severity = (alert.get("severity") or "medium").lower()
            if severity not in ("low", "medium", "high", "critical"):
                severity = "medium"

            container = Container(
                name=f"Doppel Alert: {alert_id}",
                severity=severity,
                source_data_identifier=unique_sdi,
                description=None,
                run_automation=False,
            )

            existing_container = get_existing_container(soar, unique_sdi)
            container_id = None

            if existing_container:
                container_id = existing_container["id"]
                if update_container(soar, container_id, container):
                    containers_updated += 1
                else:
                    containers_failed += 1
            else:
                try:
                    yield container
                    containers_added += 1
                    container_id = container.container_id
                except Exception as e:
                    containers_failed += 1
                    logger.error(
                        f"Failed to create container for alert {alert_id}: {e}"
                    )
                    continue

            if not container_id:
                continue

            # ==================== Main Artifact ====================
            cef = {
                "alert_id": alert_id,
                "entity": entity,
                "brand": alert.get("brand"),
                "queue_state": alert.get("queue_state"),
                "entity_state": alert.get("entity_state"),
                "severity": severity,
                "product": alert.get("product"),
                "platform": alert.get("platform"),
                "source": alert.get("source"),
                "created_at": alert.get("created_at"),
                "last_activity": alert.get("last_activity_timestamp"),
                "doppel_link": alert.get("doppel_link"),
                "screenshot_url": alert.get("screenshot_url"),
                "score": alert.get("score"),
                "tags": ",".join(
                    tag.get("name", "") if isinstance(tag, dict) else str(tag)
                    for tag in alert.get("tags", [])
                ),
            }
            if extra := alert.get("entity_content"):
                cef["entity_content"] = json.dumps(extra)

            entity_sanitized = (
                entity.replace("://", "_")
                .replace("/", "_")
                .replace(":", "_")
                .replace(" ", "_")
            )
            main_artifact_sdi = f"{alert_id}-{entity_sanitized}"

            artifact = Artifact(
                name=f"Entity: {entity}",
                label="artifact",
                type=alert.get("product", "generic"),
                cef=cef,
                source_data_identifier=main_artifact_sdi,
                description=None,
                run_automation=False,
                container_id=container_id,
            )

            existing_artifact = get_existing_artifact(
                soar, main_artifact_sdi, container_id
            )
            if existing_artifact:
                if update_artifact(soar, existing_artifact["id"], artifact):
                    artifacts_updated += 1
                else:
                    artifacts_failed += 1
            else:
                try:
                    yield artifact
                    artifacts_added += 1
                except Exception as e:
                    artifacts_failed += 1
                    logger.error(f"Failed to create artifact for alert {alert_id}: {e}")

            # ==================== Audit Logs ====================
            for log in alert.get("audit_logs", []):
                audit_timestamp = (
                    log.get("timestamp", "unknown")
                    .replace(":", "_")
                    .replace(".", "_")
                    .replace(" ", "_")
                )
                audit_type = (
                    log.get("type", "unknown")
                    .replace(" ", "_")
                    .replace(":", "_")
                    .replace("/", "_")
                )
                audit_sdi = f"{alert_id}-{audit_timestamp}-{audit_type}"

                if get_existing_artifact(soar, audit_sdi, container_id):
                    audit_artifacts_skipped += 1
                    continue

                audit_artifact = Artifact(
                    name=f"Type: {log.get('type', 'unknown')}",
                    label="audit_log",
                    type="audit_log",
                    cef={
                        "alert_id": alert_id,
                        "entity": entity,
                        "audit_type": log.get("type", "?"),
                        "audit_value": log.get("value", "?"),
                        "audit_timestamp": log.get("timestamp", "?"),
                        "audit_created_by": log.get("changed_by", "?"),
                    },
                    source_data_identifier=audit_sdi,
                    description=f"Audit log entry for alert {alert_id}",
                    run_automation=False,
                    container_id=container_id,
                )
                try:
                    yield audit_artifact
                    audit_artifacts_added += 1
                except Exception:
                    audit_artifacts_failed += 1

            total_processed += 1

        page += 1
        meta = resp.get("metadata", {}) if isinstance(resp, dict) else {}
        if page >= meta.get("total_pages", 1):
            break

    logger.info(f"POLLING FINISHED - {total_processed} alerts processed")

    soar.set_summary(
        {
            "containers_added": containers_added,
            "containers_updated": containers_updated,
            "containers_failed": containers_failed,
            "artifacts_added": artifacts_added,
            "artifacts_updated": artifacts_updated,
            "artifacts_failed": artifacts_failed,
            "audit_artifacts_added": audit_artifacts_added,
            "audit_artifacts_skipped": audit_artifacts_skipped,
            "audit_artifacts_failed": audit_artifacts_failed,
            "total_processed": total_processed,
        }
    )

    if not is_manual:
        state["last_poll_time"] = now_utc.strftime("%Y-%m-%dT%H:%M:%S")
        asset.ingest_state = state
        logger.info(
            f"Saved last_poll_time = {state['last_poll_time']} for next scheduled run."
        )


# ========================================
# CLI
# ========================================
if __name__ == "__main__":
    app.cli()
