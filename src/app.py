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
# 3. CUSTOM ACTION OUTPUT
# ========================================
class DoppelActionOutput(ActionOutput):
    status_code: int = OutputField(
        example_values=[200, 404, 500], column_name="Status Code"
    )
    response_body: str = OutputField(
        example_values=['{"id": "TST-900", "entity": "http://sample.com"}', "[]"],
        column_name="Response Body (JSON)",
    )
    error_message: str = OutputField(
        example_values=["", "Alert not found"], column_name="Error Message"
    )


# ========================================
# 4. APP
# ========================================
app = App(
    name="Doppel",
    app_type="generic",
    logo="logo.svg",
    logo_dark="logo_dark.svg",
    product_vendor="Splunk Inc.",
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
    if not asset.doppel_api_key:
        logger.error("Doppel API key required")
        raise ActionFailure("Doppel API key required")
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
@app.action()
def create_alert(
    params: CreateAlertParams, asset: Asset, soar: SOARClient
) -> DoppelActionOutput:
    logger.info("create_alert started")
    if not asset.doppel_api_key:
        logger.error("API key missing")
        return DoppelActionOutput(
            success=False,
            message="API key missing",
            status_code=0,
            response_body="{}",
            error_message="API key missing",
        )
    payload = {"entity": params.entity}
    if params.brand:
        payload["brand"] = params.brand
    if params.source:
        payload["source"] = params.source
    ok, status_code, data, error = _make_request(asset, "POST", "/alert", data=payload)
    response_body = json.dumps(data) if data else "[]"
    if ok and (not data or (isinstance(data, list | dict) and len(data) == 0)):
        logger.warning("Empty response from API")
        return DoppelActionOutput(
            success=False,
            message="Failed to create alert: Empty response",
            status_code=status_code,
            response_body=response_body,
            error_message="Empty response",
        )
    if ok:
        logger.info(f"Alert created: {data.get('id')}")
    else:
        logger.error(f"Failed to create alert: {error}")
    return DoppelActionOutput(
        success=ok,
        message=f"Created alert {data.get('id', 'unknown')}" if ok else error,
        status_code=status_code,
        response_body=response_body,
        error_message="" if ok else error,
    )


@app.action()
def get_alert(
    params: GetAlertParams, asset: Asset, soar: SOARClient
) -> DoppelActionOutput:
    logger.info("get_alert started")
    if not asset.doppel_api_key:
        logger.error("API key missing")
        return DoppelActionOutput(
            success=False,
            message="API key missing",
            status_code=0,
            response_body="{}",
            error_message="API key missing",
        )
    if (params.id and params.entity) or not (params.id or params.entity):
        logger.error("Invalid parameters: Provide either id or entity")
        return DoppelActionOutput(
            success=False,
            message="Provide either id or entity",
            status_code=0,
            response_body="{}",
            error_message="Invalid parameters",
        )

    query_params = {}
    identifier = params.id or params.entity
    if params.id:
        query_params["id"] = params.id
    elif params.entity:
        query_params["entity"] = params.entity

    ok, status_code, data, error = _make_request(
        asset, "GET", "/alert", params=query_params
    )
    response_body = json.dumps(data) if data else "[]"

    if ok:
        if not data or (isinstance(data, list | dict) and len(data) == 0):
            logger.warning(f"No alert found for {identifier}")
            return DoppelActionOutput(
                success=False,
                message=f"No alert found for {identifier}",
                status_code=status_code,
                response_body=response_body,
                error_message="No alert found",
            )
        logger.info(f"Alert found for {identifier}")
        return DoppelActionOutput(
            success=True,
            message=f"Found alert for {identifier}",
            status_code=status_code,
            response_body=response_body,
            error_message="",
        )
    logger.error(f"Failed to fetch alert for {identifier}: {error}")
    return DoppelActionOutput(
        success=False,
        message=f"Failed to fetch alert for {identifier}: {error}",
        status_code=status_code,
        response_body=response_body,
        error_message=error,
    )


@app.action()
def get_all_alerts(
    params: GetAllAlertsParams, asset: Asset, soar: SOARClient
) -> DoppelActionOutput:
    logger.info("get_all_alerts started")
    if not asset.doppel_api_key:
        logger.error("API key missing")
        return DoppelActionOutput(
            success=False,
            message="API key missing",
            status_code=0,
            response_body="{}",
            error_message="API key missing",
        )

    query_params = {k: v for k, v in params.__dict__.items() if v is not None}
    ok, status_code, data, error = _make_request(
        asset, "GET", "/alerts", params=query_params
    )
    response_body = json.dumps(data) if data else "[]"

    alerts = data.get("alerts", []) if isinstance(data, dict) else []
    if ok and not alerts:
        logger.warning("No alerts found")
        return DoppelActionOutput(
            success=False,
            message="No alerts found",
            status_code=status_code,
            response_body=response_body,
            error_message="No alerts found",
        )
    if ok:
        logger.info(f"Fetched {len(alerts)} alerts")
    else:
        logger.error(f"Failed to fetch alerts: {error}")
    return DoppelActionOutput(
        success=ok,
        message=f"Fetched {len(alerts)} alerts" if ok else error,
        status_code=status_code,
        response_body=response_body,
        error_message="" if ok else error,
    )


@app.action()
def update_alert(
    params: UpdateAlertParams, asset: Asset, soar: SOARClient
) -> DoppelActionOutput:
    logger.info("update_alert started")
    if not asset.doppel_api_key:
        logger.error("API key missing")
        return DoppelActionOutput(
            success=False,
            message="API key missing",
            status_code=0,
            response_body="{}",
            error_message="API key missing",
        )
    if (params.id and params.entity) or not (params.id or params.entity):
        logger.error("Invalid parameters: Provide either id or entity")
        return DoppelActionOutput(
            success=False,
            message="Provide either id or entity",
            status_code=0,
            response_body="{}",
            error_message="Invalid parameters",
        )

    query_params = {}
    identifier = params.id or params.entity
    if params.id:
        query_params["id"] = params.id
    elif params.entity:
        query_params["entity"] = params.entity

    payload = {
        k: v
        for k, v in params.__dict__.items()
        if k not in ("id", "entity") and v is not None
    }
    if not payload:
        logger.error("No fields to update")
        return DoppelActionOutput(
            success=False,
            message="No fields to update",
            status_code=0,
            response_body="{}",
            error_message="No fields to update",
        )

    ok, status_code, data, error = _make_request(
        asset, "PUT", "/alert", params=query_params, data=payload
    )
    response_body = json.dumps(data) if data else "[]"

    if ok:
        if not data or (isinstance(data, list | dict) and len(data) == 0):
            logger.warning(f"No alert updated for {identifier}")
            return DoppelActionOutput(
                success=False,
                message=f"No alert updated for {identifier}",
                status_code=status_code,
                response_body=response_body,
                error_message="No alert updated",
            )
        logger.info(f"Alert updated for {identifier}")
        return DoppelActionOutput(
            success=True,
            message=f"Updated alert for {identifier}",
            status_code=status_code,
            response_body=response_body,
            error_message="",
        )
    logger.error(f"Failed to update alert for {identifier}: {error}")
    return DoppelActionOutput(
        success=False,
        message=f"Failed to update alert for {identifier}: {error}",
        status_code=status_code,
        response_body=response_body,
        error_message=error,
    )


# ========================================
# 8. HELPER FUNCTIONS FOR UPDATES
# ========================================
def get_existing_container(soar: SOARClient, sdi: str) -> dict | None:
    try:
        encoded_sdi = quote(sdi, safe="")
        response = soar.get(
            f'rest/container?_filter_source_data_identifier="{encoded_sdi}"'
        )
        data = response.json()
        containers = data.get("data", [])
        if containers:
            logger.info(f"Found container for SDI {sdi}")
            return containers[0]
        logger.info(f"No container found for SDI {sdi}")
        return None
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
    if update_payload["severity"] not in ("low", "medium", "high", "critical"):
        logger.error(f"Invalid severity for container ID {container_id}")
        return False
    logger.info(f"Updating container ID {container_id}")
    for attempt in range(3):
        try:
            response = soar.post(f"rest/container/{container_id}", json=update_payload)
            data = response.json()
            if data.get("success", False) and data.get("id") == container_id:
                logger.info(f"Container ID {container_id} updated")
                return True
            logger.error(
                f"Failed to update container ID {container_id}: {data.get('message', 'Unknown error')}"
            )
            if attempt < 2 and response.status_code in (429, 500, 503):
                logger.warning(f"Retrying container ID {container_id}")
                time.sleep(2**attempt)
                continue
            return False
        except Exception as e:
            logger.error(f"Failed to update container ID {container_id}: {e}")
            if (
                attempt < 2
                and hasattr(e, "response")
                and e.response.status_code in (429, 500, 503)
            ):
                logger.warning(f"Retrying container ID {container_id}")
                time.sleep(2**attempt)
                continue
            return False
    logger.error(f"Max retries exceeded for container ID {container_id}")
    return False


def get_existing_artifact(soar: SOARClient, sdi: str, container_id: int) -> dict | None:
    try:
        encoded_sdi = quote(sdi, safe="")
        response = soar.get(
            f'rest/artifact?_filter_source_data_identifier="{encoded_sdi}"&_filter_container={container_id}'
        )
        data = response.json()
        artifacts = data.get("data", [])
        if artifacts:
            logger.info(f"Found artifact for SDI {sdi} in container {container_id}")
            return artifacts[0]
        logger.info(f"No artifact found for SDI {sdi} in container {container_id}")
        return None
    except Exception as e:
        logger.error(f"Failed to query artifact for SDI {sdi}: {e}")
        return None


def update_artifact(soar: SOARClient, artifact_id: int, artifact: Artifact) -> bool:
    sanitized_cef = {}
    for k, v in artifact.cef.items():
        if v is None:
            continue
        if isinstance(v, (str | int | float | bool)):
            sanitized_cef[k] = v
        else:
            sanitized_cef[k] = str(v)
    update_payload = {
        "name": artifact.name,
        "label": artifact.label,
        "type": artifact.type,
        "cef": sanitized_cef,
        "description": artifact.description,
        "run_automation": artifact.run_automation,
    }
    logger.info(f"Updating artifact ID {artifact_id}")
    for attempt in range(3):
        try:
            response = soar.post(f"rest/artifact/{artifact_id}", json=update_payload)
            data = response.json()
            if data.get("success", False) and data.get("id") == artifact_id:
                logger.info(f"Artifact ID {artifact_id} updated")
                return True
            logger.error(
                f"Failed to update artifact ID {artifact_id}: {data.get('message', 'Unknown error')}"
            )
            if attempt < 2 and response.status_code in (429, 500, 503):
                logger.warning(f"Retrying artifact ID {artifact_id}")
                time.sleep(2**attempt)
                continue
            return False
        except Exception as e:
            logger.error(f"Failed to update artifact ID {artifact_id}: {e}")
            if (
                attempt < 2
                and hasattr(e, "response")
                and e.response.status_code in (429, 500, 503)
            ):
                logger.warning(f"Retrying artifact ID {artifact_id}")
                time.sleep(2**attempt)
                continue
            return False
    logger.error(f"Max retries exceeded for artifact ID {artifact_id}")
    return False


# ========================================
# 9. ON POLL - YIELD CONTAINER/ARTIFACT WITH UPDATES
# ========================================
@app.on_poll()
def on_poll(
    params: OnPollParams, asset: Asset, soar: SOARClient
) -> Iterator[Container | Artifact]:
    logger.info("DOPPEL POLLING STARTED")
    if not asset.doppel_api_key:
        logger.error("API key missing")
        return

    is_manual = soar.get_executing_container_id() == 0
    if is_manual:
        start_ts = (
            datetime.now(ZoneInfo("UTC"))
            - timedelta(days=asset.historical_polling_days)
        ).strftime("%Y-%m-%dT%H:%M:%S")
        logger.info(f"Manual Poll: Fetching since {start_ts}")
        base_params = {"last_activity_timestamp": start_ts}
    else:
        start_ts = (datetime.now(ZoneInfo("UTC")) - timedelta(minutes=30)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        logger.info(f"Scheduled Poll: Fetching since {start_ts}")
        base_params = {"last_activity_timestamp": start_ts}

    base_params["page_size"] = 100
    page = 0
    total_processed = 0
    containers_added = 0
    containers_updated = 0
    artifacts_added = 0
    artifacts_updated = 0
    audit_artifacts_added = 0
    audit_artifacts_skipped = 0
    containers_failed = 0
    artifacts_failed = 0
    audit_artifacts_failed = 0

    while True:
        query_params = base_params.copy()
        query_params["page"] = page
        logger.info(f"Fetching page {page}")

        success, status_code, resp, error = _make_request(
            asset, "GET", "/alerts", params=query_params
        )
        if not success:
            logger.error(f"API failed on page {page}: {error}")
            break

        alerts = resp.get("alerts", [])
        logger.info(f"Page {page}: {len(alerts)} alerts")

        if not alerts:
            logger.info("No alerts, ending")
            break

        for alert in alerts:
            alert_id = alert.get("id", "unknown")
            entity = alert.get("entity", "unknown")
            logger.info(f"Processing alert {alert_id}")

            unique_sdi = alert_id
            entity_sanitized = (
                entity.replace("://", "_")
                .replace("/", "_")
                .replace(":", "_")
                .replace(" ", "_")
            )
            main_artifact_sdi = f"{alert_id}-{entity_sanitized}"

            severity = alert.get("severity") or "medium"
            severity = severity.lower() if isinstance(severity, str) else "medium"
            if severity not in ("low", "medium", "high", "critical"):
                logger.warning(f"Invalid severity for alert {alert_id}")
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
                    logger.error(f"Failed to update container for alert {alert_id}")
            else:
                try:
                    yield container
                    containers_added += 1
                    existing_container = get_existing_container(soar, unique_sdi)
                    if existing_container:
                        container_id = existing_container["id"]
                    else:
                        containers_failed += 1
                        logger.error(
                            f"Failed to retrieve container for alert {alert_id}"
                        )
                        continue
                except Exception as e:
                    containers_failed += 1
                    logger.error(
                        f"Failed to create container for alert {alert_id}: {e}"
                    )
                    continue

            if not container_id:
                logger.error(f"No container ID for alert {alert_id}")
                continue

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
                "uploaded_by": alert.get("uploaded_by"),
                "tags": ",".join(
                    tag.get("name", "") if isinstance(tag, dict) else str(tag)
                    for tag in alert.get("tags", [])
                ),
            }
            if extra := alert.get("entity_content"):
                cef["entity_content"] = json.dumps(extra)

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
                artifact_id = existing_artifact["id"]
                if update_artifact(soar, artifact_id, artifact):
                    artifacts_updated += 1
                else:
                    artifacts_failed += 1
                    logger.error(f"Failed to update artifact for alert {alert_id}")
            else:
                try:
                    yield artifact
                    artifacts_added += 1
                except Exception as e:
                    artifacts_failed += 1
                    logger.error(f"Failed to create artifact for alert {alert_id}: {e}")

            audit = alert.get("audit_logs", [])
            if audit:
                logger.info(f"Processing {len(audit)} audit logs for alert {alert_id}")
                sorted_audit = sorted(
                    audit,
                    key=lambda log: log.get("timestamp", "1970-01-01T00:00:00")
                    or "1970-01-01T00:00:00",
                    reverse=True,
                )
                for i, log in enumerate(sorted_audit, 1):
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

                    existing_audit_artifact = get_existing_artifact(
                        soar, audit_sdi, container_id
                    )
                    if existing_audit_artifact:
                        audit_artifacts_skipped += 1
                        continue

                    audit_cef = {
                        "alert_id": alert_id,
                        "entity": entity,
                        "audit_type": log.get("type", "?"),
                        "audit_value": log.get("value", "?"),
                        "audit_timestamp": log.get("timestamp", "?"),
                        "audit_created_by": log.get("changed_by", "?"),
                    }
                    audit_artifact = Artifact(
                        name=f"Type: {log.get('type', 'unknown')}",
                        label="audit_log",
                        type="audit_log",
                        cef=audit_cef,
                        source_data_identifier=audit_sdi,
                        description=f"Audit log entry {i} for alert {alert_id}",
                        run_automation=False,
                        container_id=container_id,
                    )

                    try:
                        yield audit_artifact
                        audit_artifacts_added += 1
                    except Exception as e:
                        audit_artifacts_failed += 1
                        logger.error(
                            f"Failed to create audit artifact {i} for alert {alert_id}: {e}"
                        )

            total_processed += 1

        meta = resp.get("metadata", {})
        total_pages = meta.get("total_pages", 1)
        page += 1
        if page >= total_pages:
            logger.info("Reached last page")
            break

    logger.info(f"POLLING FINISHED - {total_processed} alerts processed")
    logger.info(
        f"Containers: added={containers_added}, updated={containers_updated}, failed={containers_failed}"
    )
    logger.info(
        f"Artifacts: added={artifacts_added}, updated={artifacts_updated}, failed={artifacts_failed}"
    )
    logger.info(
        f"Audit artifacts: added={audit_artifacts_added}, skipped={audit_artifacts_skipped}, failed={audit_artifacts_failed}"
    )

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


# ========================================
# CLI
# ========================================
if __name__ == "__main__":
    app.cli()
