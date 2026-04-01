# Doppel

Publisher: Doppel <br>
Connector Version: 1.0.0 <br>
Product Vendor: Splunk Inc. <br>
Product Name: doppel <br>
Minimum Product Version: 6.4.0

The Doppel-Splunk SOAR integration automates the ingestion of Doppel alerts into Splunk SOAR, creating containers and artifacts for efficient analysis. It supports actions to create, retrieve, and update alerts directly within the platform.

### Configuration variables

This table lists the configuration variables required to operate Doppel. These variables are specified when configuring a doppel asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**doppel_api_key** | required | password | Doppel API Key |
**user_api_key** | optional | password | Optional User API Key |
**org_code** | optional | string | Optional Organization Code |
**historical_polling_days** | optional | numeric | Number of days to look back for initial polling (default: 30) |

### Supported Actions

[test connectivity](#action-test-connectivity) - test connectivity <br>
[create alert](#action-create-alert) - create alert <br>
[get alert](#action-get-alert) - get alert <br>
[get all alerts](#action-get-all-alerts) - get all alerts <br>
[update alert](#action-update-alert) - update alert <br>
[on poll](#action-on-poll) - on poll

## action: 'test connectivity'

test connectivity

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create alert'

create alert

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**entity** | required | Entity (domain/email/etc) | string | |
**brand** | optional | Brand name | string | |
**source** | optional | Source system | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.entity | string | | |
action_result.parameter.brand | string | | |
action_result.parameter.source | string | | |
action_result.data.\*.status_code | numeric | | 200 404 500 |
action_result.data.\*.response_body | string | | {"id": "TST-900", "entity": "http://sample.com"} [] |
action_result.data.\*.error_message | string | | Alert not found |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get alert'

get alert

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | optional | Alert ID | string | |
**entity** | optional | Entity | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | | |
action_result.parameter.entity | string | | |
action_result.data.\*.status_code | numeric | | 200 404 500 |
action_result.data.\*.response_body | string | | {"id": "TST-900", "entity": "http://sample.com"} [] |
action_result.data.\*.error_message | string | | Alert not found |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get all alerts'

get all alerts

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**search_key** | optional | Search term | string | |
**queue_state** | optional | Queue state | string | |
**product** | optional | Product | string | |
**created_before** | optional | ISO timestamp | string | |
**created_after** | optional | ISO timestamp | string | |
**last_activity_timestamp** | optional | ISO timestamp | string | |
**tags** | optional | Comma-separated tags | string | |
**page** | optional | Page number (0-based) | numeric | |
**page_size** | optional | Number of alerts per page | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.search_key | string | | |
action_result.parameter.queue_state | string | | |
action_result.parameter.product | string | | |
action_result.parameter.created_before | string | | |
action_result.parameter.created_after | string | | |
action_result.parameter.last_activity_timestamp | string | | |
action_result.parameter.tags | string | | |
action_result.parameter.page | numeric | | |
action_result.parameter.page_size | numeric | | |
action_result.data.\*.status_code | numeric | | 200 404 500 |
action_result.data.\*.response_body | string | | {"id": "TST-900", "entity": "http://sample.com"} [] |
action_result.data.\*.error_message | string | | Alert not found |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update alert'

update alert

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | optional | Alert ID | string | |
**entity** | optional | Entity | string | |
**queue_state** | optional | New queue state | string | |
**entity_state** | optional | New entity state | string | |
**comment** | optional | Comment to add | string | |
**tag_action** | optional | add/remove | string | |
**tag_name** | optional | Tag name | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | | |
action_result.parameter.entity | string | | |
action_result.parameter.queue_state | string | | |
action_result.parameter.entity_state | string | | |
action_result.parameter.comment | string | | |
action_result.parameter.tag_action | string | | |
action_result.parameter.tag_name | string | | |
action_result.data.\*.status_code | numeric | | 200 404 500 |
action_result.data.\*.response_body | string | | {"id": "TST-900", "entity": "http://sample.com"} [] |
action_result.data.\*.error_message | string | | Alert not found |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'on poll'

on poll

Type: **ingest** <br>
Read only: **True**

Callback action for the on_poll ingest functionality

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Start of time range, in epoch time (milliseconds). | numeric | |
**end_time** | optional | End of time range, in epoch time (milliseconds). | numeric | |
**container_count** | optional | Maximum number of container records to query for. | numeric | |
**artifact_count** | optional | Maximum number of artifact records to query for. | numeric | |
**container_id** | optional | Comma-separated list of container IDs to limit the ingestion to. | string | |

#### Action Output

No Output

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
