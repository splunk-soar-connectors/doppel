**Unreleased**

* Added OAuth 2.0 client credentials authentication (Doppel API v2) via new optional asset fields **client_id** and **client_secret**; existing API-key assets continue to work unchanged on API v1
* OAuth tokens are cached in encrypted per-asset state and re-minted only on expiry, with a single automatic re-mint retry on HTTP 401
* Added client attribution headers (`x-doppel-client`, `User-Agent`) to all Doppel API requests
* Added a unit test suite covering authentication modes, token lifecycle, and output mapping
