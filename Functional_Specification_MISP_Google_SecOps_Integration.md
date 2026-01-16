# Functional Specification | MISP to Google SecOps Forwarder


[**Motivation**](#motivation)


[**Requirements**](#requirements)


[**Design Details**](#design-details)
    [Workflow Diagram](#workflow-diagram)
    [High-Level Architecture](#high-level-architecture)
    [Security Considerations](#security-considerations)
    [Error Handling Design](#error-handling-design)
    [Dependency Mapping](#dependency-mapping)


[**Components**](#components)
    [1. Configuration](#configuration)
    [2. MISP Poller (Client)](#misp-poller)
    [3. Entity Converter (Transformation)](#entity-converter)
    [4. SecOps Ingestion Manager](#secops-ingestion-manager)
    [5. State Manager](#state-manager)


[**APIs Used**](#apis-used)


[**Testing Approach**](#testing-approach)


[**Resources**](#resources)


---


# Motivation {#motivation}


MISP (Malware Information Sharing Platform) is a premier open-source platform for sharing, storing, and correlating Indicators of Compromise (IoCs) of targeted attacks. Google SecOps (Chronicle) is a cloud-native SIEM that provides petabyte-scale threat detection.


The motivation for this integration is to automatically bridge the gap between MISP and Google SecOps. By continuously forwarding high-fidelity IoCs from MISP to Google SecOps, security teams can:
1.  **Automate Threat Intelligence Ingestion**: Eliminate manual export/import of IoCs.
2.  **Enhance Detection**: Automatically correlate MISP attributes (IPs, Domains, Hashes) against all incoming security logs in Google SecOps.
3.  **Real-Time Alerting**: Generate instant alerts when internal telemetry matches a known malicious entity from MISP.
4.  **Contextualize Threats**: Enrich SecOps detections with MISP event metadata (Threat Level, Organization, Description).


# Requirements {#requirements}


### **1. Integration Requirements**
*   The application must allow users to configure connection details for both MISP and Google SecOps.
*   It must run as a standalone service (Docker container or system process).


### **2. Polling & Data Ingestion**
*   **Polling**: The system must periodically poll MISP for new **published** attributes.
*   **Filtering**: Only specific attribute types (e.g., `ip-src`, `domain`, `md5`) should be fetched to ensure relevance.
*   **State Management**: The system must track the timestamp of the last successfully fetched attribute to prevent duplicate processing on restart.


### **3. Data Transformation**
*   **Normalization**: MISP attributes must be converted into **Google SecOps Entity Context** format (UDM).
*   **Enrichment**: Entities should be enriched with:
    *   Severity (mapped from MISP Threat Level).
    *   Expiration (defaulting to a set period, e.g., 90 days). Once expired, the entity remains in SecOps for historical analysis but ceases to trigger real-time alerts.
    *   Source Metadata (Organization, Event Info).


### **4. Security & Access**
*   **MISP Authentication**: Must use API Key validation.
*   **Google SecOps Authentication**: Must use **Service Account Credentials** (JSON) with scoped permissions (`https://www.googleapis.com/auth/malachite-ingestion`).
*   **Transport Security**: All communication must occur over HTTPS.


# Design Details {#design-details}


## Workflow Diagram {#workflow-diagram}


### **High-Level Architecture** {#high-level-architecture}


1.  **Startup & Config**: Loads config from CLI/JSON/Env. Checks `state.json`.
2.  **Historical Polling**: Initializes fetch timestamp based on `HISTORICAL_POLLING_DAYS` on first run. Also supports runtime reset if this configuration changes.
3.  **Polling Engine**: Wakes up at `FETCH_INTERVAL` and queries MISP.
2.  **MISP API**: Returns a list of Attributes updated since `last_timestamp`.
3.  **Transformation Layer**: Iterates through attributes, filtering unsupported types and mapping fields to UDM Entity objects.
4.  **Ingestion Layer**: Batches valid Entities and POSTs them to the Google SecOps Entity API with a defined time window.
5.  **SecOps Correlation Engine**: Automatically matches incoming telemetry logs against these active Entities.
6.  **Alerting & Notification**: Generates an "IoC Match" alert if telemetry matches an active MISP-sourced Entity.
7.  **State Manager**: Updates the local state file with the latest timestamp upon successful processing.


## Security Considerations {#security-considerations}


1.  **What type of communication does the integration use?** REST API (HTTPS).
2.  **How does data flow between components?**
    *   MISP -> (HTTPS GET/POST) -> Forwarder
    *   Forwarder -> (HTTPS POST) -> Google SecOps API
3.  **How are secrets managed?**
    *   MISP API Key: Environment Variable (`MISP_API_KEY`).
    *   Google Credentials: File-based Service Account JSON (`GOOGLE_SA_CREDENTIALS`).
4.  **Is data encrypted?** Yes, TLS 1.2+ for transit. No persistent storage of data at rest (stateless forwarding), except for the timestamp state file.


## Error Handling Design {#error-handling-design}


1.  **API Failures**:
    *   **MISP**: Log error and retry on next interval.
    *   **SecOps**: Log error. If a batch fails, the state is NOT updated, allowing retry of the same data window.
2.  **Invalid Data**: Attributes that cannot be mapped to a valid Entity type are skipped and logged as warnings (verbose mode) or ignored to keep noise low.
3.  **Rate Limiting**: The application respects standard HTTP backoff if implemented by the libraries, though primarily relies on the configured `FETCH_INTERVAL` and `FETCH_PAGE_SIZE` to control load.


## Dependency Mapping {#dependency-mapping}


| Dependency Name | Purpose | Type | Version |
| :--- | :--- | :--- | :--- |
| **MISP Instance** | Source of Threat Intelligence (IoCs). | External | 2.4+ |
| **Google SecOps API** | Destination for Ingestion (`malachiteingestion-pa`). | External | v2 |
| **Python Requests** | HTTP Library for API interactions. | Library | Latest |
| **Google Auth** | Library for handling Service Account OAuth flows. | Library | Latest |


# Components {#components}


### **1. Configuration**
*   **Precedence Logic** (Highest to Lowest):
    1.  CLI Arguments
    2.  JSON Config File (`--config`)
    3.  Environment Variables (`.env`)
*   **Key Settings**:
    *   **Credentials**: `MISP_API_KEY`, `GOOGLE_SA_CREDENTIALS` (Env only for security).
    *   **Tuning**: `FETCH_INTERVAL`, `FETCH_PAGE_SIZE`, `FORWARDER_BATCH_SIZE`.
    *   **Features**: `HISTORICAL_POLLING_DAYS`, `TEST_MODE`, `MAX_TEST_EVENTS`.


### **2. MISP Poller (Client)**
*   Located in `src/misp/client.py`.
*   Uses `requests` to hit `/attributes/restSearch`.
*   Parameters: `returnFormat='json'`, `published=1`, `timestamp=last_seen`.
*   Handles pagination to retrieve large sets of attributes.


### **3. Entity Converter (Transformation)**
*   Located in `src/secops/manager.py` (Static method `convert_to_entity`).
*   **Mappings**:
    *   `ip-src`, `ip-dst` -> `IP_ADDRESS`
    *   `domain`, `hostname` -> `DOMAIN_NAME`
    *   `md5`, `sha1`, `sha256` -> `FILE`
    *   `url` -> `URL`
*   **Metadata**: Maps `threat_level_id` to `severity` (Critical, High, Medium, Low).


### **4. SecOps Ingestion Manager**
*   Located in `src/secops/manager.py`.
*   Authenticates using Google Service Account.
*   Batches entities (default 100 per request).
*   Sends POST requests to `https://malachiteingestion-pa.googleapis.com/v2/entities:batchCreate`.


### **5. State Manager**
*   Local JSON file (`misp_data/state.json`).
*   Stores `{"last_timestamp": <epoch>}`.
*   Ensures continuity across restarts.


# APIs Used {#apis-used}


### **1. MISP Attribute Search**
*   **Endpoint**: `/attributes/restSearch`
*   **Method**: `POST` (for complex filtering)
*   **Description**: Retrieves attributes based on filters.
*   **Auth**: Header `Authorization: <MISP_API_KEY>`
*   **Key Parameters**: `page`, `limit`, `timestamp` (since), `type` (list of types).


### **2. Google SecOps Entity Ingestion**
*   **Endpoint**: `https://malachiteingestion-pa.googleapis.com/v2/entities:batchCreate`
*   **Method**: `POST`
*   **Description**: Creates or updates Entities in the Google SecOps Unified Data Model.
*   **Auth**: OAuth 2.0 Bearer Token (Scope: `malachite-ingestion`).
*   **Payload**:
    ```json
    {
      "customerId": "UUID",
      "log_type": "MISP_IOC",
      "entities": [ { ... } ]
    }
    ```


# Testing Approach {#testing-approach}


*   **Unit Testing**:
    *   `tests/test_all.py` verifies the Logic Conversion (MISP -> Entity) and ensures API clients are initialized with correct headers (Mocked).
*   **Integration Testing (Manual)**:
    *   Run against a live MISP instance.
    *   Verify logs show "Forwarded batch of X entities".
    *   Check `misp_data/state.json` is created and updated.
*   **Traffic Simulation (End-to-End)**:
    *   `tests/simulate_match.py` provides an interactive utility to:
        1.  Accept user input for an IoC (IP, Domain, etc.).
        2.  Generate a synthetic UDM Event containing that IoC.
        3.  Send the UDM Event to SecOps to verify that previous Entity ingestion triggers a valid "IoC Match" detection.


# Resources {#resources}
1.  **MISP REST API Documentation**: [https://www.misp-project.org/documentation/](https://www.misp-project.org/documentation/)
2.  **Google SecOps Ingestion API**: [https://cloud.google.com/chronicle/docs/ingestion/api/ingest-entities](https://cloud.google.com/chronicle/docs/ingestion/api/ingest-entities) (Reference)
