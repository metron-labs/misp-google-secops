# MISP to Google SecOps Feed Forwarder

This integration fetches Indicators of Compromise (IoCs) from a MISP instance and ingests them into Google SecOps SIEM as UDM events.

## Features
- **Polling**: Fetches IoCs from MISP at configurable intervals.
- **Conversion**: Maps MISP Attributes (IP, Domain, File Hash) to **Google SecOps Entities** (IoCs).
- **Ingestion**: Pushes standardized Entities to the Google SecOps **Entity API**.
- **State Management**: Tracks the last fetch timestamp to avoid duplicates.

## Prerequisites
- **MISP Server must be running** and accessible from the machine/container running this forwarder.
- Python 3.11+ or Docker
- valid MISP API Key
- Google Cloud Service Account with permissions to write to the Ingestion API.

## Configuration
Configuration is managed via environment variables or a `.env` file (if running locally with `python-dotenv`, though this container assumes env vars are passed).

| Variable | Description | Default |
|----------|-------------|---------|
| `MISP_URL` | Base URL of the MISP instance | (Required) |
| `MISP_API_KEY` | API Key for MISP | (Required) |
| `GOOGLE_SA_CREDENTIALS` | Path to Google Service Account JSON file | (Required) |
| `GOOGLE_CUSTOMER_ID` | Google SecOps Customer ID (UUID) | (Required) |
| `FETCH_INTERVAL` | Polling interval in seconds | 3600 (1 hour) |
| `FETCH_PAGE_SIZE` | Attributes per page request | 100 |
| `FORWARDER_BATCH_SIZE` | Events per Ingestion API call | 100 |

## Deployment

### Docker
1. Build the image:
   ```bash
   docker build -t misp-forwarder .
   ```

2. Run the container:
   ```bash
   docker run -d \
     --network host \
     --env-file .env \
     -v $(pwd)/credentials.json:/app/credentials.json \
     -v $(pwd)/misp_data:/app/data \
     -e GOOGLE_SA_CREDENTIALS=/app/credentials.json \
     misp-forwarder
   ```
   > **Note:** If MISP is running on `localhost` on Linux, you MUST use `--network host` so the container can access it. For Mac/Windows, use `host.docker.internal` instead of `localhost` in your `MISP_URL`.

3. **If MISP is on a remote server** (not localhost), remove `--network host`:
   ```bash
   docker run -d \
     --env-file .env \
     -v $(pwd)/credentials.json:/app/credentials.json \
     -v $(pwd)/misp_data:/app/data \
     -e GOOGLE_SA_CREDENTIALS=/app/credentials.json \
     misp-forwarder
   ```
   > Make sure your `MISP_URL` in `.env` points to the remote server (e.g., `https://misp.example.com`).

### Manual

1. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   ```
2. **Activate the virtual environment:**

      On Windows:

   ```bash
   .\venv\Scripts\activate
   ```

   On MacOS/Linux:
      
   ```bash
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set environment variables:**
    Looking the .evn.example for environment variables. Copy it to .env and fill the values.
   
5. **Run the application:**
   ```bash
   python -m src.main
   ```

## Testing

### Unit Tests
Run the unit tests to verify logic without making actual API calls:
```bash
python tests/test_all.py
```

### Traffic Simulation
Simulate a malicious traffic event that triggers a match against an ingested IoC (requires valid credentials):
```bash
python tests/simulate_match.py
```

## Troubleshooting

### Connection Refused (Docker)
**Error:** `HTTPSConnectionPool(host='localhost', port=443): Failed to establish a new connection: [Errno 111] Connection refused`

**Reason:** The container is trying to connect to itself via `localhost`.

**Fix:**
- **Linux:** Add `--network host` to your docker run command.
- **Mac/Windows:** Change `MISP_URL` to `https://host.docker.internal`.
- **General:** Ensure your MISP server is actually running (`service apache2 status` or similar).