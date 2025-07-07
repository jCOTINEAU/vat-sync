# Introduction

This tool synchronizes CVE justifications between images, editions, and versions, reducing the need for manual copy-pasting.

## Authentication

To authenticate the CLI, follow these steps:

1. Log in to the VAT platform.
2. Open the network tab in your browser and retrieve the following cookies:
   - `connect.sid`
   - `__Host-ironbank-vat-authservice-session-id-cookie`
3. The cookies can be retrieved from either :
   - More Tools → Developer Tools → Application. Then, Storage → Cookies
   - Right-click -> Inspect -> Network -> Reload the page -> click on the first request -> Headers -> Cookie
4. Export the cookies as environment variables:
   ```bash
   export CONNECT_SID_COOKIE="<your_connect.sid_cookie>"
   export IRONBANK_SESSION_ID_COOKIE="<your_session_id_cookie>"
   ```

## Configuration

Ensure you have a `configs.json` file in the same directory where you are running the CLI. A default `configs.json` file is available in the repository if you cloned it.

### Example `configs.json`

```json
{
  "source_configurations": [
     {
        "edition": "datacenter-app",
        "version": "2025.3.0",
        "branch": "master",
        "image_name": "sonarsource/sonarqube/sonarqube"
     }
  ],
  "target_configurations": [
     {
        "edition": "datacenter-search",
        "version": "2025.3.0",
        "branch": "development",
        "image_name": "sonarsource/sonarqube/sonarqube"
     }
  ]
}
```

## Functionality

When running the binary, the tool performs the following actions:

1. Fetches all `Justified` and `Verified` justifications from the `source_configurations` (e.g., `2025.3.0 datacenter-app`).
2. Transfers the justifications that exist in both configurations to the `target_configurations` (e.g., `2025.3.0 datacenter-search`).
3. Note that, by default the dry-run is true, meaning the actual sync will not run, only logs will be printed.

This process ensures consistency and reduces manual effort in managing CVE justifications across different images and versions.

## How to run 

If you have go installed on your machine, you can run with `go run main.go (--config path/to/file.json) --dry-run false`

Else you can used the compiled binaries available [here](https://github.com/jCOTINEAU/vat-sync/releases), note that on mac you might have `Apple could not verify` issue, and need to run `sudo xattr -dr com.apple.quarantine /path/to/var-synchronize-binary`