package main

import (
    "bytes"
    "encoding/json"
    "flag"
    "fmt"
    "io/ioutil"
    "net/http"
    "net/url"
    "os"
)

type CVE struct {
    FindingId     string `json:"id"`                // The unique identifier for the CVE finding
    CVEID         string `json:"finding"`           // The CVE ID (e.g., CVE-2023-1234)
    Justification string `json:"justificationText"` // The text justification for the CVE
    InheritsFrom  string `json:"inheritsFrom"`      // If the CVE is coming from a parent image layer
    Status        string `json:"status"`            // The current status of the CVE (e.g., "Needs Justification", "Verified", "Justified")
    Designator    int    `json:"designator"`        // int representing the justification type ("True Positive", "False Positive", etc.)
}

// JustificationList is a map where the key is the CVE ID and the value is the CVE struct,
type JustificationList map[string]CVE

// SourceConfig defines a specific combination of edition, single version, branch, and image name.
type SourceConfig struct {
    Edition   string `json:"edition"`    // The edition (e.g., "datacenter-app")
    Version   string `json:"version"`    // A single version for this edition (e.g., "1.0.0")
    Branch    string `json:"branch"`     // The branch (e.g., "master", "developer")
    ImageName string `json:"image_name"` // The image name (e.g., "sonarsource/sonarqube/sonarqube")
}

// Configurations struct matches the overall structure of the JSON configuration file,
// including both source and target configurations.
type Configurations struct {
    SourceConfigs []SourceConfig `json:"source_configurations"`
    TargetConfigs []SourceConfig `json:"target_configurations"`
}

// ResponseWrapper is a wrapper struct to match the JSON structure from the API.
type ResponseWrapper struct {
    Findings   []CVE  `json:"findings"`
    ImageTagId string `json:"imageTagId"`
}

type APIClient struct {
    Host       string
    ImagePath  string
    Cookies    []*http.Cookie
    HTTPClient *http.Client
}

func NewAPIClient(host, imagePath string, cookies []*http.Cookie) *APIClient {
    return &APIClient{
        Host:       host,
        ImagePath:  imagePath,
        Cookies:    cookies,
        HTTPClient: &http.Client{},
    }
}

// buildImageAPIURL constructs the URL for fetching image-related CVEs.
func (c *APIClient) buildImageAPIURL(config SourceConfig) (string, error) {
    u, err := url.Parse(c.Host + c.ImagePath)
    if err != nil {
        return "", fmt.Errorf("error parsing base URL: %w", err)
    }

    q := u.Query()
    q.Set("imageName", config.ImageName)
    q.Set("tag", fmt.Sprintf("%s-%s", config.Version, config.Edition))
    q.Set("branch", config.Branch)
    u.RawQuery = q.Encode()

    return u.String(), nil
}

// getJustificationsFromAPI fetches CVE justifications from the API.
func (c *APIClient) getJustificationsFromAPI(apiURL string) ([]CVE, string, error) {
    req, err := http.NewRequest("GET", apiURL, nil)
    if err != nil {
        return nil, "", fmt.Errorf("failed to create HTTP request for %s: %w", apiURL, err)
    }

    for _, cookie := range c.Cookies {
        req.AddCookie(cookie)
    }

    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return nil, "", fmt.Errorf("failed to make HTTP request to %s: %w", apiURL, err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        bodyBytes, readErr := ioutil.ReadAll(resp.Body)
        if readErr != nil {
            return nil, "", fmt.Errorf("received non-OK HTTP status code: %d from %s, failed to read response body: %w", resp.StatusCode, apiURL, readErr)
        }
        return nil, "", fmt.Errorf("received non-OK HTTP status code: %d from %s. Response body: %s", resp.StatusCode, apiURL, string(bodyBytes))
    }

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, "", fmt.Errorf("failed to read response body from %s: %w", apiURL, err)
    }

    var wrapper ResponseWrapper
    err = json.Unmarshal(body, &wrapper)
    if err != nil {
        return nil, "", fmt.Errorf("failed to unmarshal JSON response from %s: %w", apiURL, err)
    }

    return wrapper.Findings, wrapper.ImageTagId, nil
}

// updateCVE sends a PUT request to update a CVE.
func (c *APIClient) updateCVE(targetConfig SourceConfig, imageTagId string, cve CVE, existingCVE CVE) error {
    apiPath := "/api/findings" // This path is specific to the update operation

    u, err := url.Parse(c.Host + apiPath)
    if err != nil {
        return fmt.Errorf("error parsing base URL for update: %w", err)
    }

    q := u.Query()
    q.Set("branch", targetConfig.Branch)
    u.RawQuery = q.Encode()
    apiURL := u.String()

    fmt.Printf("Updating CVE %s for image tag %s at %s\n", cve.CVEID, imageTagId, apiURL)

    // This works for Not Vulnerable CVE updates, it might not work yet for justifications with expected dates etc. in that case an update will be needed.
    requestBody := map[string]interface{}{
        "imageTagId": imageTagId,
        "findings": []map[string]interface{}{
            {
                "findingId":         cve.FindingId,
                "currentStatus":     cve.Status,
                "approvalStatus":    "Justified",
                "justificationText": existingCVE.Justification,
                "approvalComment":   "",
                "inheritable":       true,
                "designator":        existingCVE.Designator,
                "fixDateUnknown":    false,
            },
        },
    }
    requestBodyJSON, err := json.Marshal(requestBody)
    if err != nil {
        return fmt.Errorf("error marshaling request body for CVE %s: %w", cve.CVEID, err)
    }

    req, err := http.NewRequest("PUT", apiURL, ioutil.NopCloser(bytes.NewBuffer(requestBodyJSON)))
    if err != nil {
        return fmt.Errorf("error creating HTTP request for CVE %s: %w", cve.CVEID, err)
    }
    req.Header.Set("Content-Type", "application/json")

    for _, cookie := range c.Cookies {
        req.AddCookie(cookie)
    }

    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return fmt.Errorf("error making HTTP request to update CVE %s: %w", cve.CVEID, err)
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusOK {
        fmt.Printf("Successfully updated CVE %s.\n", cve.CVEID)
    } else {
        bodyBytes, readErr := ioutil.ReadAll(resp.Body)
        if readErr != nil {
            return fmt.Errorf("failed to update CVE %s, received status code: %d, failed to read response body: %w", cve.CVEID, resp.StatusCode, readErr)
        }
        return fmt.Errorf("failed to update CVE %s, received status code: %d. Response body: %s", cve.CVEID, resp.StatusCode, string(bodyBytes))
    }
    return nil
}

// syncCve orchestrates the synchronization of CVE justifications.
func (c *APIClient) syncCve(targetConfigs []SourceConfig, sourceJustificationList JustificationList) {
    for _, config := range targetConfigs {

        apiURL, err := c.buildImageAPIURL(config)
        if err != nil {
            fmt.Printf("Error building API URL for ImageName=%s, Edition=%s, Version=%s, Branch=%s: %v\n", config.ImageName, config.Edition, config.Version, config.Branch, err)
            continue
        }

        fmt.Printf("\n--- Attempting to sync CVEs to: %s (Image: %s) ---\n", apiURL, config.ImageName)
        cvesFromCurrentConfig, imageTagId, err := c.getJustificationsFromAPI(apiURL)
        if err != nil {
            fmt.Printf("Error fetching CVEs for ImageName=%s, Edition=%s, Version=%s, Branch=%s: %v\n", config.ImageName, config.Edition, config.Version, config.Branch, err)
            continue
        }
        fmt.Printf("Successfully fetched %d CVEs for ImageName=%s, Edition=%s, Version=%s, Branch=%s.\n", len(cvesFromCurrentConfig), config.ImageName, config.Edition, config.Version, config.Branch)

        targetJustificationList := make(JustificationList)
        for _, cve := range cvesFromCurrentConfig {
            // Only consider CVEs that are not inherited from other layers and need justification
            if cve.InheritsFrom == "" && cve.Status == "Needs Justification" {
                targetJustificationList[cve.CVEID] = cve
            }
        }

        for id, cve := range targetJustificationList {
            if existingCVE, exists := sourceJustificationList[id]; exists {
                fmt.Printf("Found CVE %s in source list. Attempting to update for Image: %s.\n", id, config.ImageName)
                if err := c.updateCVE(config, imageTagId, cve, existingCVE); err != nil {
                    fmt.Printf("Failed to update CVE %s for Image: %s: %v\n", id, config.ImageName, err)
                }
            }
        }
    }
}

// loadConfigurationsFromFile reads and unmarshals the JSON configuration file.
func loadConfigurationsFromFile(filePath string) (*Configurations, error) {
    fileContent, err := ioutil.ReadFile(filePath)
    if err != nil {
        return nil, fmt.Errorf("failed to read configuration file %s: %w", filePath, err)
    }

    var configs Configurations
    if err := json.Unmarshal(fileContent, &configs); err != nil {
        return nil, fmt.Errorf("failed to unmarshal JSON configuration from %s: %w", filePath, err)
    }
    return &configs, nil
}

// getCookiesFromEnv retrieves cookies from environment variables.
func getCookiesFromEnv() ([]*http.Cookie, error) {
    var cookies []*http.Cookie

    // Retrieve connect.sid cookie
    connectSID := os.Getenv("CONNECT_SID_COOKIE")
    if connectSID == "" {
        return nil, fmt.Errorf("environment variable CONNECT_SID_COOKIE not set")
    }
    cookies = append(cookies, &http.Cookie{
        Name:  "connect.sid",
        Value: connectSID,
    })

    // Retrieve __Host-ironbank-vat-authservice-session-id-cookie
    ironbankSessionID := os.Getenv("IRONBANK_SESSION_ID_COOKIE")
    if ironbankSessionID == "" {
        return nil, fmt.Errorf("environment variable IRONBANK_SESSION_ID_COOKIE not set")
    }
    cookies = append(cookies, &http.Cookie{
        Name:  "__Host-ironbank-vat-authservice-session-id-cookie",
        Value: ironbankSessionID,
    })

    return cookies, nil
}

func main() {

    configFilePath := flag.String("config", "configs.json", "Path to the JSON configuration file")
    flag.Parse()

    loadedConfigs, err := loadConfigurationsFromFile(*configFilePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error loading configurations: %v\n", err)
        os.Exit(1)
    }

    sourceConfigs := loadedConfigs.SourceConfigs
    targetConfigs := loadedConfigs.TargetConfigs

    userCookies, err := getCookiesFromEnv()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error getting cookies from environment: %v\n", err)
        os.Exit(1)
    }

    apiHost := "https://vat.dso.mil"
    apiPath := "/api/images"

    client := NewAPIClient(apiHost, apiPath, userCookies)

    sourceJustificationList := make(JustificationList)

    for _, config := range sourceConfigs { // Loop now uses loaded sourceConfigs
        apiURL, err := client.buildImageAPIURL(config) // ImageName is passed via config
        if err != nil {
            fmt.Printf("Error building API URL for ImageName=%s, Edition=%s, Version=%s, Branch=%s: %v\n", config.ImageName, config.Edition, config.Version, config.Branch, err)
            continue
        }

        fmt.Printf("\n--- Attempting to fetch CVEs from source: %s (Image: %s) ---\n", apiURL, config.ImageName)
        cvesFromCurrentConfig, _, err := client.getJustificationsFromAPI(apiURL)
        if err != nil {
            fmt.Printf("Error fetching CVEs for ImageName=%s, Edition=%s, Version=%s, Branch=%s: %v\n", config.ImageName, config.Edition, config.Version, config.Branch, err)
            continue
        }
        fmt.Printf("Successfully fetched %d CVEs for ImageName=%s, Edition=%s, Version=%s, Branch=%s.\n", len(cvesFromCurrentConfig), config.ImageName, config.Edition, config.Version, config.Branch)

        for _, cve := range cvesFromCurrentConfig {
            if cve.InheritsFrom == "" && (cve.Status == "Verified" || cve.Status == "Justified") {
                sourceJustificationList[cve.CVEID] = cve
            }
        }
    }
    fmt.Printf("\n--- Source Justification List created with %d unique CVEs. ---\n", len(sourceJustificationList))

    client.syncCve(targetConfigs, sourceJustificationList)
}
