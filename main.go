package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// CVE represents a Common Vulnerabilities and Exposures entry with its justification.
type CVE struct {
	FindingId     string `json:"id"`                // The unique identifier for the CVE finding
	CVEID         string `json:"finding"`           // The CVE ID (e.g., CVE-2023-1234)
	Justification string `json:"justificationText"` // The text justification for the CVE
	InheritsFrom  string `json:"inheritsFrom"`      // Optional field for inherited justifications
	Status        string `json:"status"`            // Optional field for the status of the CVE
	Designator    int    `json:"designator"`        // Optional field for the designator of the CVE
}

// JustificationList is a map where the key is the CVE ID and the value is the CVE struct,
// ensuring only one justification per CVE ID.
type JustificationList map[string]CVE

// SourceConfig defines a specific combination of edition, single version, and branch
// from which justifications will be sourced.
type SourceConfig struct {
	Edition string // The edition (e.g., "datacenter-app")
	Version string // A single version for this edition (e.g., "1.0.0")
	Branch  string // The branch (e.g., "master", "developer")
}

// ResponseWrapper is a wrapper struct to match the JSON structure from the API.
type ResponseWrapper struct {
	Findings   []CVE  `json:"findings"`
	ImageTagId string `json:"imageTagId"`
}

// APIClient holds the common API configurations and HTTP client.
type APIClient struct {
	Host      string
	ImagePath string
	ImageName string
	Cookies   []*http.Cookie
	HTTPClient *http.Client
}

// NewAPIClient creates and returns a new APIClient.
func NewAPIClient(host, imagePath, imageName string, cookies []*http.Cookie) *APIClient {
	return &APIClient{
		Host:      host,
		ImagePath: imagePath,
		ImageName: imageName,
		Cookies:   cookies,
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
	q.Set("imageName", c.ImageName)
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
		return nil, "", fmt.Errorf("received non-OK HTTP status code: %d from %s", resp.StatusCode, apiURL)
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
func (c *APIClient) updateCVE(targetConfig SourceConfig, imageTagId string, cve, existingCVE CVE) error {
	apiPath := "/api/findings" // This path is specific to the update operation

	u, err := url.Parse(c.Host + apiPath)
	if err != nil {
		return fmt.Errorf("error parsing base URL for update: %w", err)
	}

	q := u.Query()
	q.Set("branch", targetConfig.Branch)
	u.RawQuery = q.Encode()
	apiURL := u.String()

	fmt.Printf("Updating CVE %s at %s\n", cve.CVEID, apiURL)

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
		return fmt.Errorf("failed to update CVE %s, received status code: %d", cve.CVEID, resp.StatusCode)
	}
	return nil
}

// syncCve orchestrates the synchronization of CVE justifications.
func (c *APIClient) syncCve(targetConfigs []SourceConfig, masterJustificationList JustificationList) {
	for _, config := range targetConfigs {
		apiURL, err := c.buildImageAPIURL(config)
		if err != nil {
			fmt.Printf("Error building API URL for Edition=%s, Version=%s, Branch=%s: %v\n", config.Edition, config.Version, config.Branch, err)
			continue
		}

		fmt.Printf("\n--- Attempting to sync CVEs to: %s ---\n", apiURL)
		cvesFromCurrentConfig, imageTagId, err := c.getJustificationsFromAPI(apiURL)
		if err != nil {
			fmt.Printf("Error fetching CVEs for Edition=%s, Version=%s, Branch=%s: %v\n", config.Edition, config.Version, config.Branch, err)
			continue
		}
		fmt.Printf("Successfully fetched %d CVEs for Edition=%s, Version=%s, Branch=%s.\n", len(cvesFromCurrentConfig), config.Edition, config.Version, config.Branch)

		targetJustificationList := make(JustificationList)
		for _, cve := range cvesFromCurrentConfig {
			if cve.InheritsFrom == "" && cve.Status == "Needs Justification" {
				targetJustificationList[cve.CVEID] = cve
			}
		}

		for id, cve := range targetJustificationList {
			if existingCVE, exists := masterJustificationList[id]; exists {
				fmt.Printf("Updating CVE %s for imageTagId: %s\n", id, imageTagId)
				if err := c.updateCVE(config, imageTagId, cve, existingCVE); err != nil {
					fmt.Printf("Failed to update CVE %s: %v\n", id, err)
				}
			}
		}
	}
}

func main() {
	sourceConfigs := []SourceConfig{
		{
			Edition: "datacenter-app",
			Version: "2025.3.0",
			Branch:  "master",
		},
		{
			Edition: "datacenter-app",
			Version: "2025.1.2",
			Branch:  "master",
		},
		{
			Edition: "datacenter-app",
			Version: "10.8.1",
			Branch:  "master",
		},
	}

	targetConfigs := []SourceConfig{
		{
			Edition: "datacenter-search",
			Version: "2025.1.2",
			Branch:  "development",
		},
		{
			Edition: "datacenter-app",
			Version: "2025.1.2",
			Branch:  "development",
		},
		{
			Edition: "developer",
			Version: "2025.1.2",
			Branch:  "development",
		},
		{
			Edition: "enterprise",
			Version: "2025.1.2",
			Branch:  "development",
		},
		{
			Edition: "enterprise",
			Version: "9.9.9",
			Branch:  "master",
		},
		{
			Edition: "datacenter-app",
			Version: "9.9.9",
			Branch:  "master",
		},
		{
			Edition: "datacenter-search",
			Version: "9.9.9",
			Branch:  "master",
		},
		{
			Edition: "developer",
			Version: "9.9.8",
			Branch:  "master",
		},
		{
			Edition: "developer",
			Version: "2025.3.1",
			Branch:  "master",
		},
		{
			Edition: "datacenter-search",
			Version: "2025.3.1",
			Branch:  "master",
		},
		{
			Edition: "datacenter-app",
			Version: "2025.3.1",
			Branch:  "master",
		},
		{
			Edition: "enterprise",
			Version: "2025.3.1",
			Branch:  "master",
		},
	}

	userCookies := []*http.Cookie{
		{
			Name:  "connect.sid",
			Value: "s%3AqCkNvdN7h_O-OAgzGC9a1B7-AKb4gs3d.g%2F6CHjrCERuug5xD7PmCOKgrB%2Fxre7XdEUc28GHhxR4",
		},
		{
			Name:  "__Host-ironbank-vat-authservice-session-id-cookie",
			Value: "pelmuoyJxGcswQTkKBYTftnqd88X83WXSQ3zT5kF4MHYjIzb9wl0GKoWlaekjy2a",
		},
	}


	// API client setup
	apiHost := "https://vat.dso.mil"
	apiPath := "/api/images"
	imageName := "sonarsource/sonarqube/sonarqube"

	client := NewAPIClient(apiHost, apiPath, imageName, userCookies)

	// Master Justification List - this will consolidate CVEs from all source configurations.
	masterJustificationList := make(JustificationList)

	// Process each source configuration
	for _, config := range sourceConfigs {
		apiURL, err := client.buildImageAPIURL(config)
		if err != nil {
			fmt.Printf("Error building API URL for Edition=%s, Version=%s, Branch=%s: %v\n", config.Edition, config.Version, config.Branch, err)
			continue
		}

		fmt.Printf("\n--- Attempting to fetch CVEs from: %s ---\n", apiURL)
		cvesFromCurrentConfig, _, err := client.getJustificationsFromAPI(apiURL)
		if err != nil {
			fmt.Printf("Error fetching CVEs for Edition=%s, Version=%s, Branch=%s: %v\n", config.Edition, config.Version, config.Branch, err)
			continue
		}
		fmt.Printf("Successfully fetched %d CVEs for Edition=%s, Version=%s, Branch=%s.\n", len(cvesFromCurrentConfig), config.Edition, config.Version, config.Branch)

		for _, cve := range cvesFromCurrentConfig {
			if cve.InheritsFrom == "" && (cve.Status == "Verified" || cve.Status == "Justified") {
				masterJustificationList[cve.CVEID] = cve
			}
		}
	}

	client.syncCve(targetConfigs, masterJustificationList)
}