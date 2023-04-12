package models

type SnykVulnerability struct {
	CVSSv3         string        `json:"CVSSv3"`
	AlternativeIds []interface{} `json:"alternativeIds"`
	CreationTime   string        `json:"creationTime"`
	Credit         []string      `json:"credit"`
	CvssScore      float64       `json:"cvssScore"`
	Description    string        `json:"description"`
	DisclosureTime string        `json:"disclosureTime"`
	Exploit        string        `json:"exploit"`
	FixedIn        []string      `json:"fixedIn"`
	From           []string      `json:"from"`
	Functions      []interface{} `json:"functions"`
	FunctionsNew   []interface{} `json:"functions_new"`
	ID             string        `json:"id"`
	Identifiers    struct {
		Cve  []string `json:"CVE"`
		Cwe  []string `json:"CWE"`
		Ghsa []string `json:"GHSA"`
	} `json:"identifiers"`
	IsPatchable      bool          `json:"isPatchable"`
	IsUpgradable     bool          `json:"isUpgradable"`
	Language         string        `json:"language"`
	Malicious        bool          `json:"malicious"`
	ModificationTime string        `json:"modificationTime"`
	ModuleName       string        `json:"moduleName"`
	Name             string        `json:"name"`
	PackageManager   string        `json:"packageManager"`
	PackageName      string        `json:"packageName"`
	Patches          []interface{} `json:"patches"`
	Proprietary      bool          `json:"proprietary"`
	PublicationTime  string        `json:"publicationTime"`
	References       []struct {
		Title string `json:"title"`
		URL   string `json:"url"`
	} `json:"references"`
	Semver struct {
		Vulnerable []string `json:"vulnerable"`
	} `json:"semver"`
	Severity             string `json:"severity"`
	SeverityWithCritical string `json:"severityWithCritical"`
	SocialTrendAlert     bool   `json:"socialTrendAlert"`
	Title                string `json:"title"`
	// UpgradePath          []string `json:"upgradePath"`
	Version string `json:"version"`
}
