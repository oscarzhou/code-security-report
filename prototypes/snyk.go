package prototypes

type Snyk struct {
	DependencyCount   int64  `json:"dependencyCount"`
	DisplayTargetFile string `json:"displayTargetFile"`
	FilesystemPolicy  bool   `json:"filesystemPolicy"`
	Filtered          struct {
		Ignore []interface{} `json:"ignore"`
		Patch  []interface{} `json:"patch"`
	} `json:"filtered"`
	FoundProjectCount int64 `json:"foundProjectCount"`
	IgnoreSettings    struct {
		AdminOnly                  bool `json:"adminOnly"`
		DisregardFilesystemIgnores bool `json:"disregardFilesystemIgnores"`
		ReasonRequired             bool `json:"reasonRequired"`
	} `json:"ignoreSettings"`
	IsPrivate      bool `json:"isPrivate"`
	LicensesPolicy struct {
		OrgLicenseRules struct {
			AGPL_1_0 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"AGPL-1.0"`
			AGPL_3_0 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"AGPL-3.0"`
			Artistic_1_0 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"Artistic-1.0"`
			Artistic_2_0 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"Artistic-2.0"`
			CDDL_1_0 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"CDDL-1.0"`
			CPOL_1_02 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"CPOL-1.02"`
			EPL_1_0 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"EPL-1.0"`
			GPL_2_0 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"GPL-2.0"`
			GPL_3_0 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"GPL-3.0"`
			LGPL_2_0 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"LGPL-2.0"`
			LGPL_2_1 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"LGPL-2.1"`
			LGPL_3_0 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"LGPL-3.0"`
			MPL_1_1 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"MPL-1.1"`
			MPL_2_0 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"MPL-2.0"`
			MS_RL struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"MS-RL"`
			SimPL_2_0 struct {
				Instructions string `json:"instructions"`
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
			} `json:"SimPL-2.0"`
		} `json:"orgLicenseRules"`
		Severities struct{} `json:"severities"`
	} `json:"licensesPolicy"`
	Ok             bool   `json:"ok"`
	Org            string `json:"org"`
	PackageManager string `json:"packageManager"`
	Path           string `json:"path"`
	Policy         string `json:"policy"`
	ProjectID      string `json:"projectId"`
	ProjectName    string `json:"projectName"`
	Remediation    struct {
		Ignore     struct{} `json:"ignore"`
		Patch      struct{} `json:"patch"`
		Pin        struct{} `json:"pin"`
		Unresolved []struct {
			CVSSv3         string        `json:"CVSSv3"`
			AlternativeIds []interface{} `json:"alternativeIds"`
			CreationTime   string        `json:"creationTime"`
			Credit         []string      `json:"credit"`
			CvssScore      float64       `json:"cvssScore"`
			Description    string        `json:"description"`
			DisclosureTime string        `json:"disclosureTime"`
			Exploit        string        `json:"exploit"`
			FixedIn        []interface{} `json:"fixedIn"`
			From           []string      `json:"from"`
			Functions      []interface{} `json:"functions"`
			FunctionsNew   []interface{} `json:"functions_new"`
			ID             string        `json:"id"`
			Identifiers    struct {
				Cve []interface{} `json:"CVE"`
				Cwe []string      `json:"CWE"`
			} `json:"identifiers"`
			IsPatchable      bool          `json:"isPatchable"`
			IsPinnable       bool          `json:"isPinnable"`
			IsRuntime        bool          `json:"isRuntime"`
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
			Severity             string        `json:"severity"`
			SeverityWithCritical string        `json:"severityWithCritical"`
			SocialTrendAlert     bool          `json:"socialTrendAlert"`
			Title                string        `json:"title"`
			UpgradePath          []interface{} `json:"upgradePath"`
			Version              string        `json:"version"`
		} `json:"unresolved"`
		Upgrade struct {
			Chart_js_2_7_3 struct {
				UpgradeTo string   `json:"upgradeTo"`
				Upgrades  []string `json:"upgrades"`
				Vulns     []string `json:"vulns"`
			} `json:"chart.js@2.7.3"`
			Moment_2_29_1 struct {
				UpgradeTo string   `json:"upgradeTo"`
				Upgrades  []string `json:"upgrades"`
				Vulns     []string `json:"vulns"`
			} `json:"moment@2.29.1"`
		} `json:"upgrade"`
	} `json:"remediation"`
	SeverityThreshold string `json:"severityThreshold"`
	Summary           string `json:"summary"`
	UniqueCount       int64  `json:"uniqueCount"`
	Vulnerabilities   []struct {
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
	} `json:"vulnerabilities"`
}

type ShortSnykVulnerability struct {
	ID         string
	ModuleName string
	Severity   string
	CvssScore  float64
	Title      string
	Version    string
	FixedIn    []string
}

type SnykTemplate struct {
	Name            string
	Languages       []string
	Vulnerabilities []ShortSnykVulnerability
	Critical        int64
	High            int64
	Medium          int64
	Low             int64
	Unknown         int64
	Total           int64
}
