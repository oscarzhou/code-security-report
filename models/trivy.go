package models

import "time"

type Trivy struct {
	SchemaVersion int    `json:"SchemaVersion"`
	ArtifactName  string `json:"ArtifactName"`
	ArtifactType  string `json:"ArtifactType"`
	Metadata      struct {
		ImageID     string   `json:"ImageID"`
		DiffIDs     []string `json:"DiffIDs"`
		RepoTags    []string `json:"RepoTags"`
		RepoDigests []string `json:"RepoDigests"`
		ImageConfig struct {
			Architecture string    `json:"architecture"`
			Created      time.Time `json:"created"`
			History      []struct {
				Created    time.Time `json:"created"`
				CreatedBy  string    `json:"created_by"`
				Comment    string    `json:"comment"`
				EmptyLayer bool      `json:"empty_layer,omitempty"`
			} `json:"history"`
			Os     string `json:"os"`
			Rootfs struct {
				Type    string   `json:"type"`
				DiffIds []string `json:"diff_ids"`
			} `json:"rootfs"`
			Config struct {
				Entrypoint []string `json:"Entrypoint"`
				Env        []string `json:"Env"`
				Volumes    struct {
					Data struct {
					} `json:"/data"`
				} `json:"Volumes"`
				WorkingDir   string `json:"WorkingDir"`
				ExposedPorts struct {
					Eight000TCP struct {
					} `json:"8000/tcp"`
					Nine000TCP struct {
					} `json:"9000/tcp"`
					Nine443TCP struct {
					} `json:"9443/tcp"`
				} `json:"ExposedPorts"`
			} `json:"config"`
		} `json:"ImageConfig"`
	} `json:"Metadata"`
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Layer            struct {
				DiffID string `json:"DiffID"`
			} `json:"Layer"`
			SeveritySource string `json:"SeveritySource,omitempty"`
			PrimaryURL     string `json:"PrimaryURL,omitempty"`
			DataSource     struct {
				ID   string `json:"ID"`
				Name string `json:"Name"`
				URL  string `json:"URL"`
			} `json:"DataSource"`
			Title       string   `json:"Title"`
			Description string   `json:"Description"`
			Severity    string   `json:"Severity"`
			CweIDs      []string `json:"CweIDs,omitempty"`
			Cvss        struct {
				Nvd struct {
					V2Vector string  `json:"V2Vector"`
					V3Vector string  `json:"V3Vector"`
					V2Score  float64 `json:"V2Score"`
					V3Score  float64 `json:"V3Score"`
				} `json:"nvd"`
				Redhat struct {
					V3Vector string  `json:"V3Vector"`
					V3Score  float64 `json:"V3Score"`
				} `json:"redhat"`
			} `json:"CVSS,omitempty"`
			References       []string  `json:"References"`
			PublishedDate    time.Time `json:"PublishedDate,omitempty"`
			LastModifiedDate time.Time `json:"LastModifiedDate,omitempty"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

type ShortTrivyVulnerability struct {
	ID               string
	Target           string
	Type             string
	PkgName          string
	Severity         string
	Title            string
	InstalledVersion string
	FixedVersion     string
	CompositeID      string `json:"-"`
}

type ShortTrivyResult struct {
	Target          string
	Type            string
	Vulnerabilities []ShortTrivyVulnerability
	SeverityStat    SeverityStat
	Total           int64
}

type TrivySummaryTemplate struct {
	Name    string
	Type    string
	Results []ShortTrivyResult
}

type TrivyDiffTemplate struct {
	BaseSummary     TrivySummaryTemplate
	FixedSummary    TrivySummaryTemplate
	NewFoundSummary TrivySummaryTemplate
}
