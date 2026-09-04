package db

import (
	"time"
)

type NucleiFinding struct {
	TemplateID    string `json:"template_id" bson:"template_id"`
	Type          string `json:"type" bson:"type"`
	Name          string `json:"name" bson:"name"`
	Severity      string `json:"severity" bson:"severity"`
	URL           string `json:"url" bson:"url"`
	Host          string `json:"host" bson:"host"`
	MatcherName   string `json:"matcher_name,omitempty" bson:"matcher_name,omitempty"`
	ExtractorName string `json:"extractor_name,omitempty" bson:"extractor_name,omitempty"`
	Request       string `json:"request,omitempty" bson:"request,omitempty"`
	Response      string `json:"response,omitempty" bson:"response,omitempty"`
}

type SubdomainRecord struct {
	Subdomain    string    `bson:"subdomain" json:"subdomain"`
	RootDomain   string    `bson:"root_domain" json:"root_domain"`
	Providers    []string  `bson:"providers" json:"providers"`
	Ports        []string  `bson:"ports,omitempty" json:"ports,omitempty"`
	DiscoveredAt time.Time `bson:"discovered_at" json:"discovered_at"`
	UpdatedAt    time.Time `bson:"updated_at" json:"updated_at"`
}

type HTTPRecord struct {
	RootDomain     string          `bson:"root_domain" json:"root_domain"`
	Subdomain      string          `bson:"subdomain" json:"subdomain"`
	StatusCode     int             `bson:"status_code,omitempty" json:"status_code,omitempty"`
	ContentLength  int             `bson:"content_length,omitempty" json:"content_length,omitempty"`
	Title          string          `bson:"title,omitempty" json:"title,omitempty"`
	Technologies   []string        `bson:"technologies,omitempty" json:"technologies,omitempty"`
	CDN            string          `bson:"cdn,omitempty" json:"cdn,omitempty"`
	IP             string          `bson:"ip,omitempty" json:"ip,omitempty"`
	CNAME          []string        `bson:"cname,omitempty" json:"cname,omitempty"`
	Ports          []string        `bson:"ports,omitempty" json:"ports,omitempty"`
	ProbeType      string          `bson:"probe_type" json:"probe_type"`
	DiscoveredAt   time.Time       `bson:"discovered_at" json:"discovered_at"`
	ScreenshotPath string          `bson:"screenshot_path,omitempty" json:"screenshot_path,omitempty"`
	ScreenshotHash string          `bson:"screenshot_hash,omitempty" json:"screenshot_hash,omitempty"`
	NucleiFindings []NucleiFinding `bson:"nuclei_findings,omitempty" json:"nuclei_findings,omitempty"`
}

type VirtualHostRecord struct {
	RootDomain   string    `bson:"root_domain" json:"root_domain"`
	Subdomain    string    `bson:"subdomain" json:"subdomain"`
	CNAME        []string  `bson:"cname,omitempty" json:"cname,omitempty"`
	DiscoveredAt time.Time `bson:"discovered_at" json:"discovered_at"`
	UpdatedAt    time.Time `bson:"updated_at" json:"updated_at"`
}

type ScreenshotRecord struct {
	Subdomain      string    `bson:"subdomain" json:"subdomain"`
	RootDomain     string    `bson:"root_domain" json:"root_domain"`
	StatusCode     int       `bson:"status_code" json:"status_code"`
	Title          string    `bson:"title" json:"title"`
	ScreenshotPath string    `bson:"screenshot_path" json:"screenshot_path"`
	ScreenshotHash string    `bson:"screenshot_hash,omitempty" json:"screenshot_hash,omitempty"`
	LoadTimeMs     int       `bson:"load_time_ms,omitempty" json:"load_time_ms,omitempty"`
	Technologies   []string  `bson:"technologies,omitempty" json:"technologies,omitempty"`
	Error          string    `bson:"error,omitempty" json:"error,omitempty"`
	CapturedAt     time.Time `bson:"captured_at" json:"captured_at"`
}

type TargetConfig struct {
	Domain     string   `json:"domain" bson:"domain"`
	Name       string   `json:"name,omitempty" bson:"name,omitempty"`
	InScope    []string `json:"in_scope,omitempty" bson:"in_scope,omitempty"`
	OutOfScope []string `json:"out_of_scope,omitempty" bson:"out_of_scope,omitempty"`
}

type SystemRecord struct {
	Key       string    `bson:"key" json:"key"`
	Value     string    `bson:"value" json:"value"`
	Timestamp time.Time `bson:"timestamp" json:"timestamp"`
}
