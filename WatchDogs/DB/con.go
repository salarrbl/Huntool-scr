package db

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ToolConfig struct {
	Name           string   `json:"name"`
	Command        string   `json:"command"`
	Args           []string `json:"args"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	Priority       int      `json:"priority"`
	Enabled        bool     `json:"enabled"`
	Retries        int      `json:"retries"`
}

var (
	Client *mongo.Client
	Ctx    = context.Background()
)

var subdomainRegex = regexp.MustCompile(`^(?:https?://)?([^/:]+)`)

func isValidSubdomain(s string) bool {
	if s == "" {
		return false
	}
	if !subdomainRegex.MatchString(s) {
		return false
	}
	host := s
	if matches := subdomainRegex.FindStringSubmatch(s); len(matches) > 1 {
		host = matches[1]
	}
	if net.ParseIP(host) != nil {
		return false
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		// Reject wildcards and other clearly invalid chars
		if strings.Contains(part, "*") || strings.Contains(part, "?") {
			return false
		}
		for _, r := range part {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

func ConnectDB() {
	var err error
	uri := "mongodb://localhost:27017/watchdogs"
	if _, sockErr := os.Stat("/run/mongodb/mongodb.sock"); sockErr == nil {
		uri = "mongodb:///run/mongodb/mongodb.sock?authSource=admin"
	}
	Client, err = mongo.Connect(Ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatalf("❌ MongoDB connect: %v", err)
	}
	pingCtx, pingCancel := context.WithTimeout(Ctx, 5*time.Second)
	defer pingCancel()
	if err := Client.Ping(pingCtx, nil); err != nil {
		log.Fatalf("❌ MongoDB ping failed: %v", err)
	}
	ensureIndexes()
}

func DisconnectDB() {
	if Client != nil {
		_ = Client.Disconnect(Ctx)
	}
}

func ensureIndexes() {
	if Client == nil {
		log.Println("⚠️ Cannot ensure indexes: DB not connected")
		return
	}
	subCollection := Client.Database("watchdogs").Collection("subdomains")
	subCollection.Indexes().CreateOne(Ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "root_domain", Value: 1}, {Key: "subdomain", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	tgtCollection := Client.Database("watchdogs").Collection("targets")
	tgtCollection.Indexes().CreateOne(Ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "domain", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	httpCollection := Client.Database("watchdogs").Collection("http")
	httpCollection.Indexes().CreateOne(Ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "root_domain", Value: 1}, {Key: "subdomain", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	vhCollection := Client.Database("watchdogs").Collection("virtual_host")
	vhCollection.Indexes().CreateOne(Ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "root_domain", Value: 1}, {Key: "subdomain", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
}

func GetCollection(name string) *mongo.Collection {
	if Client == nil {
		log.Panicf("Cannot get collection: DB not connected")
	}
	return Client.Database("watchdogs").Collection(strings.TrimSpace(name))
}

func UpsertTarget(cfg TargetConfig) error {
	if Client == nil || cfg.Domain == "" {
		return nil
	}
	collection := GetCollection("targets")
	now := time.Now()
	primaryDomain := strings.TrimSpace(cfg.Domain)
	if primaryDomain == "" {
		return nil
	}
	filter := bson.M{"domain": primaryDomain}
	update := bson.M{
		"$set": bson.M{
			"name":         cfg.Name,
			"in_scope":     cfg.InScope,
			"out_of_scope": cfg.OutOfScope,
			"updated_at":   now,
		},
		"$setOnInsert": bson.M{
			"created_at": now,
			"domain":     primaryDomain,
		},
	}
	_, err := collection.UpdateOne(Ctx, filter, update, options.Update().SetUpsert(true))
	return err
}

func BulkUpsertSubdomains(rootDomain, provider string, subdomains []string, portsMap map[string][]string) error {
	if Client == nil || len(subdomains) == 0 {
		return nil
	}
	collection := GetCollection("subdomains")
	cfg, _ := GetTargetByDomain(rootDomain)
	var filteredSubs []string
	for _, sub := range subdomains {
		sub = strings.TrimSpace(sub)
		if isValidSubdomain(sub) && IsInScope(sub, cfg) {
			filteredSubs = append(filteredSubs, sub)
		}
	}
	if len(filteredSubs) == 0 {
		return nil
	}
	const batchSize = 1000
	for i := 0; i < len(filteredSubs); i += batchSize {
		end := i + batchSize
		if end > len(filteredSubs) {
			end = len(filteredSubs)
		}
		batch := filteredSubs[i:end]
		var models []mongo.WriteModel
		now := time.Now()
		for _, sub := range batch {
			filter := bson.M{"root_domain": rootDomain, "subdomain": sub}
			addToSet := bson.M{"providers": provider}
			if ports, ok := portsMap[sub]; ok && len(ports) > 0 {
				addToSet["ports"] = bson.M{"$each": ports}
			}
			update := bson.M{
				"$set":      bson.M{"updated_at": now},
				"$addToSet": addToSet,
				"$setOnInsert": bson.M{
					"root_domain":   rootDomain,
					"subdomain":     sub,
					"discovered_at": now,
				},
			}
			models = append(models, mongo.NewUpdateOneModel().SetFilter(filter).SetUpdate(update).SetUpsert(true))
		}
		if len(models) > 0 {
			_, err := collection.BulkWrite(Ctx, models, options.BulkWrite().SetOrdered(false))
			if err != nil {
				return fmt.Errorf("bulk upsert subdomains failed: %w", err)
			}
		}
	}
	return nil
}

func BulkUpsertSubdomainsForDiscovery(rootDomain, provider string, subdomains []string) error {
	if Client == nil || len(subdomains) == 0 {
		return nil
	}
	collection := GetCollection("subdomains")
	cfg, _ := GetTargetByDomain(rootDomain)
	var filteredSubs []string
	for _, sub := range subdomains {
		sub = strings.TrimSpace(sub)
		if isValidSubdomain(sub) && IsInScope(sub, cfg) {
			filteredSubs = append(filteredSubs, sub)
		}
	}
	if len(filteredSubs) == 0 {
		return nil
	}
	const batchSize = 1000
	for i := 0; i < len(filteredSubs); i += batchSize {
		end := i + batchSize
		if end > len(filteredSubs) {
			end = len(filteredSubs)
		}
		batch := filteredSubs[i:end]
		var models []mongo.WriteModel
		now := time.Now()
		for _, sub := range batch {
			filter := bson.M{"root_domain": rootDomain, "subdomain": sub}
			update := bson.M{
				"$set": bson.M{
					"updated_at": now,
				},
				"$addToSet": bson.M{
					"providers": provider,
				},
				"$setOnInsert": bson.M{
					"root_domain":   rootDomain,
					"subdomain":     sub,
					"discovered_at": now,
				},
			}
			models = append(models, mongo.NewUpdateOneModel().SetFilter(filter).SetUpdate(update).SetUpsert(true))
		}
		if len(models) > 0 {
			_, err := collection.BulkWrite(Ctx, models, options.BulkWrite().SetOrdered(false))
			if err != nil {
				return fmt.Errorf("bulk upsert subdomains for discovery tool '%s' failed: %w", provider, err)
			}
		}
	}
	return nil
}

func UpdateNaabuPorts(rootDomain string, portsMap map[string][]string) error {
	if Client == nil || len(portsMap) == 0 {
		return nil
	}
	collection := GetCollection("http")
	const batchSize = 1000
	keys := make([]string, 0, len(portsMap))
	for k := range portsMap {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}
		batchKeys := keys[i:end]
		var models []mongo.WriteModel
		now := time.Now()
		for _, sub := range batchKeys {
			ports := portsMap[sub]
			if len(ports) == 0 {
				continue
			}
			sub = strings.TrimSpace(sub)
			if sub == "" {
				continue
			}
			filter := bson.M{"root_domain": rootDomain, "subdomain": sub}
			update := bson.M{
				"$addToSet": bson.M{"ports": bson.M{"$each": ports}},
				"$set":      bson.M{"updated_at": now},
				"$setOnInsert": bson.M{
					"root_domain":   rootDomain,
					"subdomain":     sub,
					"probe_type":    "naabu",
					"discovered_at": now,
				},
			}
			models = append(models, mongo.NewUpdateOneModel().SetFilter(filter).SetUpdate(update).SetUpsert(true))
		}
		if len(models) > 0 {
			_, err := collection.BulkWrite(Ctx, models, options.BulkWrite().SetOrdered(false))
			if err != nil {
				return fmt.Errorf("bulk update naabu ports failed: %w", err)
			}
		}
	}
	return nil
}

func UpdateNucleiFindingsForSubdomain(rootDomain, subdomain string, findings []NucleiFinding) error {
	if Client == nil || len(findings) == 0 {
		return nil
	}
	collection := GetCollection("http")
	filter := bson.M{"root_domain": rootDomain, "subdomain": strings.ToLower(strings.TrimSpace(subdomain))}
	update := bson.M{
		"$addToSet": bson.M{"nuclei_findings": bson.M{"$each": findings}},
		"$set":      bson.M{"updated_at": time.Now()},
	}
	_, err := collection.UpdateOne(Ctx, filter, update)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil
		}
		return fmt.Errorf("failed to update Nuclei findings for %s/%s: %w", rootDomain, subdomain, err)
	}
	return nil
}

func InsertHTTPRecords(records []HTTPRecord) error {
	if Client == nil || len(records) == 0 {
		return nil
	}
	collection := GetCollection("http")
	cfg, _ := GetTargetByDomain(records[0].RootDomain)
	var filteredRecords []HTTPRecord
	for _, rec := range records {
		if IsInScope(rec.Subdomain, cfg) {
			filteredRecords = append(filteredRecords, rec)
		}
	}
	if len(filteredRecords) == 0 {
		return nil
	}
	const batchSize = 1000
	for i := 0; i < len(filteredRecords); i += batchSize {
		end := i + batchSize
		if end > len(filteredRecords) {
			end = len(filteredRecords)
		}
		batch := filteredRecords[i:end]
		var models []mongo.WriteModel
		now := time.Now()
		for _, rec := range batch {
			filter := bson.M{"root_domain": rec.RootDomain, "subdomain": rec.Subdomain}
			update := bson.M{
				"$set":         rec,
				"$setOnInsert": bson.M{"created_at": now},
			}
			models = append(models, mongo.NewUpdateOneModel().SetFilter(filter).SetUpdate(update).SetUpsert(true))
		}
		if len(models) > 0 {
			_, err := collection.BulkWrite(Ctx, models, options.BulkWrite().SetOrdered(false))
			if err != nil {
				return fmt.Errorf("bulk insert http records failed: %w", err)
			}
		}
	}
	return nil
}

func InsertVirtualHosts(records []VirtualHostRecord) error {
	if Client == nil || len(records) == 0 {
		return nil
	}
	collection := GetCollection("virtual_host")
	cfg, _ := GetTargetByDomain(records[0].RootDomain)
	var filteredRecords []VirtualHostRecord
	for _, rec := range records {
		if IsInScope(rec.Subdomain, cfg) {
			filteredRecords = append(filteredRecords, rec)
		}
	}
	if len(filteredRecords) == 0 {
		return nil
	}
	const batchSize = 1000
	for i := 0; i < len(filteredRecords); i += batchSize {
		end := i + batchSize
		if end > len(filteredRecords) {
			end = len(filteredRecords)
		}
		batch := filteredRecords[i:end]
		var models []mongo.WriteModel
		now := time.Now()
		for _, rec := range batch {
			filter := bson.M{"root_domain": rec.RootDomain, "subdomain": rec.Subdomain}
			update := bson.M{
				"$set": bson.M{
					"updated_at": now,
					"cname":      rec.CNAME,
				},
				"$setOnInsert": bson.M{
					"root_domain":   rec.RootDomain,
					"subdomain":     rec.Subdomain,
					"discovered_at": now,
				},
			}
			models = append(models, mongo.NewUpdateOneModel().SetFilter(filter).SetUpdate(update).SetUpsert(true))
		}
		if len(models) > 0 {
			_, err := collection.BulkWrite(Ctx, models, options.BulkWrite().SetOrdered(false))
			if err != nil {
				return fmt.Errorf("bulk insert virtual hosts failed: %w", err)
			}
		}
	}
	return nil
}

func UpdateHTTPStatusBySubdomain(rootDomain, subdomain string, statusCode int, title string) error {
	if Client == nil {
		return fmt.Errorf("db not connected")
	}
	collection := GetCollection("http")
	filter := bson.M{"root_domain": rootDomain, "subdomain": strings.TrimSpace(subdomain)}
	update := bson.M{
		"$set": bson.M{
			"status_code": statusCode,
			"title":       strings.TrimSpace(title),
			"updated_at":  time.Now(),
		},
	}
	_, err := collection.UpdateOne(Ctx, filter, update)
	return err
}

func UpdateScreenshotDataBySubdomain(rootDomain, subdomain string, path string, hash string) error {
	if Client == nil {
		return fmt.Errorf("db not connected")
	}
	collection := GetCollection("http")
	filter := bson.M{"root_domain": rootDomain, "subdomain": strings.TrimSpace(subdomain)}
	update := bson.M{
		"$set": bson.M{
			"screenshot_path": path,
			"screenshot_hash": hash,
			"captured_at":     time.Now(),
		},
	}
	_, err := collection.UpdateOne(Ctx, filter, update)
	return err
}

func IsInScope(domainOrURL string, cfg *TargetConfig) bool {
	if cfg == nil {
		return true
	}
	domainOrURL = strings.TrimSpace(domainOrURL)
	if domainOrURL == "" {
		return false
	}
	host := domainOrURL
	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil {
			host = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, pattern := range cfg.OutOfScope {
		if matchScopePattern(pattern, domainOrURL, host) {
			return false
		}
	}
	if len(cfg.InScope) == 0 {
		return true
	}
	for _, pattern := range cfg.InScope {
		if matchScopePattern(pattern, domainOrURL, host) {
			return true
		}
	}
	return false
}

func isDomainPattern(pattern string) bool {
	if pattern == "" || strings.Contains(pattern, " ") {
		return false
	}
	return strings.Contains(pattern, ".") || strings.HasPrefix(pattern, "*")
}

func matchScopePattern(pattern, original, host string) bool {
	pattern = strings.TrimSpace(pattern)
	if !isDomainPattern(pattern) {
		return false
	}
	if strings.HasPrefix(pattern, ".") {
		pattern = pattern[1:]
	}
	if strings.EqualFold(pattern, original) || strings.EqualFold(pattern, host) {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(strings.ToLower(host), strings.ToLower(suffix))
	}
	return strings.HasSuffix(strings.ToLower(host), strings.ToLower(pattern))
}

func GetTargetByDomain(domain string) (*TargetConfig, error) {
	if Client == nil {
		return nil, fmt.Errorf("db not connected")
	}
	collection := GetCollection("targets")
	filter := bson.M{"domain": strings.TrimSpace(domain)}
	var cfg TargetConfig
	err := collection.FindOne(Ctx, filter).Decode(&cfg)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("error retrieving target config for %s: %w", domain, err)
	}
	return &cfg, nil
}

func extractSubdomain(urlStr string, rootDomain string) string {
	urlStr = strings.TrimSpace(urlStr)
	if urlStr == "" {
		return ""
	}
	if u, err := url.Parse(urlStr); err == nil && u.Host != "" {
		host := u.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if strings.EqualFold(host, rootDomain) {
			return host
		}
		return strings.ToLower(host)
	}
	if matches := subdomainRegex.FindStringSubmatch(urlStr); len(matches) > 1 {
		return strings.ToLower(matches[1])
	}
	return strings.ToLower(urlStr)
}

func ExtractSubdomain(urlStr string, rootDomain string) string {
	return extractSubdomain(urlStr, rootDomain)
}

func ExtractRootDomain(urlStr string) string {
	urlStr = strings.TrimSpace(urlStr)
	if urlStr == "" {
		return ""
	}
	host := urlStr
	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil && u.Host != "" {
			host = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

func UpsertHTTPRecord(record HTTPRecord) error {
	if Client == nil {
		return fmt.Errorf("db not connected")
	}
	collection := GetCollection("http")
	filter := bson.M{"root_domain": record.RootDomain, "subdomain": record.Subdomain}
	update := bson.M{
		"$set":         record,
		"$setOnInsert": bson.M{"created_at": time.Now()},
	}
	_, err := collection.UpdateOne(Ctx, filter, update, options.Update().SetUpsert(true))
	return err
}

func LoadToolsConfig(filePath string) ([]ToolConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", filePath, err)
	}
	var tools []ToolConfig
	if err := json.Unmarshal(data, &tools); err != nil {
		return nil, fmt.Errorf("parse config file %s: %w", filePath, err)
	}
	return tools, nil
}

func GetProviderNamesFromConfig(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", filePath, err)
	}
	var tools []ToolConfig
	if err := json.Unmarshal(data, &tools); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", filePath, err)
	}
	var providerNames []string
	for _, tool := range tools {
		if tool.Priority == 0 && tool.Enabled {
			providerNames = append(providerNames, tool.Name)
		}
	}
	return providerNames, nil
}

// ─── DB GUARDIAN FUNCTIONS ───

var expectedCollections = []string{
	"subdomains",
	"targets",
	"http",
	"virtual_host",
	"hot-breads",
	"system",
}

func EnsureCollections() {
	if Client == nil {
		log.Println("⚠️ Cannot ensure collections: DB not connected")
		return
	}
	db := Client.Database("watchdogs")
	for _, name := range expectedCollections {
		_ = db.CreateCollection(Ctx, name)
	}
	log.Println("✅ Ensured all expected collections exist")
}

func CheckDBHealth() error {
	if Client == nil {
		return fmt.Errorf("db client is nil")
	}
	pingCtx, cancel := context.WithTimeout(Ctx, 3*time.Second)
	defer cancel()
	if err := Client.Ping(pingCtx, nil); err != nil {
		return fmt.Errorf("mongodb ping failed: %w", err)
	}

	names, err := Client.Database("watchdogs").ListCollectionNames(Ctx, bson.M{})
	if err != nil {
		return fmt.Errorf("failed to list collections: %w", err)
	}
	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}
	var missing []string
	for _, exp := range expectedCollections {
		if !nameSet[exp] {
			missing = append(missing, exp)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("collections %v are MISSING - database may have been wiped or storage is not persistent", missing)
	}
	return nil
}

var startupToken string

func WriteStartupToken() error {
	if Client == nil {
		return fmt.Errorf("db not connected")
	}
	startupToken = fmt.Sprintf("watchdogs-%d", time.Now().UnixNano())
	coll := GetCollection("system")
	_, err := coll.UpdateOne(Ctx,
		bson.M{"key": "startup_token"},
		bson.M{"$set": bson.M{
			"key":       "startup_token",
			"value":     startupToken,
			"timestamp": time.Now(),
		}},
		options.Update().SetUpsert(true),
	)
	return err
}

func VerifyStartupToken() error {
	if Client == nil || startupToken == "" {
		return nil
	}
	coll := GetCollection("system")
	var result SystemRecord
	err := coll.FindOne(Ctx, bson.M{"key": "startup_token"}).Decode(&result)
	if err != nil {
		return fmt.Errorf("startup token missing - database was wiped since daemon started")
	}
	if result.Value != startupToken {
		return fmt.Errorf("startup token mismatch - database was wiped since daemon started")
	}
	return nil
}

func UpsertSystemHeartbeat() error {
	if Client == nil {
		return fmt.Errorf("db not connected")
	}
	coll := GetCollection("system")
	_, err := coll.UpdateOne(Ctx,
		bson.M{"key": "heartbeat"},
		bson.M{"$set": bson.M{
			"key":       "heartbeat",
			"value":     "alive",
			"timestamp": time.Now(),
		}},
		options.Update().SetUpsert(true),
	)
	return err
}
