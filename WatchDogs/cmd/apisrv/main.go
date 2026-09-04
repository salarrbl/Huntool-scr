package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var db *mongo.Database
var apiKey string

func main() {
	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		uri = "mongodb://localhost:27017/watchdogs"
	}
	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8080"
	}
	apiKey = os.Getenv("WATCHDOGS_API_KEY")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatal(err)
	}
	db = client.Database("watchdogs")
	log.Printf("WatchDogs API :%s", port)

	mux := http.NewServeMux()
	mux.HandleFunc("/", w(handleRoot))
	mux.HandleFunc("/health", w(handleHealth))
	mux.HandleFunc("/targets", w(handleTargets))
	mux.HandleFunc("/targets/", w(handleTargetByDomain))
	mux.HandleFunc("/recon/", w(handleReconByDomain))
	mux.HandleFunc("/breads/http/distinct", w(handleHTTPDistinct))
	mux.HandleFunc("/breads/subs/distinct", w(handleSubsDistinct))
	mux.HandleFunc("/breads/http/ports", w(handleHTTPPorts))
	mux.HandleFunc("/breads/", w(handleBreadsTarget))
	mux.HandleFunc("/hot-breads", w(handleHotBreads))
	mux.HandleFunc("/providers", w(handleProviders))

	srv := &http.Server{Addr: ":" + port, Handler: mux, ReadTimeout: 30 * time.Second, WriteTimeout: 120 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func w(fn func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if apiKey != "" && r.Header.Get("X-API-Key") != apiKey {
			http.Error(w, "Unauthorized", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fn(w, r)
	}
}

func ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"message": "WatchDogs API"})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	c, cancel := ctx()
	defer cancel()
	err := db.Client().Ping(c, nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "healthy"})
}

// TargetConfig matches db.TargetConfig
type TargetConfig struct {
	Domain     string   `json:"domain" bson:"domain"`
	Name       string   `json:"name,omitempty" bson:"name,omitempty"`
	Platform   string   `json:"platform,omitempty" bson:"platform,omitempty"`
	InScope    []string `json:"in_scope,omitempty" bson:"in_scope,omitempty"`
	OutOfScope []string `json:"out_of_scope,omitempty" bson:"out_of_scope,omitempty"`
}

func handleTargets(w http.ResponseWriter, r *http.Request) {
	c, cancel := ctx()
	defer cancel()

	switch r.Method {
	case http.MethodGet:
		// GET /targets - list all targets with full details
		cursor, _ := db.Collection("targets").Find(c, bson.M{})
		var targets []TargetConfig
		cursor.All(c, &targets)
		json.NewEncoder(w).Encode(targets)
	case http.MethodPost:
		// POST /targets - create new target
		var target TargetConfig
		if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
			http.Error(w, "Invalid JSON", 400)
			return
		}
		target.Domain = strings.TrimSpace(target.Domain)
		if target.Domain == "" {
			http.Error(w, "Domain is required", 400)
			return
		}
		// Check if exists
		existing := db.Collection("targets").FindOne(c, bson.M{"domain": target.Domain})
		if existing.Err() == nil {
			http.Error(w, "Target already exists", 409)
			return
		}
		now := time.Now()
		update := bson.M{
			"$set": bson.M{
				"name":         target.Name,
				"in_scope":     target.InScope,
				"out_of_scope": target.OutOfScope,
				"updated_at":   now,
			},
			"$setOnInsert": bson.M{
				"created_at": now,
				"domain":     target.Domain,
			},
		}
		_, err := db.Collection("targets").UpdateOne(c, bson.M{"domain": target.Domain}, update, options.Update().SetUpsert(true))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "created"})
	default:
		http.Error(w, "Method not allowed", 405)
	}
}

func handleTargetByDomain(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/targets/")
	if domain == "" {
		http.Error(w, "Domain required", 400)
		return
	}

	// Check if this is a recon request: /targets/{domain}/recon
	if strings.HasSuffix(domain, "/recon") {
		domain = strings.TrimSuffix(domain, "/recon")
		if domain == "" {
			http.Error(w, "Domain required", 400)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", 405)
			return
		}
		// Check if target exists
		c, cancel := ctx()
		defer cancel()
		err := db.Collection("targets").FindOne(c, bson.M{"domain": domain}).Err()
		if err != nil {
			if err == mongo.ErrNoDocuments {
				http.Error(w, "Target not found", 404)
				return
			}
			http.Error(w, err.Error(), 500)
			return
		}

		// TODO: Trigger actual recon - for now just return success
		// This would integrate with the watchdogs daemon or a job queue
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "started",
			"message": "Recon triggered for " + domain,
		})
		return
	}

	c, cancel := ctx()
	defer cancel()

	switch r.Method {
	case http.MethodGet:
		// GET /targets/{domain} - get single target
		var target TargetConfig
		err := db.Collection("targets").FindOne(c, bson.M{"domain": domain}).Decode(&target)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				http.Error(w, "Target not found", 404)
				return
			}
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(target)
	case http.MethodPut:
		// PUT /targets/{domain} - update target
		var target TargetConfig
		if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
			http.Error(w, "Invalid JSON", 400)
			return
		}
		target.Domain = domain // Ensure domain matches URL
		now := time.Now()
		update := bson.M{
			"$set": bson.M{
				"name":         target.Name,
				"platform":     target.Platform,
				"in_scope":     target.InScope,
				"out_of_scope": target.OutOfScope,
				"updated_at":   now,
			},
		}
		_, err := db.Collection("targets").UpdateOne(c, bson.M{"domain": domain}, update)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
	case http.MethodDelete:
		// DELETE /targets/{domain} - delete target
		_, err := db.Collection("targets").DeleteOne(c, bson.M{"domain": domain})
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	default:
		http.Error(w, "Method not allowed", 405)
	}
}

func handleTargetRecon(w http.ResponseWriter, r *http.Request, domain string) {
	// domain is already extracted by caller
	if domain == "" {
		http.Error(w, "Domain required", 400)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	// Check if target exists
	c, cancel := ctx()
	defer cancel()
	err := db.Collection("targets").FindOne(c, bson.M{"domain": domain}).Err()
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Target not found", 404)
			return
		}
		http.Error(w, err.Error(), 500)
		return
	}

	// TODO: Trigger actual recon - for now just return success
	// This would integrate with the watchdogs daemon or a job queue
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "started",
		"message": "Recon triggered for " + domain,
	})
}

func handleReconByDomain(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/recon/")
	if domain == "" {
		http.Error(w, "Domain required", 400)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	// Check if target exists
	c, cancel := ctx()
	defer cancel()
	err := db.Collection("targets").FindOne(c, bson.M{"domain": domain}).Err()
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Target not found", 404)
			return
		}
		http.Error(w, err.Error(), 500)
		return
	}

	// TODO: Trigger actual recon - for now just return success
	// This would integrate with the watchdogs daemon or a job queue
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "started",
		"message": "Recon triggered for " + domain,
	})
}

func handleHTTPDistinct(w http.ResponseWriter, r *http.Request) {
	c, cancel := ctx()
	defer cancel()
	vals, _ := db.Collection("http").Distinct(c, "subdomain", bson.M{})
	json.NewEncoder(w).Encode(vals)
}

func handleSubsDistinct(w http.ResponseWriter, r *http.Request) {
	c, cancel := ctx()
	defer cancel()
	vals, _ := db.Collection("subdomains").Distinct(c, "subdomain", bson.M{})
	json.NewEncoder(w).Encode(vals)
}

func handleHTTPPorts(w http.ResponseWriter, r *http.Request) {
	c, cancel := ctx()
	defer cancel()
	cursor, _ := db.Collection("http").Find(c, bson.M{"ports.0": bson.M{"$exists": true}}, options.Find().SetProjection(bson.M{"subdomain": 1}))
	var docs []bson.M
	cursor.All(c, &docs)
	seen := map[string]bool{}
	result := []string{}
	for _, d := range docs {
		if s, ok := d["subdomain"].(string); ok && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	json.NewEncoder(w).Encode(result)
}

func handleBreadsTarget(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/breads/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 {
		http.Error(w, "bad path", 400)
		return
	}
	target, action := parts[0], parts[1]
	var ext string
	if len(parts) > 2 {
		ext = parts[2]
	}

	switch action {
	case "http":
		handleTargetHTTP(w, r, target, ext)
	case "subs":
		handleTargetSubs(w, r, target, ext)
	case "vh-hosts":
		handleTargetVHosts(w, r, target)
	}
}

func handleTargetHTTP(w http.ResponseWriter, r *http.Request, target, sub string) {
	c, cancel := ctx()
	defer cancel()
	col := db.Collection("http")
	filter := bson.M{"root_domain": target}

	switch sub {
	case "all":
		cursor, _ := col.Find(c, filter, options.Find().SetProjection(bson.M{
			"subdomain": 1, "title": 1, "status_code": 1, "ports": 1, "technologies": 1,
		}))
		w.Write([]byte("["))
		first := true
		for cursor.Next(c) {
			var doc bson.M
			cursor.Decode(&doc)
			b, _ := json.Marshal(doc)
			if !first {
				w.Write([]byte(","))
			}
			first = false
			w.Write(b)
		}
		w.Write([]byte("]"))
	case "cve":
		filter["nuclei_findings.0"] = bson.M{"$exists": true}
		cursor, _ := col.Find(c, filter, options.Find().SetProjection(bson.M{"subdomain": 1, "nuclei_findings": 1}))
		w.Write([]byte("["))
		first := true
		for cursor.Next(c) {
			var doc bson.M
			cursor.Decode(&doc)
			subVal := doc["subdomain"]
			if findings, ok := doc["nuclei_findings"].(bson.A); ok {
				for _, f := range findings {
					if fm, ok := f.(bson.M); ok {
						fm["subdomain"] = subVal
						b, _ := json.Marshal(fm)
						if !first {
							w.Write([]byte(","))
						}
						first = false
						w.Write(b)
					}
				}
			}
		}
		w.Write([]byte("]"))
	default:
		cursor, _ := col.Find(c, filter, options.Find().SetProjection(bson.M{"subdomain": 1}))
		w.Write([]byte("["))
		first := true
		for cursor.Next(c) {
			var doc bson.M
			cursor.Decode(&doc)
			if s, ok := doc["subdomain"].(string); ok {
				if !first {
					w.Write([]byte(","))
				}
				first = false
				b, _ := json.Marshal(s)
				w.Write(b)
			}
		}
		w.Write([]byte("]"))
	}
}

func handleTargetSubs(w http.ResponseWriter, r *http.Request, target, sub string) {
	c, cancel := ctx()
	defer cancel()

	if sub == "provider" {
		handleProvidersRoute(w)
		return
	}
	if strings.HasPrefix(sub, "provider/") {
		provider := strings.TrimPrefix(sub, "provider/")
		cursor, _ := db.Collection("subdomains").Find(c, bson.M{"root_domain": target, "providers": bson.M{"$elemMatch": bson.M{"$eq": provider}}}, options.Find().SetProjection(bson.M{"subdomain": 1}))
		writeSubdomains(w, c, cursor)
		return
	}

	cursor, _ := db.Collection("subdomains").Find(c, bson.M{"root_domain": target}, options.Find().SetProjection(bson.M{"subdomain": 1}))
	writeSubdomains(w, c, cursor)
}

func writeSubdomains(w http.ResponseWriter, c context.Context, cursor *mongo.Cursor) {
	w.Write([]byte("["))
	first := true
	for cursor.Next(c) {
		var doc bson.M
		cursor.Decode(&doc)
		if s, ok := doc["subdomain"].(string); ok {
			if !first {
				w.Write([]byte(","))
			}
			first = false
			b, _ := json.Marshal(s)
			w.Write(b)
		}
	}
	w.Write([]byte("]"))
}

func handleTargetVHosts(w http.ResponseWriter, r *http.Request, target string) {
	c, cancel := ctx()
	defer cancel()
	cursor, _ := db.Collection("virtual_host").Find(c, bson.M{"root_domain": target}, options.Find().SetProjection(bson.M{"subdomain": 1}))
	writeSubdomains(w, c, cursor)
}

func handleHotBreads(w http.ResponseWriter, r *http.Request) {
	c, cancel := ctx()
	defer cancel()
	cursor, _ := db.Collection("hot-breads").Find(c, bson.M{}, options.Find().SetProjection(bson.M{"subdomain": 1}))
	writeSubdomains(w, c, cursor)
}

func handleProviders(w http.ResponseWriter, r *http.Request) {
	handleProvidersRoute(w)
}

func handleProvidersRoute(w http.ResponseWriter) {
	c, cancel := ctx()
	defer cancel()
	vals, _ := db.Collection("subdomains").Distinct(c, "providers", bson.M{})
	all := map[string]bool{}
	for _, v := range vals {
		if arr, ok := v.(bson.A); ok {
			for _, a := range arr {
				if s, ok := a.(string); ok {
					all[s] = true
				}
			}
		}
	}
	result := make([]string, 0, len(all))
	for k := range all {
		result = append(result, k)
	}
	json.NewEncoder(w).Encode(result)
}
