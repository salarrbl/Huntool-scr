package db

import (
	"fmt"
	"strings"
	"time" // Import time for time.Time
	"go.mongodb.org/mongo-driver/bson"
	// Ensure the client and context (Ctx) are correctly defined and accessible
	// from con.go within the same package 'db'
	// e.g., con.go should have something like:
	// package db
	// import ("context" and "go.mongodb.org/mongo-driver/mongo")
	// var (
	//     Client *mongo.Client // Exported
	//     Ctx    context.Context // Exported
	// )
	// And GetCollection should be defined in con.go
)

// Make sure HotBreadResult is defined before it's used, matching the structure in Kit/gungnir/monitor.go
type HotBreadResult struct {
	Subdomain    string    `bson:"subdomain" json:"subdomain"`
	RootDomain   string    `bson:"root_domain" json:"root_domain"`
	Source       string    `bson:"source"`             // e.g., "gungnir"
	Timestamp    time.Time `bson:"timestamp" json:"timestamp"` // Matches monitor.go
	DiscoveredAt time.Time `bson:"discovered_at,omitempty"` // Added if you want to track initial discovery time
}

// GetAllHotBreadsSubdomains fetches all subdomains from the 'hot-breads' collection.
func GetAllHotBreadsSubdomains() ([]HotBreadResult, error) {
	// Use the hardcoded database name "watchdogs" from GetCollection in con.go
	collection := GetCollection("hot-breads") // Use GetCollection to get the right DB and Collection
	cursor, err := collection.Find(Ctx, bson.M{}) // Find all documents using the exported Ctx
	if err != nil {
		return nil, fmt.Errorf("finding documents in 'hot-breads': %w", err)
	}
	defer cursor.Close(Ctx) // Use the exported Ctx

	var results []HotBreadResult
	if err = cursor.All(Ctx, &results); err != nil { // Decode all results using the exported Ctx
		return nil, fmt.Errorf("decoding documents from 'hot-breads': %w", err)
	}

	return results, nil
}

// ... (rest of your functions remain unchanged, assuming they correctly use Client, Ctx, GetCollection) ...

func GetSubdomainsByRootDomain(rootDomain string) ([]SubdomainRecord, error) {
	if Client == nil { // Uses the exported Client
		return nil, fmt.Errorf("db not connected")
	}
	collection := GetCollection("subdomains") // Uses the exported GetCollection
	filter := bson.M{"root_domain": strings.TrimSpace(rootDomain)}
	cursor, err := collection.Find(Ctx, filter) // Uses the exported Ctx
	if err != nil {
		return nil, err
	}
	defer cursor.Close(Ctx) // Uses the exported Ctx
	var records []SubdomainRecord
	if err := cursor.All(Ctx, &records); err != nil { // Uses the exported Ctx
		return nil, err
	}
	return records, nil
}

func GetHTTPRecordsByRootDomain(rootDomain string) ([]HTTPRecord, error) {
	if Client == nil { // Uses the exported Client
		return nil, fmt.Errorf("db not connected")
	}
	collection := GetCollection("http") // Uses the exported GetCollection
	filter := bson.M{"root_domain": strings.TrimSpace(rootDomain)}
	cursor, err := collection.Find(Ctx, filter) // Uses the exported Ctx
	if err != nil {
		return nil, err
	}
	defer cursor.Close(Ctx) // Uses the exported Ctx
	var records []HTTPRecord
	if err := cursor.All(Ctx, &records); err != nil { // Uses the exported Ctx
		return nil, err
	}
	return records, nil
}

// GetDistinctSubdomainsByRootDomain fetches distinct subdomains from the 'http' collection for a specific root domain.
func GetDistinctSubdomainsByRootDomain(rootDomain string) ([]string, error) {
	if Client == nil { // Uses the exported Client
		return nil, fmt.Errorf("db not connected")
	}
	collection := GetCollection("http") // Uses the exported GetCollection
	filter := bson.M{"root_domain": strings.TrimSpace(rootDomain)}
	// Use the Distinct method to get unique subdomain values for the specific root domain
	distinctValues, err := collection.Distinct(Ctx, "subdomain", filter) // Uses the exported Ctx
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct subdomains from 'http' for %s: %w", rootDomain, err)
	}

	// Convert interface{} slice to string slice
	var subdomains []string
	for _, value := range distinctValues {
		if str, ok := value.(string); ok && str != "" { // Type assert and check for empty string
			subdomains = append(subdomains, str)
		}
		// Optionally log non-string values if encountered
		// else {
		//  log.Printf("Warning: Non-string value found in 'subdomain' field: %v", value)
		// }
	}

	return subdomains, nil
}

// GetAllDistinctSubdomainsFromHTTP fetches all distinct subdomains from the 'http' collection.
func GetAllDistinctSubdomainsFromHTTP() ([]string, error) {
	if Client == nil { // Uses the exported Client
		return nil, fmt.Errorf("db not connected")
	}
	collection := GetCollection("http") // Uses the exported GetCollection
	// Use the Distinct method to get unique subdomain values
	distinctValues, err := collection.Distinct(Ctx, "subdomain", bson.D{}) // Uses the exported Ctx
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct subdomains from 'http': %w", err)
	}
	// Convert interface{} slice to string slice
	var subdomains []string
	for _, value := range distinctValues {
		if str, ok := value.(string); ok && str != "" { // Type assert and check for empty string
			subdomains = append(subdomains, str)
		}
		// Optionally log non-string values if encountered
		// else {
		//  log.Printf("Warning: Non-string value found in 'subdomain' field: %v", value)
		// }
	}

	return subdomains, nil
}

// GetAllDistinctSubdomainsFromSubdomains fetches all distinct subdomains from the 'subdomains' collection.
func GetAllDistinctSubdomainsFromSubdomains() ([]string, error) {
	if Client == nil { // Uses the exported Client
		return nil, fmt.Errorf("db not connected")
	}
	collection := GetCollection("subdomains") // Uses the exported GetCollection
	// Use the Distinct method to get unique subdomain values
	distinctValues, err := collection.Distinct(Ctx, "subdomain", bson.D{}) // Uses the exported Ctx
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct subdomains from 'subdomains': %w", err)
	}
	// Convert interface{} slice to string slice
	var subdomains []string
	for _, value := range distinctValues {
		if str, ok := value.(string); ok && str != "" { // Type assert and check for empty string
			subdomains = append(subdomains, str)
		}
		// Optionally log non-string values if encountered
		// else {
		//  log.Printf("Warning: Non-string value found in 'subdomain' field: %v", value)
		// }
	}

	return subdomains, nil
}

// GetAllSubdomainsWithOpenPortsFromHTTP fetches subdomains from the 'http' collection where the 'ports' array is not empty.
func GetAllSubdomainsWithOpenPortsFromHTTP() ([]string, error) {
	if Client == nil { // Uses the exported Client
		return nil, fmt.Errorf("db not connected")
	}
	collection := GetCollection("http") // Uses the exported GetCollection
	// Define the filter: 'ports' array exists and has at least one element
	filter := bson.M{
		"ports": bson.M{
			"$exists": true,
			"$ne":     []string{}, // Not an empty array
		},
	}
	// Use Find with the filter to get matching documents
	cursor, err := collection.Find(Ctx, filter) // Uses the exported Ctx
	if err != nil {
		return nil, fmt.Errorf("failed to query for subdomains with ports from 'http': %w", err)
	}
	defer cursor.Close(Ctx) // Uses the exported Ctx
	// Iterate through the results and collect subdomains
	var subdomainsWithPorts []string
	seen := make(map[string]bool) // To avoid duplicates if a subdomain appears multiple times in the collection
	for cursor.Next(Ctx) {        // Uses the exported Ctx
		var record HTTPRecord
		if err := cursor.Decode(&record); err != nil {
			// Log error decoding individual record but continue processing others
			// log.Printf("Warning: Error decoding record in GetAllSubdomainsWithOpenPortsFromHTTP: %v", err)
			continue
		}
		if record.Subdomain != "" && !seen[record.Subdomain] {
			seen[record.Subdomain] = true
			subdomainsWithPorts = append(subdomainsWithPorts, record.Subdomain)
		}
	}
	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor iteration error: %w", err)
	}

	return subdomainsWithPorts, nil
}

// GetAllTargetsFromTargets fetches all target configurations from the 'targets' collection.
func GetAllTargetsFromTargets() ([]TargetConfig, error) {
	if Client == nil { // Uses the exported Client
		return nil, fmt.Errorf("db not connected")
	}
	collection := GetCollection("targets") // Uses the exported GetCollection
	// An empty filter {} will match all documents in the collection
	cursor, err := collection.Find(Ctx, bson.D{}) // Uses the exported Ctx
	if err != nil {
		return nil, err
	}
	defer cursor.Close(Ctx) // Uses the exported Ctx
	var targets []TargetConfig
	if err := cursor.All(Ctx, &targets); err != nil { // Uses the exported Ctx
		return nil, err
	}
	return targets, nil
}

// NEW FUNCTION: GetVirtualHostsByRootDomain (requires exported Client, Ctx, GetCollection)
func GetVirtualHostsByRootDomain(rootDomain string) ([]VirtualHostRecord, error) {
	if Client == nil { // Uses the exported Client
		return nil, fmt.Errorf("db not connected")
	}
	collection := GetCollection("virtual_host") // Uses the exported GetCollection
	filter := bson.M{"root_domain": strings.TrimSpace(rootDomain)}
	cursor, err := collection.Find(Ctx, filter) // Uses the exported Ctx
	if err != nil {
		return nil, err
	}
	defer cursor.Close(Ctx) // Uses the exported Ctx
	var records []VirtualHostRecord
	if err := cursor.All(Ctx, &records); err != nil { // Uses the exported Ctx
		return nil, err
	}
	return records, nil
}
