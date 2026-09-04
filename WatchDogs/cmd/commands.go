package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"watchdogs/colors"
	dbPkg "watchdogs/DB"

	"github.com/spf13/cobra"
)

// BreadsCmd represents the base breads command. Exported (capital B).
var BreadsCmd = &cobra.Command{
	Use:   "breads",
	Short: "List targets or interact with a specific target's data",
	Long:  `Lists all target domains from the 'targets' collection or provides subcommands to interact with data for a specific target.`,
	Run: func(cmd *cobra.Command, args []string) {
		dbPkg.ConnectDB()
		defer dbPkg.DisconnectDB()
		targets, err := dbPkg.GetAllTargetsFromTargets()
		if err != nil {
			log.Fatalf("%s Error fetching targets from 'targets' collection: %v\n", colors.Colorize(colors.Red, "❌"), err)
		}

		for _, target := range targets {
			fmt.Println(colors.Colorize(colors.Lavender, target.Domain))
		}
	},
}

// Command for breads http [TARGET]
var httpCmd = &cobra.Command{
	Use:   "http [TARGET]",
	Short: "List subdomains from the 'http' collection for the specified target, or all records if no target is given",
	Long:  `Fetches subdomains from the 'http' collection in the database for the specified target and prints them. If no target is provided, prints all HTTP records across all targets in 'all' format.`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			// No target given: print all HTTP records across all targets in 'all' format
			dbPkg.ConnectDB()
			defer dbPkg.DisconnectDB()
			targets, err := dbPkg.GetAllTargetsFromTargets()
			if err != nil {
				log.Printf("%s Error fetching targets: %v\n", colors.Colorize(colors.Red, "❌"), err)
				return
			}
			for _, target := range targets {
				httpRecords, err := dbPkg.GetHTTPRecordsByRootDomain(strings.ToLower(target.Domain))
				if err != nil {
					log.Printf("%s Error fetching HTTP records for root domain '%s': %v\n", colors.Colorize(colors.Red, "❌"), target.Domain, err)
					continue
				}
				for _, record := range httpRecords {
					fmt.Printf("%s%s%s%s%s%s%s%s%s\n",
						record.Subdomain,
						colors.Pipe(),
						colors.Colorize(colors.TitleColor(record.Title), record.Title),
						colors.Pipe(),
						colors.StatusCodeBadge(record.StatusCode),
						colors.Pipe(),
						colors.FormatPorts(record.Ports),
						colors.Pipe(),
						colors.FormatTechnologies(record.Technologies),
					)
				}
			}
			return
		}

		targetName := strings.ToLower(args[0])
		dbPkg.ConnectDB()
		defer dbPkg.DisconnectDB()
		httpRecords, err := dbPkg.GetHTTPRecordsByRootDomain(targetName)
		if err != nil {
			log.Printf("%s Error fetching HTTP records for root domain '%s': %v\n", colors.Colorize(colors.Red, "❌"), targetName, err)
			return
		}

		for _, record := range httpRecords {
			fmt.Println(record.Subdomain)
		}
	},
}

// Command for breads http all [TARGET]
var httpAllCmd = &cobra.Command{
	Use:   "all [TARGET]",
	Short: "List detailed info from the 'http' collection for the specified target",
	Long:  `Fetches subdomain, Title, Status Code, Ports, Technologies from the 'http' collection for the specified target (excluding the URL).`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := strings.ToLower(args[0])
		dbPkg.ConnectDB()
		defer dbPkg.DisconnectDB()
		httpRecords, err := dbPkg.GetHTTPRecordsByRootDomain(targetName)
		if err != nil {
			log.Printf("%s Error fetching HTTP records for root domain '%s': %v\n", colors.Colorize(colors.Red, "❌"), targetName, err)
			return
		}
		for _, record := range httpRecords {
			fmt.Printf("%s%s%s%s%s%s%s%s%s\n",
				record.Subdomain,
				colors.Pipe(),
				colors.Colorize(colors.TitleColor(record.Title), record.Title),
				colors.Pipe(),
				colors.StatusCodeBadge(record.StatusCode),
				colors.Pipe(),
				colors.FormatPorts(record.Ports),
				colors.Pipe(),
				colors.FormatTechnologies(record.Technologies),
			)
		}
	},
}

// Command for breads http title [TARGET]
var httpTitleCmd = &cobra.Command{
	Use:   "title [TARGET]",
	Short: "List subdomains with their titles from the 'http' collection for the specified target",
	Long:  `Fetches subdomain and title pairs from the 'http' collection in the database for the specified target and prints them, omitting records with empty titles.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := strings.ToLower(args[0])
		dbPkg.ConnectDB()
		defer dbPkg.DisconnectDB()
		httpRecords, err := dbPkg.GetHTTPRecordsByRootDomain(targetName)
		if err != nil {
			log.Printf("%s Error fetching HTTP records for root domain '%s': %v\n", colors.Colorize(colors.Red, "❌"), targetName, err)
			return
		}
		for _, record := range httpRecords {
			if record.Title != "" {
				fmt.Printf("%s %s\n",
					record.Subdomain,
					colors.Colorize(colors.Yellow+colors.Italic, record.Title),
				)
			}
		}
	},
}

// Command for breads http cdn [TARGET]
var httpCDNCmd = &cobra.Command{
	Use:   "cdn [TARGET]",
	Short: "List subdomains with their CDN info from the 'http' collection",
	Long:  `Fetches subdomain and CDN pairs from the 'http' collection for the specified target.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := strings.ToLower(args[0])
		dbPkg.ConnectDB()
		defer dbPkg.DisconnectDB()
		httpRecords, err := dbPkg.GetHTTPRecordsByRootDomain(targetName)
		if err != nil {
			log.Printf("%s Error fetching HTTP records for root domain '%s': %v\n", colors.Colorize(colors.Red, "❌"), targetName, err)
			return
		}
		for _, record := range httpRecords {
			if record.CDN != "" {
				fmt.Printf("%s %s\n",
					record.Subdomain,
					colors.Colorize(colors.CDNColor(record.CDN)+colors.Bold, record.CDN),
				)
			}
		}
	},
}

// Command for breads http tech [TARGET]
var httpTechCmd = &cobra.Command{
	Use:   "tech [TARGET]",
	Short: "List subdomains with their technologies from the 'http' collection",
	Long:  `Fetches subdomain and technologies from the 'http' collection for the specified target.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := strings.ToLower(args[0])
		dbPkg.ConnectDB()
		defer dbPkg.DisconnectDB()
		httpRecords, err := dbPkg.GetHTTPRecordsByRootDomain(targetName)
		if err != nil {
			log.Printf("%s Error fetching HTTP records for root domain '%s': %v\n", colors.Colorize(colors.Red, "❌"), targetName, err)
			return
		}
		for _, record := range httpRecords {
			if len(record.Technologies) > 0 {
				fmt.Printf("%s %s\n",
					record.Subdomain,
					colors.FormatTechnologies(record.Technologies),
				)
			}
		}
	},
}

// Command for breads http content-length [TARGET]
var httpContentLengthCmd = &cobra.Command{
	Use:   "content-length [TARGET]",
	Short: "List subdomains with their content length from the 'http' collection",
	Long:  `Fetches subdomain and content_length pairs from the 'http' collection for the specified target.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := strings.ToLower(args[0])
		dbPkg.ConnectDB()
		defer dbPkg.DisconnectDB()
		httpRecords, err := dbPkg.GetHTTPRecordsByRootDomain(targetName)
		if err != nil {
			log.Printf("%s Error fetching HTTP records for root domain '%s': %v\n", colors.Colorize(colors.Red, "❌"), targetName, err)
			return
		}
		for _, record := range httpRecords {
			if record.ContentLength > 0 {
				fmt.Printf("%s %s\n",
					record.Subdomain,
					colors.Colorize(colors.ContentLengthColor(record.ContentLength), fmt.Sprintf("%d", record.ContentLength)),
				)
			}
		}
	},
}

// Command for breads http status-code [TARGET]
var httpStatusCodeCmd = &cobra.Command{
	Use:   "status-code [TARGET]",
	Short: "List subdomains with their status codes from the 'http' collection for the specified target",
	Long:  `Fetches subdomain and status code pairs from the 'http' collection in the database for the specified target and prints them.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := strings.ToLower(args[0])
		dbPkg.ConnectDB()
		defer dbPkg.DisconnectDB()
		httpRecords, err := dbPkg.GetHTTPRecordsByRootDomain(targetName)
		if err != nil {
			log.Printf("%s Error fetching HTTP records for root domain '%s': %v\n", colors.Colorize(colors.Red, "❌"), targetName, err)
			return
		}
		for _, record := range httpRecords {
			fmt.Printf("%s %s\n",
				record.Subdomain,
				colors.StatusCodeBadge(record.StatusCode),
			)
		}
	},
}

// Command for breads http ports [TARGET]
var httpPortsCmd = &cobra.Command{
	Use:   "ports [TARGET]",
	Short: "List subdomains with open ports from the 'http' collection for the specified target",
	Long:  `Fetches subdomains from the 'http' collection where the 'ports' array is not empty for the specified target.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := strings.ToLower(args[0])
		dbPkg.ConnectDB()
		defer dbPkg.DisconnectDB()
		httpRecords, err := dbPkg.GetHTTPRecordsByRootDomain(targetName)
		if err != nil {
			log.Printf("%s Error fetching HTTP records for root domain '%s': %v\n", colors.Colorize(colors.Red, "❌"), targetName, err)
			return
		}
		for _, record := range httpRecords {
			if len(record.Ports) > 0 {
				fmt.Printf("%s %s\n",
					record.Subdomain,
					colors.FormatPorts(record.Ports),
				)
			}
		}
	},
}

// Command for breads subs (lists targets if no subcommand/arg)
var subsBaseCmd = &cobra.Command{
	Use:   "subs",
	Short: "Interact with subdomain data. Use 'subs TARGET' to list subdomains or 'subs provider PROVIDER_NAME TARGET' to filter.",
	Long:  `Lists available targets when run without arguments. Use 'subs TARGET' to list subdomains for a specific target (using its short name) or 'subs provider PROVIDER_NAME TARGET' to list subdomains found by a specific provider for a specific target.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			dbPkg.ConnectDB()
			defer dbPkg.DisconnectDB()
			targets, err := dbPkg.GetAllTargetsFromTargets()
			if err != nil {
				log.Fatalf("%s Error fetching targets from 'targets' collection: %v\n", colors.Colorize(colors.Red, "❌"), err)
			}

			for _, target := range targets {
				fmt.Println(colors.Colorize(colors.Lavender, target.Domain))
			}
			return
		}
		fmt.Printf("%s Unexpected argument(s) for 'subs'. Use 'subs TARGET' or 'subs provider PROVIDER_NAME TARGET'. Got: %v\n", colors.Colorize(colors.Red, "❌"), args)
	},
}

// Command for breads subs target [TARGET]
var subsTargetCmd = &cobra.Command{
	Use:   "target [TARGET]",
	Short: "List subdomains for the specified target (using its short name)",
	Long:  `Fetches subdomains from the 'subdomains' collection in the database for the specified target.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := strings.ToLower(args[0])
		dbPkg.ConnectDB()
		defer dbPkg.DisconnectDB()
		inScopePatterns, err := getInScopePatternsForTarget(targetName)
		if err != nil {
			log.Fatalf("%s Error resolving target '%s': %v\n", colors.Colorize(colors.Red, "❌"), targetName, err)
		}
		allRootDomainsToCheck := append(inScopePatterns, targetName)

		for _, rootDomainToCheck := range allRootDomainsToCheck {
			subRecords, err := dbPkg.GetSubdomainsByRootDomain(rootDomainToCheck)
			if err != nil {
				log.Printf("%s Error fetching subdomain records for root domain '%s': %v\n", colors.Colorize(colors.Red, "❌"), rootDomainToCheck, err)
				continue
			}

			for _, record := range subRecords {
				fmt.Println(record.Subdomain)
			}
		}
	},
}

// Command for breads subs provider
var subsProviderCmd = &cobra.Command{
	Use:   "provider",
	Short: "List available sub-enum providers OR filter subdomains by a specific provider for a target",
	Long:  `Use 'breads subs provider' to list all available subdomain enumeration providers. Use 'breads subs provider PROVIDER_NAME TARGET' to list subdomains discovered *only* by PROVIDER_NAME for TARGET.`,
	Args: cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		dbPkg.ConnectDB()
		defer dbPkg.DisconnectDB()
		if len(args) == 0 {
			availableProviders, err := getAvailableSubEnumProvidersSafe()
			if err != nil {
				log.Fatalf("%s Error loading available sub-enum providers: %v\n", colors.Colorize(colors.Red, "❌"), err)
			}
			foundCSP := false
			for _, p := range availableProviders {
				if strings.EqualFold(p, "csprecon") {
					foundCSP = true
					break
				}
			}
			if !foundCSP {
				availableProviders = append(availableProviders, "csprecon")
			}

			for _, provider := range availableProviders {
				fmt.Println(colors.Colorize(colors.Teal, provider))
			}
		} else if len(args) == 2 {
			providerName := args[0]
			targetName := strings.ToLower(args[1])

			inScopePatterns, err := getInScopePatternsForTarget(targetName)
			if err != nil {
				log.Fatalf("%s Error resolving target '%s': %v\n", colors.Colorize(colors.Red, "❌"), targetName, err)
			}
			allRootDomainsToCheck := append(inScopePatterns, targetName)

			for _, rootDomainToCheck := range allRootDomainsToCheck {
				subRecords, err := dbPkg.GetSubdomainsByRootDomain(rootDomainToCheck)
				if err != nil {
					log.Printf("%s Error fetching subdomain records for root domain '%s': %v\n", colors.Colorize(colors.Red, "❌"), rootDomainToCheck, err)
					continue
				}

				for _, record := range subRecords {
					if len(record.Providers) == 1 && strings.EqualFold(record.Providers[0], providerName) {
						fmt.Printf("%s %s\n",
							record.Subdomain,
							colors.Colorize(colors.TechColor(providerName)+colors.Bold, providerName),
						)
					}
				}
			}
		} else {
			fmt.Printf("%s Usage: 'breads subs provider' OR 'breads subs provider PROVIDER_NAME TARGET'. Got %d arguments: %v\n", colors.Colorize(colors.Red, "❌"), len(args), args)
		}
	},
}

// Command for breads vh-hosts [TARGET]
var vhHostsCmd = &cobra.Command{
	Use:   "vh-hosts [TARGET]",
	Short: "List subdomains from the 'virtual_host' collection for the specified target",
	Long:  `Fetches subdomains from the 'virtual_host' collection in the database for the specified target.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := strings.ToLower(args[0])
		dbPkg.ConnectDB()
		defer dbPkg.DisconnectDB()
		vhRecords, err := dbPkg.GetVirtualHostsByRootDomain(targetName)
		if err != nil {
			log.Printf("%s Error fetching 'virtual_host' records for root domain '%s': %v\n", colors.Colorize(colors.Red, "❌"), targetName, err)
			return
		}

		for _, record := range vhRecords {
			fmt.Println(record.Subdomain)
		}
	},
}

// Command for breads cve [TARGET]
var cveCmd = &cobra.Command{
	Use:   "cve [TARGET]",
	Short: "List CVEs/Nuclei findings from the 'http' collection for the specified target",
	Long:  `Fetches Nuclei findings (including CVEs) from the 'http' collection in the database for the specified target.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := strings.ToLower(args[0])
		dbPkg.ConnectDB()
		defer dbPkg.DisconnectDB()
		httpRecords, err := dbPkg.GetHTTPRecordsByRootDomain(targetName)
		if err != nil {
			log.Printf("%s Error fetching HTTP records for root domain '%s': %v\n", colors.Colorize(colors.Red, "❌"), targetName, err)
			return
		}

		for _, record := range httpRecords {
			for _, finding := range record.NucleiFindings {
				fmt.Printf("%s %s %s %s %s\n",
					record.Subdomain,
					colors.Colorize(colors.Mauve, finding.TemplateID),
					colors.Colorize(colors.Pink, finding.Name),
					colors.Colorize(colors.SeverityColor(finding.Severity), finding.Severity),
					colors.Colorize(colors.Sky, finding.URL),
				)
			}
		}
	},
}

// Helper function to resolve a short target name to its full root domains
func getInScopePatternsForTarget(shortTargetName string) ([]string, error) {
	allTargets, err := dbPkg.GetAllTargetsFromTargets()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch targets: %w", err)
	}
	var resolvedInScopePatterns []string
	for _, target := range allTargets {
		if strings.EqualFold(target.Domain, shortTargetName) {
			resolvedInScopePatterns = append(resolvedInScopePatterns, target.InScope...)
		}
	}

	return resolvedInScopePatterns, nil
}

// NEW HELPER FUNCTION: getAvailableSubEnumProvidersSafe
func getAvailableSubEnumProvidersSafe() ([]string, error) {
	configPath := filepath.Join("Kit", "tools.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("tools.json not found in expected location: %s", configPath)
	}
	providerNames, err := dbPkg.GetProviderNamesFromConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load provider names from config: %w", err)
	}

	return providerNames, nil
}

var daemonStartFunc func(ctx context.Context)

// SetDaemonStartFunc injects the StartDaemon function from main.go into the cmd package.
func SetDaemonStartFunc(startFunc func(ctx context.Context)) {
	daemonStartFunc = startFunc
}

var defaultDaemonCmd = &cobra.Command{
	Use:   "",
	Short: "Start the Watchdogs daemon (default action)",
	Long:  `Starts the Watchdogs background process, continuously monitoring and scanning based on Breads/breads.json.`,
	Run: func(cmd *cobra.Command, args []string) {
		if daemonStartFunc == nil {
			log.Fatal("%s Daemon start function not set. This should be injected from main.go.\n", colors.Colorize(colors.Red, "❌"))
		}
		daemonStartFunc(cmd.Context())
	},
}

func init() {
	BreadsCmd.AddCommand(
		httpCmd,
		subsBaseCmd,
		vhHostsCmd,
		cveCmd,
	)
	httpCmd.AddCommand(
		httpAllCmd,
		httpTitleCmd,
		httpStatusCodeCmd,
		httpCDNCmd,
		httpTechCmd,
		httpContentLengthCmd,
		httpPortsCmd,
	)
	subsBaseCmd.AddCommand(
		subsTargetCmd,
		subsProviderCmd,
	)

	RootCmd.Run = defaultDaemonCmd.Run
}

