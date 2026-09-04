package cmd

import (
	"encoding/json"
	"fmt"

	"watchdogs/colors"

	"github.com/spf13/cobra"
)

// APICmd is the root for all remote API interactions
var APICmd = &cobra.Command{
	Use:   "api",
	Short: "Interact with Watchdogs data on the VPS",
	Long:  `Fetches data directly from the remote Watchdogs API server defined in api-config.json.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// --- API Breads Commands ---
var apiBreadsCmd = &cobra.Command{
	Use:   "breads",
	Short: "List targets or interact with specific target data on VPS",
	Run: func(cmd *cobra.Command, args []string) {
		data, err := fetchAPI("/targets")
		if err != nil {
			fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
			return
		}
		printListColored(data)
	},
}

var apiHTTPCmd = &cobra.Command{
	Use:   "http [TARGET]",
	Short: "List subdomains from 'http' collection on VPS, or all records if no target is given",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			// No target given: print all HTTP records across all targets in 'all' format
			targetsData, err := fetchAPI("/targets")
			if err != nil {
				fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
				return
			}
			var targets []string
			if err := json.Unmarshal(targetsData, &targets); err != nil {
				fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
				return
			}
			for _, target := range targets {
				data, err := fetchAPI(fmt.Sprintf("/breads/%s/http/all", target))
				if err != nil {
					fmt.Printf("%s Error fetching HTTP records for '%s': %v\n", colors.Colorize(colors.Red, "❌"), target, err)
					continue
				}
				var items []map[string]interface{}
				if err := json.Unmarshal(data, &items); err != nil {
					fmt.Printf("%s Error parsing HTTP records for '%s': %v\n", colors.Colorize(colors.Red, "❌"), target, err)
					continue
				}
				for _, item := range items {
					if subdomain, ok := item["subdomain"].(string); ok {
						title, _ := item["title"].(string)
						statusCodeFloat, _ := item["status_code"].(float64)
						statusCode := int(statusCodeFloat)
						portsRaw, _ := item["ports"].([]interface{})
						var ports []string
						for _, p := range portsRaw {
							if ps, ok := p.(string); ok {
								ports = append(ports, ps)
							} else if pf, ok := p.(float64); ok {
								ports = append(ports, fmt.Sprintf("%.0f", pf))
							}
						}
						techsRaw, _ := item["technologies"].([]interface{})
						var techs []string
						for _, t := range techsRaw {
							if ts, ok := t.(string); ok {
								techs = append(techs, ts)
							}
						}
						fmt.Printf("%s%s%s%s%s%s%s%s%s\n",
							subdomain,
							colors.Pipe(),
							colors.Colorize(colors.TitleColor(title), title),
							colors.Pipe(),
							colors.StatusCodeBadge(statusCode),
							colors.Pipe(),
							colors.FormatPorts(ports),
							colors.Pipe(),
							colors.FormatTechnologies(techs),
						)
					}
				}
			}
			return
		}

		target := args[0]
		data, err := fetchAPI(fmt.Sprintf("/breads/%s/http", target))
		if err != nil {
			fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
			return
		}
		printListColored(data)
	},
}

// Command for api breads http all [TARGET]
var apiHTTPAllCmd = &cobra.Command{
	Use:   "all [TARGET]",
	Short: "List detailed info from the 'http' collection on VPS",
	Long:  `Fetches subdomain, Title, Status Code, Ports, Technologies from the 'http' collection on the VPS API for the specified target (excluding the URL).`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := args[0]
		data, err := fetchAPI(fmt.Sprintf("/breads/%s/http/all", targetName))
		if err != nil {
			fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
			return
		}
		var items []map[string]interface{}
		if err := json.Unmarshal(data, &items); err == nil {
			for _, item := range items {
				if subdomain, ok := item["subdomain"].(string); ok {
					title, _ := item["title"].(string)
					statusCodeFloat, _ := item["status_code"].(float64)
					statusCode := int(statusCodeFloat)
					portsRaw, _ := item["ports"].([]interface{})
					var ports []string
					for _, p := range portsRaw {
						if ps, ok := p.(string); ok {
							ports = append(ports, ps)
						} else if pf, ok := p.(float64); ok {
							ports = append(ports, fmt.Sprintf("%.0f", pf))
						}
					}
					techsRaw, _ := item["technologies"].([]interface{})
					var techs []string
					for _, t := range techsRaw {
						if ts, ok := t.(string); ok {
							techs = append(techs, ts)
						}
					}
					fmt.Printf("%s%s%s%s%s%s%s%s%s\n",
						subdomain,
						colors.Pipe(),
						colors.Colorize(colors.TitleColor(title), title),
						colors.Pipe(),
						colors.StatusCodeBadge(statusCode),
						colors.Pipe(),
						colors.FormatPorts(ports),
						colors.Pipe(),
						colors.FormatTechnologies(techs),
					)
				}
			}
		}
	},
}

// Command for api breads http cdn [TARGET]
var apiHTTPCDNCmd = &cobra.Command{
	Use:   "cdn [TARGET]",
	Short: "List subdomains with their CDN info from the 'http' collection on VPS",
	Long:  `Fetches subdomain and CDN pairs from the 'http' collection on the VPS API for the specified target.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := args[0]
		data, err := fetchAPI(fmt.Sprintf("/breads/%s/http/cdn", targetName))
		if err != nil {
			fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
			return
		}
		var items []map[string]interface{}
		if err := json.Unmarshal(data, &items); err == nil {
			for _, item := range items {
				if subdomain, ok := item["subdomain"].(string); ok {
					if cdn, ok := item["cdn"].(string); ok && cdn != "" {
						fmt.Printf("%s %s\n",
							subdomain,
							colors.Colorize(colors.CDNColor(cdn)+colors.Bold, cdn),
						)
					}
				}
			}
		}
	},
}

// Command for api breads http content-length [TARGET]
var apiHTTPContentLengthCmd = &cobra.Command{
	Use:   "content-length [TARGET]",
	Short: "List subdomains with their content length from the 'http' collection on VPS",
	Long:  `Fetches subdomain and content_length pairs from the 'http' collection on the VPS API for the specified target.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := args[0]
		data, err := fetchAPI(fmt.Sprintf("/breads/%s/http/content-length", targetName))
		if err != nil {
			fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
			return
		}
		var items []map[string]interface{}
		if err := json.Unmarshal(data, &items); err == nil {
			for _, item := range items {
				if subdomain, ok := item["subdomain"].(string); ok {
					if contentLength, ok := item["content_length"].(float64); ok && contentLength > 0 {
						fmt.Printf("%s %s\n",
							subdomain,
							colors.Colorize(colors.ContentLengthColor(int(contentLength)), fmt.Sprintf("%.0f", contentLength)),
						)
					}
				}
			}
		}
	},
}

// Command for api breads http tech [TARGET]
var apiHTTPTechCmd = &cobra.Command{
	Use:   "tech [TARGET]",
	Short: "List subdomains with their technologies from the 'http' collection on VPS",
	Long:  `Fetches subdomain and technologies from the 'http' collection on the VPS API for the specified target.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := args[0]
		data, err := fetchAPI(fmt.Sprintf("/breads/%s/http/tech", targetName))
		if err != nil {
			fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
			return
		}
		var items []map[string]interface{}
		if err := json.Unmarshal(data, &items); err == nil {
			for _, item := range items {
				if subdomain, ok := item["subdomain"].(string); ok {
					if technologies, ok := item["technologies"].([]interface{}); ok && len(technologies) > 0 {
						var techs []string
						for _, t := range technologies {
							if ts, ok := t.(string); ok {
								techs = append(techs, ts)
							}
						}
						fmt.Printf("%s %s\n",
							subdomain,
							colors.FormatTechnologies(techs),
						)
					}
				}
			}
		}
	},
}

// Command for api breads http title [TARGET]
var apiHTTPTitleCmd = &cobra.Command{
	Use:   "title [TARGET]",
	Short: "List subdomains with their titles from the 'http' collection on VPS",
	Long:  `Fetches subdomain and title pairs from the 'http' collection on the VPS API for the specified target and prints them, omitting records with empty titles.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := args[0]
		data, err := fetchAPI(fmt.Sprintf("/breads/%s/http/title", targetName))
		if err != nil {
			fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
			return
		}
		var items []map[string]interface{}
		if err := json.Unmarshal(data, &items); err == nil {
			for _, item := range items {
				if subdomain, ok := item["subdomain"].(string); ok {
					if title, ok := item["title"].(string); ok && title != "" {
						fmt.Printf("%s %s\n",
							subdomain,
							colors.Colorize(colors.Yellow+colors.Italic, title),
						)
					}
				}
			}
		}
	},
}

// Command for api breads http status-code [TARGET]
var apiHTTPStatusCodeCmd = &cobra.Command{
	Use:   "status-code [TARGET]",
	Short: "List subdomains with their status codes from the 'http' collection on VPS",
	Long:  `Fetches subdomain and status code pairs from the 'http' collection on the VPS API for the specified target and prints them.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := args[0]
		data, err := fetchAPI(fmt.Sprintf("/breads/%s/http/status-code", targetName))
		if err != nil {
			fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
			return
		}
		var items []map[string]interface{}
		if err := json.Unmarshal(data, &items); err == nil {
			for _, item := range items {
				if subdomain, ok := item["subdomain"].(string); ok {
					if statusCode, ok := item["status_code"].(float64); ok {
						fmt.Printf("%s %s\n",
							subdomain,
							colors.StatusCodeBadge(int(statusCode)),
						)
					}
				}
			}
		}
	},
}

// Command for api breads http ports [TARGET]
var apiHTTPPortsCmd = &cobra.Command{
	Use:   "ports [TARGET]",
	Short: "List subdomains with open ports from the 'http' collection on VPS",
	Long:  `Fetches subdomains from the 'http' collection on the VPS API where the 'ports' array is not empty for the specified target.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := args[0]
		data, err := fetchAPI(fmt.Sprintf("/breads/%s/http/ports", targetName))
		if err != nil {
			fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
			return
		}
		var items []map[string]interface{}
		if err := json.Unmarshal(data, &items); err == nil {
			for _, item := range items {
				if subdomain, ok := item["subdomain"].(string); ok {
					if ports, ok := item["ports"].([]interface{}); ok {
						var portStrs []string
						for _, p := range ports {
							if ps, ok := p.(string); ok {
								portStrs = append(portStrs, ps)
							} else if pf, ok := p.(float64); ok {
								portStrs = append(portStrs, fmt.Sprintf("%.0f", pf))
							}
						}
						fmt.Printf("%s %s\n",
							subdomain,
							colors.FormatPorts(portStrs),
						)
					}
				}
			}
		}
	},
}

var apiVHostsCmd = &cobra.Command{
	Use:   "vh-hosts [TARGET]",
	Short: "List virtual hosts on VPS",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		data, err := fetchAPI(fmt.Sprintf("/breads/%s/vh-hosts", target))
		if err != nil {
			fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
			return
		}
		printListColored(data)
	},
}

var apiCVECmd = &cobra.Command{
	Use:   "cve [TARGET]",
	Short: "List Nuclei findings/CVEs on VPS",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		data, err := fetchAPI(fmt.Sprintf("/breads/%s/http/cve", target))
		if err != nil {
			fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
			return
		}
		printJSONRawColored(data)
	},
}

// --- API Breads Subs Commands ---
var apiBreadsSubsCmd = &cobra.Command{
	Use:   "subs",
	Short: "Interact with subdomain data on VPS. Use 'subs target TARGET' or 'subs provider ...'",
	Long:  `Lists available targets when run without arguments on VPS. Use 'subs target TARGET' to list subdomains for a specific target or 'subs provider PROVIDER_NAME TARGET' to list subdomains found by a specific provider for a specific target on the VPS.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			data, err := fetchAPI("/targets")
			if err != nil {
				fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
				return
			}
			printListColored(data)
			return
		}
		fmt.Printf("%s Unexpected argument(s) for 'api breads subs'. Use 'api breads subs target TARGET' or 'api breads subs provider ...'. Got: %v\n", colors.Colorize(colors.Red, "❌"), args)
	},
}

// Command for api breads subs target [TARGET]
var apiBreadsSubsTargetCmd = &cobra.Command{
	Use:   "target [TARGET]",
	Short: "List subdomains for the specified target (using its short name) on VPS",
	Long:  `Fetches subdomains from the 'subdomains' collection on the VPS via the API for the specified target.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetName := args[0]
		data, err := fetchAPI(fmt.Sprintf("/breads/%s/subs/target", targetName))
		if err != nil {
			fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
			return
		}
		printListColored(data)
	},
}

// Command for api breads subs provider
var apiBreadsSubsProviderCmd = &cobra.Command{
	Use:   "provider",
	Short: "List available sub-enum providers OR filter subdomains by a specific provider for a target on VPS",
	Long:  `Use 'api breads subs provider' to list all available subdomain enumeration providers on the VPS. Use 'api breads subs provider PROVIDER_NAME TARGET' to list subdomains discovered *only* by PROVIDER_NAME for TARGET on the VPS.`,
	Args: cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			data, err := fetchAPI("/providers")
			if err != nil {
				fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
				return
			}
			printListColored(data)
		} else if len(args) == 2 {
			providerName := args[0]
			targetName := args[1]
			data, err := fetchAPI(fmt.Sprintf("/breads/%s/subs/provider/%s", targetName, providerName))
			if err != nil {
				fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
				return
			}
			var items []string
			if err := json.Unmarshal(data, &items); err == nil {
				for _, item := range items {
					fmt.Printf("%s %s\n",
						item,
						colors.Colorize(colors.TechColor(providerName)+colors.Bold, providerName),
					)
				}
			}
		} else {
			fmt.Printf("%s Usage: 'api breads subs provider' OR 'api breads subs provider PROVIDER_NAME TARGET'. Got %d arguments: %v\n", colors.Colorize(colors.Red, "❌"), len(args), args)
		}
	},
}

// --- API Gungnir Command ---
var apiGungnirCmd = &cobra.Command{
	Use:   "gungnir",
	Short: "List subdomains discovered by Gungnir on the VPS",
	Long:  `Fetches and prints all subdomains from the 'hot-breads' collection on the VPS via the API.`,
	Run: func(cmd *cobra.Command, args []string) {
		data, err := fetchAPI("/hot-breads")
		if err != nil {
			fmt.Printf("%s %v\n", colors.Colorize(colors.Red, "❌"), err)
			return
		}
		printListColored(data)
	},
}

func init() {
	apiBreadsCmd.AddCommand(apiHTTPCmd, apiVHostsCmd, apiCVECmd, apiBreadsSubsCmd)
	apiHTTPCmd.AddCommand(apiHTTPAllCmd, apiHTTPTitleCmd, apiHTTPStatusCodeCmd, apiHTTPPortsCmd, apiHTTPCDNCmd, apiHTTPContentLengthCmd, apiHTTPTechCmd)
	apiBreadsSubsCmd.AddCommand(apiBreadsSubsTargetCmd, apiBreadsSubsProviderCmd)
	APICmd.AddCommand(apiGungnirCmd)
	APICmd.AddCommand(apiBreadsCmd)
	RootCmd.AddCommand(APICmd)
}
