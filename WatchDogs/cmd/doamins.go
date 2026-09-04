package cmd

import (
	"fmt"
	"log"

	"watchdogs/colors"

	db "watchdogs/DB"

	"github.com/spf13/cobra"
)

// DomainsCmd represents the base domains command. Exported (capital D).
var DomainsCmd = &cobra.Command{
	Use:   "domains",
	Short: "Extract domains from the database",
	Long:  `Extracts domains from different collections in the database.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// httpDomainsCmd represents the 'domains http' command
var httpDomainsCmd = &cobra.Command{
	Use:   "http",
	Short: "Extract domains from the 'http' collection",
	Long:  `Fetches subdomains from the 'http' collection in the database and prints them.`,
	Run: func(cmd *cobra.Command, args []string) {
		db.ConnectDB()
		defer db.DisconnectDB()

		httpDomains, err := db.GetAllDistinctSubdomainsFromHTTP()
		if err != nil {
			log.Fatalf("%s Error fetching domains from 'http' collection: %v\n", colors.Colorize(colors.Red, "❌"), err)
		}

		for _, domain := range httpDomains {
			fmt.Println(colors.Colorize(colors.Lavender, domain))
		}
	},
}

// subsDomainsCmd represents the 'domains subs' command
var subsDomainsCmd = &cobra.Command{
	Use:   "subs",
	Short: "Extract domains from the 'subdomains' collection",
	Long:  `Fetches subdomains from the 'subdomains' collection in the database and prints them.`,
	Run: func(cmd *cobra.Command, args []string) {
		db.ConnectDB()
		defer db.DisconnectDB()

		subsDomains, err := db.GetAllDistinctSubdomainsFromSubdomains()
		if err != nil {
			log.Fatalf("%s Error fetching domains from 'subdomains' collection: %v\n", colors.Colorize(colors.Red, "❌"), err)
		}

		for _, domain := range subsDomains {
			fmt.Println(colors.Colorize(colors.Lavender, domain))
		}
	},
}

// portsCmd represents the 'domains http ports' command
var portsCmd = &cobra.Command{
	Use:   "ports",
	Short: "Extract domains from the 'http' collection that have open ports",
	Long:  `Fetches subdomains from the 'http' collection in the database where the 'ports' array is not empty and prints them.`,
	Run: func(cmd *cobra.Command, args []string) {
		db.ConnectDB()
		defer db.DisconnectDB()

		domainsWithPorts, err := db.GetAllSubdomainsWithOpenPortsFromHTTP()
		if err != nil {
			log.Fatalf("%s Error fetching domains with ports from 'http' collection: %v\n", colors.Colorize(colors.Red, "❌"), err)
		}

		for _, domain := range domainsWithPorts {
			fmt.Println(colors.Colorize(colors.Lavender, domain))
		}
	},
}

func init() {
	DomainsCmd.AddCommand(httpDomainsCmd)
	DomainsCmd.AddCommand(subsDomainsCmd)
	httpDomainsCmd.AddCommand(portsCmd)
}
