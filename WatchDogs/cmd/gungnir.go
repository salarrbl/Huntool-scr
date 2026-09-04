package cmd

import (
	"fmt"
	"log"

	"watchdogs/colors"

	db "watchdogs/DB"

	"github.com/spf13/cobra"
)

// gungnirCmd represents the gungnir command. Exported (capital G).
var gungnirCmd = &cobra.Command{
	Use:   "gungnir",
	Short: "List subdomains discovered by Gungnir",
	Long:  `Fetches and prints all subdomains from the 'hot-breads' collection in the database.`,
	Run: func(cmd *cobra.Command, args []string) {
		db.ConnectDB()
		defer db.DisconnectDB()
		hotBreadsRecords, err := db.GetAllHotBreadsSubdomains()
		if err != nil {
			log.Printf("%s Error fetching subdomains from 'hot-breads' collection: %v\n", colors.Colorize(colors.Red, "❌"), err)
			return
		}

		if len(hotBreadsRecords) == 0 {
			fmt.Println(colors.DimText("No hot-breads found."))
			return
		}

		fmt.Printf("%s %s\n\n", colors.Colorize(colors.Mauve+colors.Bold, "⚡ Gungnir Hot-Breads"), colors.Colorize(colors.Overlay0, fmt.Sprintf("(%d records)", len(hotBreadsRecords))))

		for _, record := range hotBreadsRecords {
			fmt.Println(colors.Colorize(colors.Lavender, record.Subdomain))
		}
	},
}
