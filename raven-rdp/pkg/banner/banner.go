// Package banner provides the RavenRDP startup artwork.
package banner

// Art is the RAVENRDP wordmark, pre-scaled for an 80-column terminal.
var Art = `
██████╗  █████╗ ██╗   ██╗███████╗███╗   ██╗
██╔══██╗██╔══██╗██║   ██║██╔════╝████╗  ██║
██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║
██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║
██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║
╚═╝  ╚═╝═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝`

// Tagline is the project subtitle.
const Tagline = "RDP CREDENTIAL AUDITOR"

// VersionLine renders the version line under the tagline.
func VersionLine(version string) string {
	return "v" + version
}
