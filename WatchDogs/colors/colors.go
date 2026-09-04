package colors

import (
	"fmt"
	"strings"
)

// NoColor disables all color output when true
var NoColor bool

// SetNoColor sets the global NoColor flag
func SetNoColor(v bool) {
	NoColor = v
}

// Catppuccin Mocha Palette - ANSI true-color escape codes
const (
	Rosewater = "\x1b[38;2;245;224;220m"
	Flamingo  = "\x1b[38;2;242;205;205m"
	Pink      = "\x1b[38;2;245;194;231m"
	Mauve     = "\x1b[38;2;203;166;247m"
	Red       = "\x1b[38;2;243;139;168m"
	Maroon    = "\x1b[38;2;235;160;172m"
	Peach     = "\x1b[38;2;250;179;135m"
	Yellow    = "\x1b[38;2;249;226;175m"
	Green     = "\x1b[38;2;166;227;161m"
	Teal      = "\x1b[38;2;148;226;213m"
	Sky       = "\x1b[38;2;137;220;235m"
	Sapphire  = "\x1b[38;2;116;199;236m"
	Blue      = "\x1b[38;2;137;180;250m"
	Lavender  = "\x1b[38;2;180;190;254m"
	Text      = "\x1b[38;2;205;214;244m"
	Subtext1  = "\x1b[38;2;186;194;222m"
	Subtext0  = "\x1b[38;2;166;173;200m"
	Overlay2  = "\x1b[38;2;147;153;178m"
	Overlay1  = "\x1b[38;2;127;132;156m"
	Overlay0  = "\x1b[38;2;108;112;134m"
	Surface2  = "\x1b[38;2;88;91;112m"
	Surface1  = "\x1b[38;2;69;71;90m"
	Surface0  = "\x1b[38;2;49;50;68m"
	Base      = "\x1b[38;2;30;30;46m"
	Mantle    = "\x1b[38;2;24;24;37m"
	Crust     = "\x1b[38;2;17;17;27m"

	Bold      = "\x1b[1m"
	Dim       = "\x1b[2m"
	Italic    = "\x1b[3m"
	Underline = "\x1b[4m"
	Reset     = "\x1b[0m"
)

// Colorize wraps text with a color and reset
func Colorize(color, text string) string {
	if NoColor {
		return text
	}
	return color + text + Reset
}

// StatusCodeColor returns appropriate color for HTTP status code
func StatusCodeColor(code int) string {
	if NoColor {
		return ""
	}
	switch {
	case code >= 200 && code < 300:
		return Green
	case code >= 300 && code < 400:
		return Blue
	case code >= 400 && code < 500:
		return Peach
	case code >= 500:
		return Red
	default:
		return Overlay1
	}
}

// StatusCodeBadge returns a styled badge for status codes with background
func StatusCodeBadge(code int) string {
	if NoColor {
		return fmt.Sprintf(" %d ", code)
	}
	var bg string
	var fg string
	switch {
	case code >= 200 && code < 300:
		bg = "\x1b[48;2;64;100;50m"
		fg = Text
	case code >= 300 && code < 400:
		bg = "\x1b[48;2;40;60;100m"
		fg = Text
	case code >= 400 && code < 500:
		bg = "\x1b[48;2;100;70;40m"
		fg = Text
	case code >= 500:
		bg = "\x1b[48;2;100;40;50m"
		fg = Text
	default:
		bg = "\x1b[48;2;60;60;70m"
		fg = Overlay1
	}
	return fmt.Sprintf("%s%s %d %s", bg, fg, code, Reset)
}

// TitleColor returns color based on title content
func TitleColor(title string) string {
	if NoColor {
		return ""
	}
	if strings.TrimSpace(title) == "" {
		return Overlay0 + Dim
	}
	return Yellow + Italic
}

// PortColor returns color for port numbers
func PortColor(port string) string {
	if NoColor {
		return ""
	}
	p := strings.TrimSpace(port)
	switch p {
	case "80", "8080":
		return Sky
	case "443", "8443":
		return Green
	default:
		return Peach
	}
}

// TechColor returns a color for a technology name (deterministic based on name)
func TechColor(tech string) string {
	if NoColor {
		return ""
	}
	tech = strings.ToLower(strings.TrimSpace(tech))
	palette := []string{
		Rosewater, Flamingo, Pink, Mauve, Red, Maroon,
		Peach, Yellow, Green, Teal, Sky, Sapphire, Blue, Lavender,
	}
	hash := 0
	for _, c := range tech {
		hash += int(c)
	}
	return palette[hash%len(palette)]
}

// CDNColor returns color for CDN info
func CDNColor(cdn string) string {
	if NoColor {
		return ""
	}
	if strings.TrimSpace(cdn) == "" {
		return Overlay0 + Dim
	}
	return Teal
}

// ContentLengthColor returns color based on content length
func ContentLengthColor(length int) string {
	if NoColor {
		return ""
	}
	switch {
	case length == 0:
		return Overlay0 + Dim
	case length < 1000:
		return Sky
	case length < 10000:
		return Blue
	case length < 100000:
		return Mauve
	default:
		return Pink
	}
}

// SeverityColor returns color for severity level
func SeverityColor(severity string) string {
	if NoColor {
		return ""
	}
	switch strings.ToLower(severity) {
	case "critical", "high":
		return Red + Bold
	case "medium":
		return Peach + Bold
	case "low":
		return Yellow
	case "info":
		return Blue
	default:
		return Overlay1
	}
}

// Pipe returns a dimmed pipe separator
func Pipe() string {
	if NoColor {
		return " | "
	}
	return Overlay0 + " | " + Reset
}

// BracketColor returns color for brackets in arrays
func BracketColor() string {
	if NoColor {
		return ""
	}
	return Surface2
}

// DimText returns dimmed text
func DimText(text string) string {
	if NoColor {
		return text
	}
	return Overlay0 + Dim + text + Reset
}

// BoldText returns bold text
func BoldText(text string) string {
	if NoColor {
		return text
	}
	return Bold + text + Reset
}

// FormatPorts formats a port array with Catppuccin colors
func FormatPorts(ports []string) string {
	if len(ports) == 0 {
		return DimText("[]")
	}
	if NoColor {
		return "[" + strings.Join(ports, ", ") + "]"
	}
	var parts []string
	parts = append(parts, BracketColor()+"["+Reset)
	for i, port := range ports {
		parts = append(parts, PortColor(port)+port+Reset)
		if i < len(ports)-1 {
			parts = append(parts, Overlay0+", "+Reset)
		}
	}
	parts = append(parts, BracketColor()+"]"+Reset)
	return strings.Join(parts, "")
}

// FormatTechnologies formats a tech array with Catppuccin colors
func FormatTechnologies(techs []string) string {
	if len(techs) == 0 {
		return DimText("[]")
	}
	if NoColor {
		return "[" + strings.Join(techs, ", ") + "]"
	}
	var parts []string
	parts = append(parts, BracketColor()+"["+Reset)
	for i, tech := range techs {
		parts = append(parts, TechColor(tech)+tech+Reset)
		if i < len(techs)-1 {
			parts = append(parts, Overlay0+", "+Reset)
		}
	}
	parts = append(parts, BracketColor()+"]"+Reset)
	return strings.Join(parts, "")
}

// FormatArray formats a generic string array with subtle colors
func FormatArray(items []string) string {
	if len(items) == 0 {
		return DimText("[]")
	}
	if NoColor {
		return "[" + strings.Join(items, ", ") + "]"
	}
	var parts []string
	parts = append(parts, BracketColor()+"["+Reset)
	for i, item := range items {
		parts = append(parts, Subtext1+item+Reset)
		if i < len(items)-1 {
			parts = append(parts, Overlay0+", "+Reset)
		}
	}
	parts = append(parts, BracketColor()+"]"+Reset)
	return strings.Join(parts, "")
}
