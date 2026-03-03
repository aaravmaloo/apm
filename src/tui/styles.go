package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	PrimaryColor   = lipgloss.Color("#00C8E5")
	SecondaryColor = lipgloss.Color("#3B7DDD")
	AccentColor    = lipgloss.Color("#F2C94C")
	ErrorColor     = lipgloss.Color("#FF6B6B")
	SuccessColor   = lipgloss.Color("#2ECC71")
	GrayColor      = lipgloss.Color("#5F5F5F")
	LightGrayColor = lipgloss.Color("#A0A0A0")

	// Styles
	MainStyle = lipgloss.NewStyle().
			Margin(1, 1)

	HeaderStyle = lipgloss.NewStyle().
			Foreground(PrimaryColor).
			Bold(true).
			MarginBottom(1)

	SidebarStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, true, false, false).
			BorderForeground(GrayColor).
			Padding(0, 1).
			Width(24)

	ContentStyle = lipgloss.NewStyle().
			Padding(0, 1)

	SelectedStyle = lipgloss.NewStyle().
			Foreground(AccentColor).
			Bold(true)

	NormalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF"))

	BorderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(GrayColor).
			Padding(1, 2)

	TitleStyle = lipgloss.NewStyle().
			Background(PrimaryColor).
			Foreground(lipgloss.Color("#000000")).
			Padding(0, 1).
			Bold(true)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(ErrorColor).
			Bold(true)

	SuccessStyle = lipgloss.NewStyle().
			Foreground(SuccessColor).
			Bold(true)

	GrayStyle = lipgloss.NewStyle().
			Foreground(LightGrayColor)
)
