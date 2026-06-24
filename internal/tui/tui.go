package tui

import (
	"fmt"
	"strings"
	"sync/atomic"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	styleGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	styleRed    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	styleYellow = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	styleGray   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleBold   = lipgloss.NewStyle().Bold(true)
	styleCyan   = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
)

type AddResultMsg struct {
	Line string
	Kind string // "found", "takeover", "inactive", "info"
}

type PhaseMsg struct{ Phase string }
type DoneMsg struct{}

type counters struct {
	found    atomic.Int64
	active   atomic.Int64
	takeover atomic.Int64
	cors     atomic.Int64
}

type model struct {
	phase   string
	recent  []string
	done    bool
	width   int
	counts  *counters
}

func newModel(c *counters) model {
	return model{phase: "Initializing", counts: c, width: 80}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case AddResultMsg:
		line := msg.Line
		switch msg.Kind {
		case "found":
			line = styleGreen.Render("[+]") + " " + line
		case "takeover":
			line = styleYellow.Render("[TAKEOVER]") + " " + line
		case "inactive":
			line = styleGray.Render("[-]") + " " + line
		case "info":
			line = styleCyan.Render("[~]") + " " + line
		}
		m.recent = append(m.recent, line)
		if len(m.recent) > 12 {
			m.recent = m.recent[len(m.recent)-12:]
		}
	case PhaseMsg:
		m.phase = msg.Phase
	case DoneMsg:
		m.done = true
		return m, tea.Quit
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m model) View() string {
	if m.done {
		return ""
	}

	var sb strings.Builder

	// Header
	sb.WriteString(styleBold.Render("SubHawk") + styleGray.Render(" v1.3") + "\n")
	sb.WriteString(styleGray.Render(strings.Repeat("─", m.width)) + "\n")

	// Phase
	sb.WriteString(fmt.Sprintf("Phase: %s\n\n", styleCyan.Render(m.phase)))

	// Counters
	found := m.counts.found.Load()
	active := m.counts.active.Load()
	takeover := m.counts.takeover.Load()
	cors := m.counts.cors.Load()

	sb.WriteString(fmt.Sprintf(
		" %s %-8d  %s %-8d  %s %-8d  %s %-8d\n\n",
		styleGray.Render("FOUND"), found,
		styleGreen.Render("ACTIVE"), active,
		styleRed.Render("TAKEOVERS"), takeover,
		styleYellow.Render("CORS"), cors,
	))

	// Recent findings
	sb.WriteString(styleGray.Render("Recent findings:\n"))
	for _, line := range m.recent {
		sb.WriteString("  " + line + "\n")
	}

	return sb.String()
}

// Program wraps tea.Program and exposes counters.
type Program struct {
	p       *tea.Program
	counts  *counters
}

func New() *Program {
	c := &counters{}
	m := newModel(c)
	p := tea.NewProgram(m, tea.WithAltScreen())
	return &Program{p: p, counts: c}
}

func (pr *Program) Start() error {
	_, err := pr.p.Run()
	return err
}

func (pr *Program) SetPhase(phase string) {
	pr.p.Send(PhaseMsg{Phase: phase})
}

func (pr *Program) AddFound(line string) {
	pr.counts.found.Add(1)
	pr.counts.active.Add(1)
	pr.p.Send(AddResultMsg{Line: line, Kind: "found"})
}

func (pr *Program) AddTakeover(line string) {
	pr.counts.found.Add(1)
	pr.counts.takeover.Add(1)
	pr.p.Send(AddResultMsg{Line: line, Kind: "takeover"})
}

func (pr *Program) AddInactive(line string) {
	pr.counts.found.Add(1)
	pr.p.Send(AddResultMsg{Line: line, Kind: "inactive"})
}

func (pr *Program) AddInfo(line string) {
	pr.p.Send(AddResultMsg{Line: line, Kind: "info"})
}

func (pr *Program) AddCORS() {
	pr.counts.cors.Add(1)
}

func (pr *Program) Done() {
	pr.p.Send(DoneMsg{})
}
