package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-wireguard/internal/wireguard"
)

// Layout constants: the rows the table cannot use (header, tab bar, note
// line, table header, help bar, status line).
const (
	headerLines   = 2
	chromeLines   = 5
	minListHeight = 1
)

// listHeight is the number of table rows that fit on screen.
func (a *app) listHeight() int {
	return max(a.height-headerLines-chromeLines, minListHeight)
}

// View renders the whole screen.
func (a *app) View() string {
	switch a.mode {
	case modeConfirm:
		return a.confirm.View(a.theme, a.width, a.height)
	case modeInput:
		return a.input.View(a.theme, a.width, a.height)
	case modePicker:
		return a.picker.View(a.theme, a.width, a.height)
	case modeHelp:
		return lipgloss.Place(a.width, a.height, lipgloss.Center, lipgloss.Center,
			ui.HelpScreen(a.theme, toolName+" — keys", helpKeys(), a.width))
	default:
		return a.browseView()
	}
}

// browseView renders the tabbed main screen: header, tabs, a note line, the
// table, help bar and status line.
func (a *app) browseView() string {
	var body string
	switch {
	case a.loading && a.rowCount() == 0:
		body = ui.EmptyState(a.theme, "reading…", a.width, a.listHeight()+1)
	case a.loadFailed && a.rowCount() == 0:
		body = ui.EmptyState(a.theme, "could not read — see the message below",
			a.width, a.listHeight()+1)
	case a.rowCount() == 0:
		body = ui.EmptyState(a.theme, a.emptyMessage(), a.width, a.listHeight()+1)
	default:
		body = a.table()
	}

	note := a.noteLine()
	help := ui.HelpBar(a.theme, a.shortHelpKeys(), a.width)
	status := ui.StatusLine(a.theme, a.statusKind, a.status, a.defaultStatus(), a.width)
	return strings.Join([]string{a.header(), a.tabsView(), note, body, help, status}, "\n")
}

// noteLine is what sits between the tabs and the table: on the peers screen,
// which interface the peers belong to, since the selection lives on the
// interfaces screen.
func (a *app) noteLine() string {
	if a.screen != wireguard.ScreenPeers {
		return ""
	}
	dev, ok := a.selectedDevice()
	if !ok {
		return ""
	}
	return a.theme.Muted.Render(ui.Truncate(" peers of "+dev.Name+
		" · select another interface on the interfaces screen", a.width))
}

// tabsView renders the screens as one row, the current one accented.
func (a *app) tabsView() string {
	var parts []string
	for s := wireguard.Screen(0); s < wireguard.ScreenCount; s++ {
		label := " " + s.Title() + " "
		if s == a.screen {
			parts = append(parts, a.theme.Accent.Render(label))
			continue
		}
		parts = append(parts, a.theme.Muted.Render(label))
	}
	return ui.Truncate(strings.Join(parts, a.theme.Muted.Render("│")), a.width)
}

// header renders the facts at the top of the screen.
func (a *app) header() string {
	peers := 0
	for _, d := range a.state.Devices {
		peers += len(d.Peers)
	}
	facts := []ui.Fact{
		{Label: "interfaces", Value: strconv.Itoa(len(a.state.Devices))},
		{Label: "peers", Value: strconv.Itoa(peers)},
	}
	if wg, ok := compatFor(a.backendCompat, backendWG); ok && wg.Backend != "" {
		facts = append(facts, ui.CompatFact(a.theme, wg))
	}
	return ui.Header{Title: toolName, Subtitle: a.backend.Describe(), Facts: facts}.
		Render(a.theme, a.width)
}

// defaultStatus is the hint shown when there is no message to report.
func (a *app) defaultStatus() string {
	return strconv.Itoa(a.rowCount()) + " rows  ·  ? for help"
}

// emptyMessage is what a screen shows when it has no rows.
func (a *app) emptyMessage() string {
	switch a.screen {
	case wireguard.ScreenStatus:
		if !a.state.WGAvailable {
			return "no wg found — install wireguard-tools, or run --demo"
		}
		if a.state.WGError != "" {
			return "could not read WireGuard: " + a.state.WGError
		}
		return "no WireGuard interfaces are up"
	case wireguard.ScreenPeers:
		dev, ok := a.selectedDevice()
		if !ok {
			return "select an interface first"
		}
		if dev.ConfigOnly {
			return dev.Name + " is down: its peers are in " + wireguard.ConfPath(dev.Name) +
				" · u on the interfaces screen brings it up"
		}
		return "this interface has no peers"
	}
	return "nothing here"
}

// table renders the current screen's table.
func (a *app) table() string {
	columns, rows, styles := a.tableData()
	return ui.Table{
		Columns: columns, Rows: rows, Styles: styles,
		Selected: a.cursor[a.screen], Offset: a.offset[a.screen], Height: a.listHeight(),
	}.Render(a.theme, a.width)
}

// tableData builds the columns, rows and per-row styles for the current screen.
func (a *app) tableData() ([]ui.Column, [][]string, []*lipgloss.Style) {
	switch a.screen {
	case wireguard.ScreenPeers:
		return a.peersTable()
	default:
		return a.statusTable()
	}
}

func (a *app) statusTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "INTERFACE", Width: 12, Flex: true},
		{Title: "STATE", Width: 6},
		{Title: "PORT", Width: 6},
		// Whether the host firewall lets a handshake reach the port, and
		// whether the host forwards for the interface.
		{Title: "UDP IN", Width: 7},
		{Title: "FORWARD", Width: 8},
		{Title: "PEERS", Width: 6},
		{Title: "PUBLIC KEY", Width: 14},
	}
	rows := make([][]string, 0, len(a.state.Devices))
	styles := make([]*lipgloss.Style, 0, len(a.state.Devices))
	for _, d := range a.state.Devices {
		rows = append(rows, []string{
			d.Name, upState(d.Up), portOf(d.ListenPort), firewallText(d),
			forwardText(d), strconv.Itoa(len(d.Peers)), shortKey(d.PublicKey),
		})
		styles = append(styles, a.stateStyle(d.Up))
	}
	return columns, rows, styles
}

func (a *app) peersTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "PEER", Width: 14},
		{Title: "ENDPOINT", Width: 16, Flex: true},
		{Title: "HANDSHAKE", Width: 12},
		{Title: "TRANSFER", Width: 16},
		{Title: "ALLOWED IPS", Width: 18},
		{Title: "KEEP", Width: 5},
	}
	dev, ok := a.selectedDevice()
	if !ok {
		return columns, nil, nil
	}
	now := time.Now()
	rows := make([][]string, 0, len(dev.Peers))
	styles := make([]*lipgloss.Style, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		rows = append(rows, []string{
			shortKey(p.PublicKey), endpointOr(p.Endpoint),
			handshakeText(now, p.LastHandshake),
			transfer(p.RxBytes, p.TxBytes),
			strings.Join(p.AllowedIPs, ", "),
			keepaliveText(p.Keepalive),
		})
		styles = append(styles, a.handshakeStyle(now, p.LastHandshake))
	}
	return columns, rows, styles
}

// stateStyle colours an interface row by whether it is up.
func (a *app) stateStyle(up bool) *lipgloss.Style {
	if up {
		s := a.theme.Row.Foreground(a.theme.OK.GetForeground())
		return &s
	}
	s := a.theme.Row.Foreground(a.theme.Muted.GetForeground())
	return &s
}

// handshakeStyle colours a peer row: fresh handshakes read OK, a peer that has
// never connected reads muted.
func (a *app) handshakeStyle(now, t time.Time) *lipgloss.Style {
	if t.IsZero() {
		s := a.theme.Row.Foreground(a.theme.Muted.GetForeground())
		return &s
	}
	if now.Sub(t) < 3*time.Minute {
		s := a.theme.Row.Foreground(a.theme.OK.GetForeground())
		return &s
	}
	s := a.theme.Row
	return &s
}

// --- small formatters ---

// forwardText says whether the host forwards for an interface.
func forwardText(d wireguard.Device) string {
	if d.Forwarding {
		return "yes"
	}
	return "-"
}

func upState(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

func portOf(port int) string {
	if port == 0 {
		return "-"
	}
	return strconv.Itoa(port)
}

// shortKey shows enough of a public key to recognise the row, never the whole
// key and never a private one (the model carries no private key).
func shortKey(key string) string {
	if key == "" {
		return "-"
	}
	if len(key) <= 10 {
		return key
	}
	return key[:8] + "…"
}

func endpointOr(e string) string {
	if e == "" {
		return "(never connected)"
	}
	return e
}

func handshakeText(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return ago(now, t)
}

func keepaliveText(seconds int) string {
	if seconds == 0 {
		return "off"
	}
	return strconv.Itoa(seconds) + "s"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// transfer renders the rx/tx counters as one compact column.
func transfer(rx, tx int64) string {
	return "↓" + bytesHuman(rx) + " ↑" + bytesHuman(tx)
}

// bytesHuman renders a byte count in the largest unit that keeps it short.
func bytesHuman(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ago renders how long ago a moment was, in one unit.
func ago(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return humanDuration(now.Sub(t)) + " ago"
}

// humanDuration renders a duration in one unit.
func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dmin", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// shortHelpKeys is the single-line hint bar, tailored to the current screen.
func (a *app) shortHelpKeys() []ui.KeyHint {
	hints := []ui.KeyHint{{Key: "tab", Desc: "screen"}}
	switch a.screen {
	case wireguard.ScreenStatus:
		hints = append(hints,
			ui.KeyHint{Key: "N", Desc: "new iface"},
			ui.KeyHint{Key: "u", Desc: "up"}, ui.KeyHint{Key: "d", Desc: "down"},
			ui.KeyHint{Key: "w", Desc: "save"})
	case wireguard.ScreenPeers:
		hints = append(hints,
			ui.KeyHint{Key: "a", Desc: "add"}, ui.KeyHint{Key: "x", Desc: "remove"},
			ui.KeyHint{Key: "w", Desc: "save"})
	}
	return append(hints,
		ui.KeyHint{Key: "r", Desc: "reload"},
		ui.KeyHint{Key: "?", Desc: "help"},
		ui.KeyHint{Key: "q", Desc: "quit"},
	)
}

// helpKeys is the full key list for the help screen.
func helpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "tab / shift+tab", Desc: "next / previous screen"},
		{Key: "1 / 2", Desc: "jump to a screen"},
		{Key: "↑/k, ↓/j", Desc: "move the selection"},
		{Key: "g / G", Desc: "first / last row"},
		{Key: "pgup/pgdn", Desc: "scroll a page"},
		{Key: "r / ctrl+r", Desc: "reload"},
		{Key: "", Desc: ""},
		{Key: "N", Desc: "create a new interface from zero (keygen, conf, up); as"},
		{Key: "", Desc: "a forwarding server: ip_forward, FORWARD -I, MASQUERADE"},
		{Key: "", Desc: "(a firewalld policy on firewalld), and the listen port"},
		{Key: "", Desc: "opened when the host firewall does not accept it"},
		{Key: "u / d", Desc: "bring the selected interface up / down"},
		{Key: "w", Desc: "save the interface's runtime config (wg-quick save, then"},
		{Key: "", Desc: "the keys back out of the conf where their files load them)"},
		{Key: "a / x", Desc: "add / remove a peer on the interface (add: end with \"psk\""},
		{Key: "", Desc: "to also generate a pre-shared key file; then an optional"},
		{Key: "", Desc: "endpoint host:port and persistent keepalive, 25 behind NAT)"},
		{Key: "", Desc: ""},
		{Key: "note", Desc: "every change is previewed and confirmed first"},
		{Key: "keys", Desc: "a private key is never shown, typed, or put on a command line"},
		{Key: "", Desc: ""},
		{Key: "?", Desc: "close this help"},
		{Key: "q", Desc: "quit"},
	}
}
