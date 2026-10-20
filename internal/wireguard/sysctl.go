package wireguard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
)

// This file is the kernel's forwarding switch, net.ipv4.ip_forward (issue
// #33).
//
// A forwarding server's conf used to turn it on with `PostUp = sysctl -w
// net.ipv4.ip_forward=1`. Ubuntu 26.04 confines wg-quick with an AppArmor
// profile whose sysctl may write only src_valid_mark, so that hook is denied,
// `wg-quick up` still reports success, and the interface comes up with its
// forwarding rules in place and nothing forwarded. So the tool turns
// forwarding on itself, outside wg-quick, in a previewed step: a drop-in under
// /etc/sysctl.d, which systemd-sysctl applies at every boot, and `sysctl -w`
// for now. Each forwarding server has its own drop-in, so removing one never
// turns off what another still needs.
//
// The rules stay IPv4 only (ParseNetworks refuses IPv6), so the switch is
// net.ipv4.ip_forward alone.

// ForwardSysctl is the kernel switch a forwarding server needs.
const ForwardSysctl = "net.ipv4.ip_forward"

// ipForwardProc is where the kernel reports the switch.
const ipForwardProc = "/proc/sys/net/ipv4/ip_forward"

// SysctlDir is where the tool writes its drop-ins.
const SysctlDir = "/etc/sysctl.d"

// forwardDropInPrefix and forwardDropInSuffix frame an interface's drop-in.
// 90 runs after the distributions' own files (Ubuntu's 10-*, 50-*, Fedora's
// 50-*) and before 99-sysctl.conf, the link to /etc/sysctl.conf, so a line an
// administrator wrote there still has the last word.
const (
	forwardDropInPrefix = "90-tui-wireguard-"
	forwardDropInSuffix = "-forward.conf"
)

// forwardDropInMarker is the first line of every drop-in the tool writes:
// it is how a removal knows the file is the tool's to delete.
const forwardDropInMarker = "# Written by tui-wireguard"

// ForwardDropInPath is the drop-in that turns forwarding on for a forwarding
// server.
func ForwardDropInPath(iface string) string {
	return SysctlDir + "/" + forwardDropInPrefix + iface + forwardDropInSuffix
}

// ForwardDropIn is the content of an interface's drop-in.
func ForwardDropIn(iface string) string {
	return forwardDropInMarker + " for the forwarding server " + iface + ".\n" +
		"# Peers reach the networks behind this host through it, which needs the\n" +
		"# kernel to forward. tui-wireguard removes this file when asked (F);\n" +
		"# other drop-ins that set the same switch are left alone.\n" +
		ForwardSysctl + " = 1\n"
}

// BuildEnableForwarding assembles the step that turns forwarding on for a
// forwarding server: the drop-in, written with `install` from stdin so it is
// whole and 644 the moment it exists (its content is shown in the dialog),
// and `sysctl -w` so the kernel forwards now rather than after a reboot. It
// runs as its own root shell, not as a wg-quick hook, which is what AppArmor
// denies on Ubuntu 26.04.
func BuildEnableForwarding(iface string) (runner.Command, error) {
	if !ValidInterface(iface) {
		return runner.Command{}, fmt.Errorf("not a valid interface name: %q", iface)
	}
	path := ForwardDropInPath(iface)
	return runner.Command{
		Argv: []string{"sh", "-c",
			"install -D -m 644 /dev/stdin " + path + " && sysctl -w " + ForwardSysctl + "=1"},
		Description: "Turn on forwarding for " + iface + " (" + path + ")",
		Stdin:       ForwardDropIn(iface),
	}, nil
}

// BuildDisableForwarding assembles the removal of an interface's drop-in. It
// deletes the file only when its first line is the tool's marker, so a file an
// administrator put at that path is refused rather than lost. The running
// kernel is left as it is: something else on the host may rely on the switch,
// and the dialog says what it will be after the next boot.
func BuildDisableForwarding(iface string) (runner.Command, error) {
	if !ValidInterface(iface) {
		return runner.Command{}, fmt.Errorf("not a valid interface name: %q", iface)
	}
	path := ForwardDropInPath(iface)
	script := `if head -n 1 ` + path + ` | grep -q "^` + forwardDropInMarker + `"; then rm -f ` + path +
		`; else echo "` + path + ` was not written by tui-wireguard: left in place" >&2; exit 1; fi`
	return runner.Command{
		Argv:        []string{"sh", "-c", script},
		Description: "Remove " + path,
		Destructive: true,
	}, nil
}

// Kernel is the kernel's forwarding switch as this host has it.
type Kernel struct {
	// Forward is net.ipv4.ip_forward now, read from /proc: "1", "0", or
	// empty when it could not be read.
	Forward string
	// ForwardAtBoot is the value the sysctl.d drop-ins set at boot, empty
	// when none sets it (the kernel's default, 0), and ForwardAtBootFrom the
	// file that sets it last.
	ForwardAtBoot     string
	ForwardAtBootFrom string
	// DropIns are the interfaces that have the tool's drop-in.
	DropIns []string
	// Files are the sysctl.d files ForwardAtBoot was worked out from, in
	// sysctlDirs order, kept to say what removing a drop-in leaves.
	Files []SysctlFile
}

// ForwardOff reports that the kernel is known not to forward.
func (k Kernel) ForwardOff() bool { return k.Forward == "0" }

// HasDropIn reports whether an interface has the tool's drop-in.
func (k Kernel) HasDropIn(iface string) bool {
	for _, name := range k.DropIns {
		if name == iface {
			return true
		}
	}
	return false
}

// Kernel forwarding words, for --check and the dialogs.
const (
	KernelOn      = "on"
	KernelOff     = "off"
	KernelUnknown = "unknown"
)

// ForwardWord is Forward as a word: on, off or unknown.
func (k Kernel) ForwardWord() string { return sysctlWord(k.Forward, KernelUnknown) }

// ForwardAtBootWord is ForwardAtBoot as a word: a switch nothing sets is off
// at boot, the kernel's default.
func (k Kernel) ForwardAtBootWord() string { return sysctlWord(k.ForwardAtBoot, KernelOff) }

func sysctlWord(v, empty string) string {
	switch v {
	case "":
		return empty
	case "0":
		return KernelOff
	}
	return KernelOn
}

// ProblemKernelForwardOff is the problem a forwarding server has when the
// kernel does not forward: its rules are in place and nothing passes them.
const ProblemKernelForwardOff = "forwarding off in the kernel (net.ipv4.ip_forward = 0): " +
	"the rules are in place and nothing is forwarded"

// Problems are what is wrong with an interface that the table alone would not
// say: today, a forwarding server on a kernel that does not forward.
func (s State) Problems(d Device) []string {
	if d.Forwarding && s.Kernel.ForwardOff() {
		return []string{ProblemKernelForwardOff}
	}
	return nil
}

// SysctlFile is one sysctl.d file: its path and content.
type SysctlFile struct {
	Path    string
	Content string
}

// sysctlDirs are the directories systemd-sysctl reads, most important first:
// a file in an earlier one masks the file of the same name in a later one.
var sysctlDirs = []string{"/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d",
	"/usr/lib/sysctl.d", "/lib/sysctl.d"}

// BootSysctl is the value systemd-sysctl gives key at boot, and the file it
// comes from, given the files of every sysctl.d directory in sysctlDirs
// order. Files are applied by name, across directories; of two files with one
// name only the one in the earlier directory counts; a later assignment wins.
// A key is written with dots or slashes and may carry a leading "-" (ignore
// errors); comments start with # or ;. Empty: nothing sets it.
func BootSysctl(files []SysctlFile, key string) (value, from string) {
	byName := map[string]SysctlFile{}
	for _, f := range files {
		name := filepath.Base(f.Path)
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		if _, masked := byName[name]; !masked {
			byName[name] = f
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		f := byName[name]
		for _, line := range strings.Split(f.Content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' || line[0] == ';' {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k = strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(k), "-"), "/", ".")
			if k == key {
				value, from = strings.TrimSpace(v), f.Path
			}
		}
	}
	return value, from
}

// ParseForwardDropIns reads the names in /etc/sysctl.d into the interfaces
// that have the tool's drop-in.
func ParseForwardDropIns(names []string) []string {
	var ifaces []string
	for _, name := range names {
		iface, ok := strings.CutPrefix(name, forwardDropInPrefix)
		if !ok {
			continue
		}
		iface, ok = strings.CutSuffix(iface, forwardDropInSuffix)
		if ok && ValidInterface(iface) {
			ifaces = append(ifaces, iface)
		}
	}
	return ifaces
}

// readKernel reads the forwarding switch and the sysctl.d drop-ins. All of it
// is world-readable, so it is plain file reads, no process and no privilege.
// A file that cannot be read is skipped: the answer is then as good as what
// could be read, and the switch itself is unknown rather than off.
func readKernel() Kernel {
	var k Kernel
	if b, err := os.ReadFile(ipForwardProc); err == nil {
		k.Forward = strings.TrimSpace(string(b))
	}
	var files []SysctlFile
	for _, dir := range sysctlDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
			path := filepath.Join(dir, e.Name())
			// The path is a fixed sysctl.d directory and a name listed in it;
			// reading follows 99-sysctl.conf -> ../sysctl.conf, as
			// systemd-sysctl does.
			if b, err := os.ReadFile(path); err == nil { //nolint:gosec // see above
				files = append(files, SysctlFile{Path: path, Content: string(b)})
			}
		}
		if dir == SysctlDir {
			k.DropIns = ParseForwardDropIns(names)
		}
	}
	k.Files = files
	k.ForwardAtBoot, k.ForwardAtBootFrom = BootSysctl(files, ForwardSysctl)
	return k
}

// ForwardAtBootWithout is ForwardAtBoot as it would be without an
// interface's drop-in: what removing it leaves for the next boot.
func (k Kernel) ForwardAtBootWithout(iface string) (value, from string) {
	skip := ForwardDropInPath(iface)
	kept := make([]SysctlFile, 0, len(k.Files))
	for _, f := range k.Files {
		if f.Path != skip {
			kept = append(kept, f)
		}
	}
	return BootSysctl(kept, ForwardSysctl)
}

// forwardDropInPattern finds the drop-in a forwarding step writes or removes.
var forwardDropInPattern = regexp.MustCompile(regexp.QuoteMeta(SysctlDir+"/"+forwardDropInPrefix) +
	`([A-Za-z0-9_.-]+)` + regexp.QuoteMeta(forwardDropInSuffix))

// ForwardingStep reports whether cmd is BuildEnableForwarding (enable) or
// BuildDisableForwarding (!enable), and for which interface.
func ForwardingStep(cmd runner.Command) (iface string, enable, ok bool) {
	argv := cmd.Argv
	if len(argv) != 3 || argv[0] != "sh" || argv[1] != "-c" {
		return "", false, false
	}
	m := forwardDropInPattern.FindStringSubmatch(argv[2])
	if m == nil || !ValidInterface(m[1]) {
		return "", false, false
	}
	switch {
	case strings.HasPrefix(argv[2], "install -D -m 644 /dev/stdin "):
		return m[1], true, true
	case strings.HasPrefix(argv[2], "if head -n 1 "):
		return m[1], false, true
	}
	return "", false, false
}
