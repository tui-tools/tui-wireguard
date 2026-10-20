package wireguard

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/runner"
)

func cmdOf(argv ...string) runner.Command { return runner.Command{Argv: argv} }

func TestBuildEnableForwarding(t *testing.T) {
	cmd, err := BuildEnableForwarding("wg0")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sh", "-c", "install -D -m 644 /dev/stdin /etc/sysctl.d/90-tui-wireguard-wg0-forward.conf" +
		" && sysctl -w net.ipv4.ip_forward=1"}
	if !reflect.DeepEqual(cmd.Argv, want) {
		t.Errorf("argv = %q", cmd.Argv)
	}
	if !strings.HasPrefix(cmd.Stdin, forwardDropInMarker+" for the forwarding server wg0.") ||
		!strings.HasSuffix(cmd.Stdin, "\nnet.ipv4.ip_forward = 1\n") {
		t.Errorf("drop-in = %q", cmd.Stdin)
	}
	if iface, enable, ok := ForwardingStep(cmd); !ok || !enable || iface != "wg0" {
		t.Errorf("ForwardingStep = %q %v %v", iface, enable, ok)
	}
	if _, err := BuildEnableForwarding("wg0;reboot"); err == nil {
		t.Error("accepted a bad interface name")
	}
}

// TestBuildDisableForwarding: the removal deletes only a file whose first
// line is the tool's marker, and leaves the running kernel alone.
func TestBuildDisableForwarding(t *testing.T) {
	cmd, err := BuildDisableForwarding("wg0")
	if err != nil {
		t.Fatal(err)
	}
	script := cmd.Argv[2]
	for _, want := range []string{
		`if head -n 1 /etc/sysctl.d/90-tui-wireguard-wg0-forward.conf | grep -q "^# Written by tui-wireguard"`,
		"then rm -f /etc/sysctl.d/90-tui-wireguard-wg0-forward.conf",
		"was not written by tui-wireguard: left in place", "exit 1",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "sysctl -w") {
		t.Errorf("the removal changes the running kernel:\n%s", script)
	}
	if !cmd.Destructive {
		t.Error("a removal is destructive")
	}
	if iface, enable, ok := ForwardingStep(cmd); !ok || enable || iface != "wg0" {
		t.Errorf("ForwardingStep = %q %v %v", iface, enable, ok)
	}
	// The marker the removal looks for is the first line the step writes.
	enable, _ := BuildEnableForwarding("wg0")
	if first, _, _ := strings.Cut(enable.Stdin, "\n"); !strings.HasPrefix(first, forwardDropInMarker) {
		t.Errorf("the drop-in's first line %q does not carry the marker", first)
	}
}

func TestForwardingStepIgnoresOtherShells(t *testing.T) {
	for _, build := range []func() (string, error){
		func() (string, error) { c, err := BuildGenerateInterfaceKey("wg0"); return c.Argv[2], err },
		func() (string, error) { c, err := BuildGeneratePSK("wg0", testPub); return c.Argv[2], err },
	} {
		script, err := build()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, ok := ForwardingStep(cmdOf("sh", "-c", script)); ok {
			t.Errorf("%q read as a forwarding step", script)
		}
	}
}

// TestBootSysctl is how systemd-sysctl orders the files: by name across the
// directories, a name in /etc masking the same name in /usr/lib, the last
// assignment winning.
func TestBootSysctl(t *testing.T) {
	files := []SysctlFile{
		{"/etc/sysctl.d/90-tui-wireguard-wg0-forward.conf", ForwardDropIn("wg0")},
		{"/etc/sysctl.d/99-sysctl.conf", "# kernel tunables\n;net.ipv4.ip_forward=0\n"},
		{"/usr/lib/sysctl.d/50-default.conf", "net.ipv4.conf.all.rp_filter = 2\n"},
		{"/usr/lib/sysctl.d/99-sysctl.conf", "net.ipv4.ip_forward = 0\n"}, // masked by /etc's
		{"/etc/sysctl.d/README.sysctl", "net.ipv4.ip_forward = 0\n"},      // not a .conf
	}
	if v, from := BootSysctl(files, ForwardSysctl); v != "1" || from != files[0].Path {
		t.Errorf("BootSysctl = %q from %q, want 1 from the drop-in", v, from)
	}
	// A later file wins, with a slash-written key and a "-" prefix.
	later := append(files, SysctlFile{"/run/sysctl.d/95-off.conf", "-net/ipv4/ip_forward=0\n"})
	if v, from := BootSysctl(later, ForwardSysctl); v != "0" || from != "/run/sysctl.d/95-off.conf" {
		t.Errorf("BootSysctl = %q from %q, want 0 from 95-off", v, from)
	}
	if v, from := BootSysctl(files[1:], ForwardSysctl); v != "" || from != "" {
		t.Errorf("nothing sets it, got %q from %q", v, from)
	}
}

func TestForwardAtBootWithout(t *testing.T) {
	k := Kernel{Files: []SysctlFile{
		{"/etc/sysctl.d/90-tui-wireguard-wg0-forward.conf", ForwardDropIn("wg0")},
		{"/etc/sysctl.d/90-tui-wireguard-wg1-forward.conf", ForwardDropIn("wg1")},
	}}
	// Another forwarding server's drop-in still turns it on.
	if v, from := k.ForwardAtBootWithout("wg1"); v != "1" || !strings.Contains(from, "wg0") {
		t.Errorf("without wg1: %q from %q", v, from)
	}
	k.Files = k.Files[:1]
	if v, _ := k.ForwardAtBootWithout("wg0"); v != "" {
		t.Errorf("without the only drop-in: %q", v)
	}
}

func TestParseForwardDropIns(t *testing.T) {
	got := ParseForwardDropIns([]string{"10-network-security.conf", "90-tui-wireguard-wg0-forward.conf",
		"90-tui-wireguard-wg.home-forward.conf", "90-tui-wireguard--x-forward.conf", "99-sysctl.conf"})
	if !reflect.DeepEqual(got, []string{"wg0", "wg.home"}) {
		t.Errorf("drop-ins = %q", got)
	}
}

// TestProblemsNameTheKernelSwitch is issue #33's report: forwarding rules on
// a kernel that does not forward are a problem; on a kernel that does, or an
// unreadable one, or without rules, they are not.
func TestProblemsNameTheKernelSwitch(t *testing.T) {
	fwd := Device{Name: "wg0", Forwarding: true}
	for _, tc := range []struct {
		forward string
		dev     Device
		want    bool
	}{
		{"0", fwd, true},
		{"1", fwd, false},
		{"", fwd, false},
		{"0", Device{Name: "wg1"}, false},
	} {
		got := State{Kernel: Kernel{Forward: tc.forward}}.Problems(tc.dev)
		if (len(got) > 0) != tc.want {
			t.Errorf("forward %q, forwarding %v: problems %q", tc.forward, tc.dev.Forwarding, got)
		}
	}
	k := Kernel{Forward: "0"}
	if k.ForwardWord() != KernelOff || (Kernel{}).ForwardWord() != KernelUnknown ||
		(Kernel{}).ForwardAtBootWord() != KernelOff || (Kernel{ForwardAtBoot: "1"}).ForwardAtBootWord() != KernelOn {
		t.Error("kernel words")
	}
}

// TestFakeAppliesTheForwardingStep: the demo writes and removes the drop-in
// the way the host would, and the kernel keeps forwarding after a removal.
func TestFakeAppliesTheForwardingStep(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	disable, _ := BuildDisableForwarding("wg0")
	if _, err := f.Run(ctx, disable); err != nil {
		t.Fatal(err)
	}
	state, _ := f.Load(ctx)
	if state.Kernel.HasDropIn("wg0") || state.Kernel.ForwardAtBoot != "" || state.Kernel.Forward != "1" {
		t.Errorf("after the removal: %+v", state.Kernel)
	}
	if _, err := f.Run(ctx, disable); err == nil {
		t.Error("removing a missing drop-in succeeded")
	}
	enable, _ := BuildEnableForwarding("wg9")
	if _, err := f.Run(ctx, enable); err != nil {
		t.Fatal(err)
	}
	state, _ = f.Load(ctx)
	if !state.Kernel.HasDropIn("wg9") || state.Kernel.ForwardAtBoot != "1" {
		t.Errorf("after enabling wg9: %+v", state.Kernel)
	}
}

// TestReadKernelReadsThisHost runs the real read: whatever this machine
// says, the switch is 0, 1 or unknown, and nothing panics on a missing
// directory.
func TestReadKernelReadsThisHost(t *testing.T) {
	k := readKernel()
	switch k.Forward {
	case "", "0", "1":
	default:
		t.Errorf("ip_forward = %q", k.Forward)
	}
}

// TestInterfaceConfHasNoSysctlHook: the switch is the tool's own step now, so
// no new conf carries a hook AppArmor would deny.
func TestInterfaceConfHasNoSysctlHook(t *testing.T) {
	for _, spec := range []ForwardSpec{
		{Egress: "eth0"},
		{Egress: "eth0", Manager: ManagerFirewalld, EgressZone: "public"},
	} {
		conf, err := InterfaceConfWith("wg0", "192.0.2.1/24", 51820, &spec)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(conf, "PostUp = sysctl") {
			t.Errorf("the conf turns forwarding on in a hook:\n%s", conf)
		}
		if !strings.Contains(conf, ForwardDropInPath("wg0")) {
			t.Errorf("the conf does not say where the switch is:\n%s", conf)
		}
	}
}
