package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tui-tools/tui-wireguard/internal/wireguard"
)

// kernelOff is the Ubuntu 26.04 case of issue #33: a forwarding server whose
// conf's sysctl hook AppArmor denied, so its rules are in place and the
// kernel does not forward, with no drop-in.
func kernelOff(a *app) *app {
	a.state.Kernel = wireguard.Kernel{Forward: "0"}
	return a
}

// TestForwardColumnSaysTheKernelIsOff: the FORWARD column and the status hint
// say why a forwarding server passes nothing.
func TestForwardColumnSaysTheKernelIsOff(t *testing.T) {
	a := kernelOff(newTestApp(t))
	a.setScreen(wireguard.ScreenStatus)
	view := a.View()
	if !strings.Contains(view, "ip_fwd=0") {
		t.Errorf("the FORWARD column does not say the kernel is off:\n%s", view)
	}
	if !strings.Contains(view, "wg0: forwarding off in the kernel") {
		t.Errorf("the status line does not say why nothing forwards:\n%s", view)
	}
	dev, _ := a.state.Device("wg0")
	if got := forwardText(dev, wireguard.Kernel{Forward: "1"}); got != "yes" {
		t.Errorf("FORWARD with the kernel on = %q", got)
	}
}

// TestFTurnsForwardingOn: F on a forwarding server whose kernel is off
// previews the drop-in and sysctl -w, explains why the hook did not do it,
// and the table says yes afterwards.
func TestFTurnsForwardingOn(t *testing.T) {
	a := kernelOff(newTestApp(t))
	a.setScreen(wireguard.ScreenStatus)
	model, _ := a.Update(key("F"))
	a = model.(*app)
	if a.mode != modeConfirm {
		t.Fatalf("F did not open a confirm (status %q)", a.status)
	}
	if !strings.Contains(a.confirm.Command, "install -D -m 644 /dev/stdin /etc/sysctl.d/90-tui-wireguard-wg0-forward.conf") ||
		!strings.Contains(a.confirm.Command, "sysctl -w net.ipv4.ip_forward=1") {
		t.Errorf("F preview = %q", a.confirm.Command)
	}
	for _, want := range []string{"the kernel does not forward", "AppArmor", "Now: off",
		"At boot: off (no sysctl.d file sets it", "net.ipv4.ip_forward = 1"} {
		if !strings.Contains(a.confirm.Body, want) {
			t.Errorf("F body lacks %q:\n%s", want, a.confirm.Body)
		}
	}
	a = confirmAndRun(t, a)
	state, _ := a.backend.Load(t.Context())
	a.state = state
	if view := a.View(); strings.Contains(view, "ip_fwd=0") {
		t.Errorf("still ip_fwd=0 after F:\n%s", view)
	}
}

// TestFRemovesTheDropIn: with the drop-in in place and the kernel forwarding
// (the demo's wg0), F offers the removal, which keeps the running kernel as
// it is and says what the next boot leaves.
func TestFRemovesTheDropIn(t *testing.T) {
	a := newTestApp(t)
	a.setScreen(wireguard.ScreenStatus)
	model, _ := a.Update(key("F"))
	a = model.(*app)
	if a.mode != modeConfirm || !a.confirm.Danger {
		t.Fatalf("F did not open a destructive confirm (mode %d)", a.mode)
	}
	if !strings.Contains(a.confirm.Command, "rm -f /etc/sysctl.d/90-tui-wireguard-wg0-forward.conf") {
		t.Errorf("removal preview = %q", a.confirm.Command)
	}
	for _, want := range []string{"keeps forwarding until the next boot",
		"After a reboot net.ipv4.ip_forward is off", "still has forwarding rules"} {
		if !strings.Contains(a.confirm.Body, want) {
			t.Errorf("removal body lacks %q:\n%s", want, a.confirm.Body)
		}
	}
}

// TestFOnAnEndpointIsRefused: an interface without forwarding rules and
// without a drop-in is not a forwarding server; F says so and runs nothing.
func TestFOnAnEndpointIsRefused(t *testing.T) {
	a := newTestApp(t)
	a.state.Devices[0].Forwarding = false
	a.state.Kernel = wireguard.Kernel{Forward: "1"}
	a.setScreen(wireguard.ScreenStatus)
	model, _ := a.Update(key("F"))
	a = model.(*app)
	if a.mode == modeConfirm || !strings.Contains(a.status, "not a forwarding server") {
		t.Errorf("F on an endpoint: mode %d, status %q", a.mode, a.status)
	}
}

// TestCheckReportsTheKernelSwitch: --check carries the switch now and at boot,
// and a forwarding server on a kernel that does not forward is a problem.
func TestCheckReportsTheKernelSwitch(t *testing.T) {
	state, _ := wireguard.NewFake().Load(context.Background())
	summary := summariseWG(state)
	if summary.KernelForwarding != "on" || summary.KernelForwardingAtBoot != "on" ||
		!summary.Interfaces[0].ForwardingDropIn || len(summary.Interfaces[0].Problems) != 0 {
		t.Errorf("demo summary = %+v", summary)
	}

	state.Kernel = wireguard.Kernel{Forward: "0"}
	summary = summariseWG(state)
	if summary.KernelForwarding != "off" || summary.KernelForwardingAtBoot != "off" {
		t.Errorf("kernel = %q at boot %q", summary.KernelForwarding, summary.KernelForwardingAtBoot)
	}
	if p := summary.Interfaces[0].Problems; len(p) != 1 || !strings.Contains(p[0], "forwarding off in the kernel") {
		t.Errorf("problems = %q", p)
	}
	out, _ := json.Marshal(summary)
	if !strings.Contains(string(out), `"kernelForwarding":"off"`) ||
		!strings.Contains(string(out), `"problems":["forwarding off in the kernel`) {
		t.Errorf("--check JSON: %s", out)
	}
}
