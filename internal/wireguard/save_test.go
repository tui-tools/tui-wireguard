package wireguard

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Invented keys for the save tests: valid key syntax, plainly not real.
const (
	saveIfaceKey = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk="
	saveOtherKey = "ooooooooooooooooooooooooooooooooooooooooooo="
	savePeerA    = "Aa/+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	savePeerB    = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	savePeerC    = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
	savePskA     = "pppppppppppppppppppppppppppppppppppppppppp1="
	savePskB     = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2="
)

func TestBuildSaveConfig(t *testing.T) {
	cmd, err := BuildSaveConfig("wg0")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(cmd.Argv) != 5 || cmd.Argv[0] != "sh" || cmd.Argv[1] != "-c" ||
		cmd.Argv[3] != saveScriptName || cmd.Argv[4] != saveRewriteAwk {
		t.Fatalf("argv = %q, want sh -c <script> %s <awk program>", cmd.Argv, saveScriptName)
	}
	script := cmd.Argv[2]
	for _, want := range []string{
		"set -e", "\nwg-quick save wg0\n", "umask 077",
		"awk -v key=/etc/wireguard/wg0.key -v pskprefix=/etc/wireguard/wg0- -v conf=/etc/wireguard/wg0.conf",
		"mv /etc/wireguard/wg0.conf.tui-save /etc/wireguard/wg0.conf",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
	// The program is on the command line the dialog shows, never on stdin.
	if cmd.Stdin != "" {
		t.Errorf("the save carries stdin the preview would not show: %q", cmd.Stdin)
	}
	// The shell itself never names a private-key flag: only the awk program
	// does, as the line it recognises.
	if strings.Contains(script, "private-key") {
		t.Errorf("the save shell sets a private key:\n%s", script)
	}
	if !cmd.Destructive {
		t.Error("save rewrites the conf file and must be marked destructive")
	}
	if iface, ok := SavedInterface(cmd); !ok || iface != "wg0" {
		t.Errorf("SavedInterface = %q, %v", iface, ok)
	}
	if _, err := BuildSaveConfig("wg0;reboot"); err == nil {
		t.Error("accepted a bad interface name")
	}
}

// awks are the awk implementations on this machine. The program has to run on
// every one a user's distribution makes /usr/bin/awk: mawk on Debian and
// Ubuntu, gawk on Fedora and Arch, busybox on the small ones.
func awks(t *testing.T) map[string][]string {
	t.Helper()
	found := map[string][]string{}
	for _, name := range []string{"awk", "mawk", "gawk", "original-awk"} {
		if path, err := exec.LookPath(name); err == nil {
			found[name] = []string{path}
		}
	}
	if path, err := exec.LookPath("busybox"); err == nil {
		found["busybox"] = []string{path, "awk"}
	}
	if len(found) == 0 {
		t.Skip("no awk on this machine")
	}
	return found
}

// saveDir is a stand-in for /etc/wireguard: the key file and the pre-shared
// key files the tool would have written.
type saveDir struct {
	dir string
}

func newSaveDir(t *testing.T) saveDir {
	t.Helper()
	return saveDir{dir: t.TempDir()}
}

func (d saveDir) key() string    { return filepath.Join(d.dir, "wg0.key") }
func (d saveDir) prefix() string { return filepath.Join(d.dir, "wg0") + "-" }
func (d saveDir) conf() string   { return filepath.Join(d.dir, "wg0.conf") }
func (d saveDir) pskFile(pub string) string {
	return strings.Replace(PSKPath("wg0", pub), pskPrefix("wg0"), d.prefix(), 1)
}

func (d saveDir) write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// keyHook is the tool's own key line for this directory.
func (d saveDir) keyHook() string { return "PostUp = wg set %i private-key " + d.key() }

// rewrite runs the save's awk program over conf, as the save shell does.
func (d saveDir) rewrite(t *testing.T, awk []string, conf string) (out, summary string) {
	t.Helper()
	d.write(t, d.conf(), conf)
	args := append(append([]string{}, awk[1:]...),
		"-v", "key="+d.key(), "-v", "pskprefix="+d.prefix(), "-v", "conf="+d.conf(),
		saveRewriteAwk, d.conf())
	// The binary is an awk found on PATH by awks and the arguments are the
	// test's own temp paths and the package's program: nothing user-supplied.
	cmd := exec.CommandContext(context.Background(), awk[0], args...) //nolint:gosec // see above
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\n%s", awk[0], err, stderr.String())
	}
	return stdout.String(), strings.TrimSpace(stderr.String())
}

// wgQuickSave does what `wg-quick save` does to a conf: the [Interface] lines
// it keeps from the file it replaces (addresses and hooks, in its own order)
// followed by `wg showconf`, whose [Interface] carries the listen port and the
// private key, and whose peers carry their pre-shared keys inline.
func wgQuickSave(old, showconf string) string {
	keep := map[string][]string{}
	order := []string{"Address", "DNS", "MTU", "Table", "SaveConfig", "PreUp", "PostUp", "PreDown", "PostDown"}
	inIface := false
	for _, l := range strings.Split(old, "\n") {
		if strings.HasPrefix(l, "[") {
			inIface = l == "[Interface]"
			continue
		}
		if !inIface {
			continue
		}
		k, _, ok := strings.Cut(l, " = ")
		if ok {
			keep[k] = append(keep[k], l)
		}
	}
	head := "[Interface]\n"
	for _, k := range order {
		for _, l := range keep[k] {
			head += l + "\n"
		}
	}
	return strings.Replace(showconf, "[Interface]\n", head, 1)
}

// showconf is `wg showconf` for wg0 with the given peers' blocks.
func showconf(privateKey string, peers ...string) string {
	s := "[Interface]\nListenPort = 51820\nPrivateKey = " + privateKey + "\n"
	for _, p := range peers {
		s += "\n" + p
	}
	return s
}

func peerBlock(pub, psk, ips string) string {
	s := "[Peer]\nPublicKey = " + pub + "\n"
	if psk != "" {
		s += "PresharedKey = " + psk + "\n"
	}
	return s + "AllowedIPs = " + ips + "\n"
}

// toolConf is the conf N writes, for this directory.
func (d saveDir) toolConf() string {
	return "[Interface]\n# a comment wg-quick save drops\nAddress = 10.8.0.1/24\nListenPort = 51820\n" +
		d.keyHook() + "\nPostUp = iptables -I FORWARD -i %i -j ACCEPT\nPostDown = iptables -D FORWARD -i %i -j ACCEPT\n"
}

// TestSaveTakesTheSecretsBackOut is issue #32: after the save the tool's
// conf carries no PrivateKey and no PresharedKey that a file can load, and
// says what it did.
func TestSaveTakesTheSecretsBackOut(t *testing.T) {
	for name, awk := range awks(t) {
		t.Run(name, func(t *testing.T) {
			d := newSaveDir(t)
			d.write(t, d.key(), saveIfaceKey+"\n")
			d.write(t, d.pskFile(savePeerA), savePskA+"\n")
			// Peer B's file holds a different key than the one in use.
			d.write(t, d.pskFile(savePeerB), savePskA+"\n")
			saved := wgQuickSave(d.toolConf(), showconf(saveIfaceKey,
				peerBlock(savePeerA, savePskA, "10.8.0.2/32"),
				peerBlock(savePeerB, savePskB, "10.8.0.3/32"),
				peerBlock(savePeerC, "", "10.8.0.4/32")))
			out, summary := d.rewrite(t, awk, saved)

			if strings.Contains(out, "PrivateKey") || strings.Contains(out, saveIfaceKey) {
				t.Errorf("the private key is still in the conf:\n%s", out)
			}
			if strings.Contains(out, savePskA) {
				t.Errorf("peer A's pre-shared key is still inline:\n%s", out)
			}
			hookA := "PostUp = wg set %i peer " + savePeerA + " preshared-key " + d.pskFile(savePeerA)
			if !strings.Contains(out, hookA+"\n") {
				t.Errorf("no PostUp loads peer A's key from its file:\n%s", out)
			}
			// The hook sits in [Interface], right under the key line.
			if !strings.Contains(out, d.keyHook()+"\n"+hookA+"\n") {
				t.Errorf("peer A's hook is not right under the key line:\n%s", out)
			}
			// B's file does not hold B's key: B keeps it inline, and gets no hook.
			if !strings.Contains(out, "PresharedKey = "+savePskB) || strings.Contains(out, "peer "+savePeerB) {
				t.Errorf("peer B's key should stay inline, without a hook:\n%s", out)
			}
			for _, keep := range []string{"Address = 10.8.0.1/24", "ListenPort = 51820",
				"PostUp = iptables -I FORWARD -i %i -j ACCEPT", "PostDown = iptables -D FORWARD -i %i -j ACCEPT",
				"PublicKey = " + savePeerC, "AllowedIPs = 10.8.0.4/32"} {
				if !strings.Contains(out, keep+"\n") {
					t.Errorf("the rewrite lost %q:\n%s", keep, out)
				}
			}
			for _, want := range []string{"the private key is loaded from " + d.key(),
				"1 pre-shared key(s) loaded from their files", "1 pre-shared key(s) stay inline"} {
				if !strings.Contains(summary, want) {
					t.Errorf("summary %q lacks %q", summary, want)
				}
			}
			// The summary is counts and paths, never a value.
			for _, secret := range []string{saveIfaceKey, savePskA, savePskB} {
				if strings.Contains(summary, secret) {
					t.Errorf("the summary carries a secret: %q", summary)
				}
			}
		})
	}
}

// TestSaveTwiceIsANoOp: the second save starts from the first one's conf,
// whose PostUp loaded the pre-shared key back into the running interface, and
// must write the very same file: no second PostUp line, no secret back.
func TestSaveTwiceIsANoOp(t *testing.T) {
	for name, awk := range awks(t) {
		t.Run(name, func(t *testing.T) {
			d := newSaveDir(t)
			d.write(t, d.key(), saveIfaceKey+"\n")
			d.write(t, d.pskFile(savePeerA), savePskA+"\n")
			runtime := showconf(saveIfaceKey,
				peerBlock(savePeerA, savePskA, "10.8.0.2/32"),
				peerBlock(savePeerC, "", "10.8.0.4/32"))
			first, _ := d.rewrite(t, awk, wgQuickSave(d.toolConf(), runtime))
			second, _ := d.rewrite(t, awk, wgQuickSave(first, runtime))
			if second != first {
				t.Errorf("a second save changed the conf:\n--- first\n%s--- second\n%s", first, second)
			}
			if n := strings.Count(second, "preshared-key"); n != 1 {
				t.Errorf("%d preshared-key hooks after two saves, want 1:\n%s", n, second)
			}
		})
	}
}

// TestSaveDropsTheHookOfARemovedPeer: a PostUp line for a peer that is gone
// would create it again at the next up (`wg set … peer` adds a missing peer),
// so the save that follows a removal takes the line out.
func TestSaveDropsTheHookOfARemovedPeer(t *testing.T) {
	for name, awk := range awks(t) {
		t.Run(name, func(t *testing.T) {
			d := newSaveDir(t)
			d.write(t, d.key(), saveIfaceKey+"\n")
			d.write(t, d.pskFile(savePeerA), savePskA+"\n")
			first, _ := d.rewrite(t, awk, wgQuickSave(d.toolConf(), showconf(saveIfaceKey,
				peerBlock(savePeerA, savePskA, "10.8.0.2/32"))))
			if !strings.Contains(first, "peer "+savePeerA) {
				t.Fatalf("no hook to begin with:\n%s", first)
			}
			after, _ := d.rewrite(t, awk, wgQuickSave(first, showconf(saveIfaceKey,
				peerBlock(savePeerC, "", "10.8.0.4/32"))))
			if strings.Contains(after, savePeerA) {
				t.Errorf("the removed peer's hook survived the save:\n%s", after)
			}
		})
	}
}

// TestSaveLeavesAHandWrittenConfAlone: a conf without the tool's key line
// keeps its PrivateKey, byte for byte as wg-quick wrote it.
func TestSaveLeavesAHandWrittenConfAlone(t *testing.T) {
	for name, awk := range awks(t) {
		t.Run(name, func(t *testing.T) {
			d := newSaveDir(t)
			// The key file even exists and matches: without the line that
			// loads it, removing the key would leave an interface without one.
			d.write(t, d.key(), saveIfaceKey+"\n")
			hand := "[Interface]\nAddress = 10.8.0.1/24\nPostUp = echo up\n"
			saved := wgQuickSave(hand, showconf(saveIfaceKey, peerBlock(savePeerC, "", "10.8.0.4/32")))
			out, summary := d.rewrite(t, awk, saved)
			if out != saved {
				t.Errorf("a hand-written conf was changed:\n--- saved\n%s--- after\n%s", saved, out)
			}
			if !strings.Contains(summary, "stays inline (a conf not written by tui-wireguard)") {
				t.Errorf("summary = %q", summary)
			}
		})
	}
}

// TestSaveKeepsAKeyItCannotProve: with the tool's key line but a key file
// that is missing or holds another key, removing PrivateKey would bring the
// interface up with the wrong key or none; it stays.
func TestSaveKeepsAKeyItCannotProve(t *testing.T) {
	for name, awk := range awks(t) {
		for _, tc := range []struct {
			name, file, want string
		}{
			{"other key", saveOtherKey + "\n", "holds another key"},
			{"missing file", "", "is missing or empty"},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				d := newSaveDir(t)
				if tc.file != "" {
					d.write(t, d.key(), tc.file)
				}
				saved := wgQuickSave(d.toolConf(), showconf(saveIfaceKey))
				out, summary := d.rewrite(t, awk, saved)
				if !strings.Contains(out, "PrivateKey = "+saveIfaceKey+"\n") {
					t.Errorf("the key was removed without a file to load it from:\n%s", out)
				}
				if !strings.Contains(summary, tc.want) {
					t.Errorf("summary %q lacks %q", summary, tc.want)
				}
			})
		}
	}
}

// TestSaveHooksSurviveWgQuickSave: wg-quick save writes the hooks back
// through a bash substitution in which "&" is the matched text, so a hook
// with one comes back broken. The save's own lines must not have one; a
// public key is base64, which has none.
func TestSaveHooksSurviveWgQuickSave(t *testing.T) {
	for name, awk := range awks(t) {
		t.Run(name, func(t *testing.T) {
			d := newSaveDir(t)
			d.write(t, d.key(), saveIfaceKey+"\n")
			d.write(t, d.pskFile(savePeerA), savePskA+"\n")
			out, _ := d.rewrite(t, awk, wgQuickSave(d.toolConf(), showconf(saveIfaceKey,
				peerBlock(savePeerA, savePskA, "10.8.0.2/32"))))
			for _, l := range strings.Split(out, "\n") {
				if strings.HasPrefix(l, "PostUp") && strings.Contains(l, "&") {
					t.Errorf("a hook carries \"&\": %q", l)
				}
			}
		})
	}
}
