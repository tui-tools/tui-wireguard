package wireguard

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
)

// This file is `w`, the save of a running interface into its conf (issue
// #32).
//
// `wg-quick save` rewrites the conf from `wg showconf`, which prints the
// private key and every pre-shared key. It keeps the [Interface] hooks of the
// file it replaces, so the PostUp line that loads the key from its root-only
// file survives, but the file now also inlines the key itself: a save quietly
// undid the promise InterfaceConf makes, that the conf carries no secret.
//
// So the save is one root shell that runs `wg-quick save` and then, in the
// same step, takes the secrets back out with the awk program below. Both are
// on the command line the confirm dialog shows, the program included: nothing
// of it travels on stdin. The program removes a secret only when the conf
// already has another way to load the very same value:
//
//   - PrivateKey goes when the conf carries the tool's own key line,
//     `PostUp = wg set %i private-key /etc/wireguard/<if>.key`, and that file
//     holds the same key. A conf written by hand keeps wg-quick's behaviour:
//     the key stays inline, in the root-only file wg-quick wrote.
//   - Each PresharedKey goes when the file `a … psk` generated for that peer
//     (PSKPath) holds the same key. It is replaced by a PostUp line that
//     loads the key from that file at up time. Those lines are the tool's:
//     every save drops them and writes one per peer that still has its key in
//     a file, so a save repeated is a no-op and a removed peer leaves no line
//     behind (`wg set … peer` on a missing peer would create it again). Any
//     other pre-shared key stays inline.
//
// The values are compared inside awk, which reads them from the files; none
// is ever an argument, and the program prints nothing but counts, to stderr,
// which is the line the status bar shows.

// saveScriptName is $0 of the save shell: what `ps` shows for it.
const saveScriptName = "tui-wireguard-save"

// saveRewriteAwk is the program that takes the secrets back out of a conf
// `wg-quick save` just wrote. It reads the conf whole, because the PostUp
// lines it writes go in [Interface], above the peers they are about.
//
// Variables (-v): key is the interface's key file, pskprefix the path every
// pre-shared key file of the interface starts with (PSKPath), conf the conf's
// path, for the summary. POSIX awk only: Ubuntu's awk is mawk, Fedora's gawk.
const saveRewriteAwk = `function value(s) { sub(/^[^=]*=[ \t]*/, "", s); sub(/[ \t\r]+$/, "", s); return s }
function firstline(path,   v) { v = ""; if ((getline v < path) <= 0) v = ""; close(path); return v }
function pskfile(pub,   p) { p = pub; gsub(/[^A-Za-z0-9]/, "", p); return pskprefix substr(p, 1, 8) ".psk" }
function ownhook(l) {
  return index(l, "PostUp = wg set %i peer ") == 1 && index(l, " preshared-key " pskprefix) > 0 &&
    substr(l, length(l) - 3) == ".psk"
}
{ n++; line[n] = $0 }
END {
  keyhook = "PostUp = wg set %i private-key " key
  managed = 0
  for (i = 1; i <= n; i++) if (line[i] == keyhook) managed = 1
  filekey = ""
  if (managed) filekey = firstline(key)
  sect = ""; peers = 0
  for (i = 1; i <= n; i++) {
    l = line[i]
    if (l ~ /^[ \t]*\[/) { sect = l; if (l ~ /^[ \t]*\[Peer\]/) { peers++; pub[peers] = ""; pskat[peers] = 0 }; continue }
    if (peers == 0 || sect !~ /^[ \t]*\[Peer\]/) continue
    if (l ~ /^PublicKey[ \t]*=/) pub[peers] = value(l)
    if (l ~ /^PresharedKey[ \t]*=/) { pskat[peers] = i; psk[peers] = value(l) }
  }
  hooks = ""; byfile = 0; inline = 0
  for (p = 1; p <= peers; p++) {
    if (!pskat[p]) continue
    f = pskfile(pub[p])
    if (pub[p] != "" && psk[p] != "" && firstline(f) == psk[p]) {
      drop[pskat[p]] = 1; byfile++
      hooks = hooks "PostUp = wg set %i peer " pub[p] " preshared-key " f "\n"
    } else inline++
  }
  sect = ""; placed = 0; keyout = 0; keyin = 0
  for (i = 1; i <= n; i++) {
    l = line[i]
    if (l ~ /^[ \t]*\[/) {
      if (sect ~ /^[ \t]*\[Interface\]/ && !placed) { printf "%s", hooks; placed = 1 }
      sect = l; print l; continue
    }
    if (drop[i]) continue
    if (sect ~ /^[ \t]*\[Interface\]/) {
      if (ownhook(l)) continue
      if (l ~ /^PrivateKey[ \t]*=/) {
        if (managed && filekey != "" && value(l) == filekey) { keyout = 1; continue }
        keyin = 1
      }
      print l
      if (l == keyhook && !placed) { printf "%s", hooks; placed = 1 }
      continue
    }
    print l
  }
  if (!placed) printf "%s", hooks
  msg = conf " saved:"
  if (keyout) msg = msg " the private key is loaded from " key
  else if (keyin && managed && filekey == "") msg = msg " the private key stays inline (" key " is missing or empty)"
  else if (keyin && managed) msg = msg " the private key stays inline (" key " holds another key)"
  else if (keyin) msg = msg " the private key stays inline (a conf not written by tui-wireguard)"
  else msg = msg " no private key in the file"
  if (byfile) msg = msg ", " byfile " pre-shared key(s) loaded from their files"
  if (inline) msg = msg ", " inline " pre-shared key(s) stay inline (no matching file)"
  print msg > "/dev/stderr"
}
`

// BuildSaveConfig assembles the save of a running interface into its conf:
// `wg-quick save <iface>`, which persists the runtime peers but rewrites the
// file wholesale (so it is marked destructive), followed in the same root
// shell by saveRewriteAwk, which takes the private key and the pre-shared
// keys back out wherever the conf can load them from their files. The new
// file is written next to the conf with umask 077 and moved over it, the way
// wg-quick writes its own.
func BuildSaveConfig(iface string) (runner.Command, error) {
	if !ValidInterface(iface) {
		return runner.Command{}, fmt.Errorf("not a valid interface name: %q", iface)
	}
	conf := ConfPath(iface)
	tmp := conf + ".tui-save"
	script := strings.Join([]string{
		"set -e",
		"wg-quick save " + iface,
		"umask 077",
		"awk -v key=" + KeyPath(iface) + " -v pskprefix=" + pskPrefix(iface) + " -v conf=" + conf +
			` "$1" ` + conf + " > " + tmp + " || { rm -f " + tmp + "; exit 1; }",
		"mv " + tmp + " " + conf,
	}, "\n")
	return runner.Command{
		Argv:        []string{"sh", "-c", script, saveScriptName, saveRewriteAwk},
		Description: "Save " + iface + " runtime config to " + conf,
		Destructive: true,
	}, nil
}

// savePattern finds the interface a save shell saves.
var savePattern = regexp.MustCompile(`(?m)^wg-quick save ([A-Za-z0-9_.-]+)$`)

// SavedInterface reports the interface a BuildSaveConfig command saves. The
// UI uses it to put the save's own summary on the status line: wg-quick save
// prints "[#] wg showconf <if>" first, and the summary is the last line.
func SavedInterface(cmd runner.Command) (string, bool) {
	argv := cmd.Argv
	if len(argv) != 5 || argv[0] != "sh" || argv[1] != "-c" || argv[3] != saveScriptName {
		return "", false
	}
	m := savePattern.FindStringSubmatch(argv[2])
	if m == nil {
		return "", false
	}
	return m[1], true
}

// pskPrefix is the path every pre-shared key file of an interface starts
// with: PSKPath without the slice of the peer's key.
func pskPrefix(iface string) string { return ConfDir + "/" + iface + "-" }
