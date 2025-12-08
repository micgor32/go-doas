package auth

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"slices"
	"strings"
)

type Entry struct {
	Action   string
	Options  []string
	Identity string
	Target   string
	Cmd      string
	CmdArgs  []string
}

const confpath = "/etc/doas.conf"
const groupspath = "/etc/group"

func CheckConfig(user *user.User) (Entry, error) {
	gids, err := user.GroupIds()
	if err != nil {
		return Entry{}, err
	}

	uname := user.Username

	conf, err := os.Open(confpath)
	if err != nil {
		return Entry{}, err
	}

	fileScanner := bufio.NewScanner(conf)
	fileScanner.Split(bufio.ScanLines)
	var fileLines []string

	for fileScanner.Scan() {
		fileLines = append(fileLines, fileScanner.Text())
	}

	conf.Close()

	var entry Entry
	var found bool

	for _, line := range fileLines {
		temp, tempFound, err := processEntry(line, gids, uname)

		if tempFound {
			entry = temp
			found = tempFound
			break
		}

		if err != nil {
			return Entry{}, err
		}
	}

	if !found {
		return Entry{}, fmt.Errorf("not authorized")
	}

	return entry, nil
}

func fillEntry(tokens []string, entry *Entry, id int) error {
	// TODO: this has to be handled better, cause for now
	// we do not handle persists, nolog and setenv.
	var validOptions = []string{
		"nopass",
		"persist",
		"nolog",
		"keepenv",
		"setenv",
	}

	if len(tokens) == 0 {
		return nil
	}

	if tokens[id] == "permit" || tokens[id] == "deny" {
		entry.Action = tokens[id]
		id++
	} else {
		return fmt.Errorf("invalid entry: missing permit|deny")
	}

	for id < len(tokens) {
		tok := tokens[id]

		if tok == "as" || tok == "cmd" {
			break
		}

		if !slices.Contains(validOptions, tok) {
			break
		}

		entry.Options = append(entry.Options, tok)
		id++
	}

	if id >= len(tokens) {
		return fmt.Errorf("invalid entry: identity missing")
	}
	entry.Identity = tokens[id]
	id++

	if id+1 < len(tokens) && tokens[id] == "as" {
		entry.Target = tokens[id+1]
		id += 2
	}

	if id < len(tokens) && tokens[id] == "cmd" {
		id++
		if id >= len(tokens) {
			return fmt.Errorf("cmd keyword present but no command")
		}

		entry.Cmd = tokens[id]
		id++

		if id < len(tokens) {
			entry.CmdArgs = tokens[id:]
		}
	}

	return nil
}

func processEntry(input string, gids []string, uname string) (Entry, bool, error) {
	line := strings.TrimSpace(input) // just in case config is dirty

	if line == "" || strings.HasPrefix(line, "#") {
		return Entry{}, false, nil
	}

	fields := strings.Fields(line)
	entry := Entry{}
	id := 0

	if err := fillEntry(fields, &entry, id); err != nil {
		return Entry{}, false, err
	}

	if entry.Identity == uname {
		return entry, true, nil
	}

	gMatch, err := matchGroups(entry.Identity, gids)
	if err != nil {
		return Entry{}, false, err
	}

	if gMatch {
		return entry, true, nil
	}

	return Entry{}, false, nil
}

func matchGroups(gname string, gids []string) (bool, error) {
	tgname := gname[1:]
	groups, err := os.Open(groupspath)
	if err != nil {
		return false, err
	}

	fileScanner := bufio.NewScanner(groups)
	fileScanner.Split(bufio.ScanLines)
	var fileLines []string

	for fileScanner.Scan() {
		fileLines = append(fileLines, fileScanner.Text())
	}

	groups.Close()

	for _, line := range fileLines {
		if strings.Contains(line, tgname) {
			parts := strings.Split(line, ":")
			for _, gid := range gids {
				if strings.Contains(parts[2], gid) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}
