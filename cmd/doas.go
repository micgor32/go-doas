package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"slices"

	"go-doas/pkg/auth"
)

var (
	usr      = flag.String("u", "root", "User as whom the following command should be executed")
	itc      = flag.Bool("i", false, "Interactive session (eqv. to sudo -i)")
	safePath = []string{
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
	}
)

func run(path []string, cmdPath string, args []string, targetUser *user.User) error {
	if err := auth.SetEnv(path, *targetUser); err != nil {
		return err
	}

	rn := exec.Command(cmdPath, args...)
	rn.Stdout = os.Stdout
	rn.Stderr = os.Stderr
	if err := rn.Run(); err != nil {
		return err
	}

	return nil
}

func main() {
	flag.Parse()
	currentUser, err := user.Current()
	if err != nil {
		os.Exit(1)
	}

	targetUser, err := user.Lookup(*usr)
	if err != nil {
		os.Exit(1)
	}

	cmdArgs := flag.Args()
	if len(cmdArgs) < 1 {
		flag.PrintDefaults()
		os.Exit(1)
	}
	cmd := cmdArgs[0]
	args := cmdArgs[1:]
	// let's not leave path empty
	path := safePath

	conf, err := auth.CheckConfig(currentUser)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	if conf.Action == "deny" {
		fmt.Print("not authorized(deny)\n")
		os.Exit(1)
	}

	cmdPath, err := exec.LookPath(cmd)

	// after manpage: "The command the user is allowed or denied to run.
	// The default is all commands."
	if cmdPath != conf.Cmd && conf.Cmd != "" {
		fmt.Printf("%s, %s\n", cmdPath, conf.Cmd)
		fmt.Print("not authorized (cmd)\n")
		os.Exit(1)
	}

	// options
	nopass := slices.Contains(conf.Options, "nopass")
	keepenv := slices.Contains(conf.Options, "keepenv")
	if keepenv {
		path = os.Environ()
	}

	if !nopass {
		transaction := auth.PamAuth(currentUser.Username)

		if err := transaction.AcctMgmt(0); err != nil {
			os.Exit(1)
		}

		if err := transaction.OpenSession(0); err != nil {
			os.Exit(1)
		}

		if err := run(path, cmdPath, args, targetUser); err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}

		if err != transaction.CloseSession(0) {
			panic(err)
		}
	} else {
		if err := run(path, cmdPath, args, targetUser); err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
	}

	os.Exit(0)
}
