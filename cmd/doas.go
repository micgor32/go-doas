package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"syscall"

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

	conf, err := auth.CheckConfig(currentUser)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	// TODO: add permit func that handles the logics of
	// permissions based on the config file
	fmt.Printf("%s\n", conf.Target)

	transaction := auth.PamAuth(currentUser.Username)

	if err := transaction.AcctMgmt(0); err != nil {
		os.Exit(1)
	}

	if err := transaction.OpenSession(0); err != nil {
		os.Exit(1)
	}

	if err := auth.SetEnv(safePath, *targetUser); err != nil {
		os.Exit(1)
	}

	cmdPath, err := exec.LookPath(cmd)

	rn := exec.Command(cmdPath, args...)
	rn.Stdout = os.Stdout
	rn.Stderr = os.Stderr
	if err := rn.Run(); err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	// TODO: remove, for debug purposes only
	fmt.Printf("%v\n", syscall.Geteuid())

	if err != transaction.CloseSession(0) {
		panic(err)
	}

	os.Exit(0)
}
