package main

import (
	"flag"
	"fmt"
	"os"
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

	args := flag.Args()
	if len(args) < 1 {
		flag.PrintDefaults()
		os.Exit(1)
	}
	cmd := args[0]
	fmt.Printf("%s, %v\n", cmd, safePath)

	if err := auth.CheckConfig(currentUser); err != nil {
		os.Exit(1)
	}

	// TODO: add also permit func

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

	if err := syscall.Exec(cmd, args, safePath); err != nil {
		fmt.Println("command failed:", err)
	}

	if err != transaction.CloseSession(0) {
		panic("shiet")
	}
	fmt.Printf("%v", syscall.Geteuid())
	os.Exit(0)
}
