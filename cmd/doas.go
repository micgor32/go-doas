package main

import (
	"flag"
	"os"
	"os/user"

	"go-doas/pkg/auth"
)

var (
	usr = flag.String("u", "", "User as whom the following command should be executed")
	itc = flag.Bool("i", false, "Interactive session (eqv. to sudo -i)")
)

func main() {
	flag.Parse()
	currentUser, err := user.Current()
	if err != nil {
		os.Exit(1)
	}

	if err := auth.CheckConfig(currentUser); err != nil {
		os.Exit(1)
	}

	auth.PamAuth(currentUser.Username)
}
