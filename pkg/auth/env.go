package auth

// #include <sys/types.h>
// #include <grp.h>
// #include <stdlib.h>
import "C"

import (
	"fmt"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

func SetEnv(spath []string, targetUser user.User) error {
	tgid, err := strconv.Atoi(targetUser.Gid)
	if err != nil {
		return err
	}

	tname := targetUser.Name
	uid, err := strconv.Atoi(targetUser.Uid)
	if err != nil {
		return err
	}

	if err := syscall.Setresgid(tgid, tgid, tgid); err != nil {
		return err
	}

	if err := initGroup(tname, tgid); err != nil {
		return err
	}

	if err := syscall.Setresuid(uid, uid, uid); err != nil {
		return err
	}

	if err := syscall.Setenv("PATH", strings.Join(spath, ":")); err != nil {
		return err
	}

	return nil
}

func initGroup(uname string, gid int) error {
	cname := C.CString(uname)
	defer C.free(unsafe.Pointer(cname))

	cgid := C.gid_t(gid)

	if err := C.initgroups(cname, cgid); err != 0 {
		return fmt.Errorf("%v", err)
	}

	return nil
}
