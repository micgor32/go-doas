package auth

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	// "time"

	"golang.org/x/sys/unix"
	// "strings"
	// "time"
)

const (
	TIMESTAMP_DIR string = "/run/doas"
)

func ProcInfo(pid int, ttyNo *int, startTime *uint64) error {
	const bufSize = 1024
	buf := make([]byte, bufSize)
	path := fmt.Sprintf("/proc/%d/stat", pid)
	if _, err := os.Stat(path); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_RDONLY, 0444)
	if err != nil {
		return err
	}
	defer f.Close()

	p := 0
	var tmp int

	for {
		tmp, err = f.Read(buf)
		if tmp > 0 {
			p += tmp
			if p >= bufSize-1 {
				break
			}
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		if tmp == 0 {
			break
		}
	}

	if tmp != 0 || bytes.IndexByte(buf[:p], 0) != -1 {
		return fmt.Errorf("NUL in: %s", path)
	}

	fld := bytes.IndexAny(buf[:p], ")")
	if fld == -1 {
		return fmt.Errorf("-1")
	}

	t := bytes.Fields(buf[fld+1 : p])

	// prints for debug only
	fmt.Println(string(buf[:p]))
	fmt.Println(string(t[4]))  // this is ttyno
	fmt.Println(string(t[19])) // this should be starttime
	// this should be handled cleaner, i.e. directly converting
	// byte field elem to int
	*ttyNo, err = strconv.Atoi(string(t[4]))
	if err != nil {
		return nil
	}

	// same here
	*startTime, err = strconv.ParseUint(string(t[19]), 10, 64)

	return nil
}

func timestampPath(path *os.File) error {
	var (
		ttynr     int
		starttime uint64
	)
	ppid := os.Getppid()
	sid, err := unix.Getsid(0)
	if err != nil {
		return err
	}

	if err := ProcInfo(ppid, &ttynr, &starttime); err != nil {
		return err
	}

	if _, err = os.Stat(TIMESTAMP_DIR); err != nil {
		// could be handled better, for now let's just assume
		// that only error that can happen will be path not found
		os.Mkdir(TIMESTAMP_DIR, 0711)
	}

	path, err = os.Create(fmt.Sprintf("%s/%d-%d-%d-%d-%d", TIMESTAMP_DIR, ppid, sid, ttynr, starttime, os.Getuid()))

	return nil
}

// helper based on time.h from OpenBSD
func timespecAdd(t, u *unix.Timespec) {
	t.Sec += u.Sec
	t.Nsec += u.Nsec
	if t.Nsec >= 1_000_000_000 {
		t.Sec++
		t.Nsec -= 1_000_000_000
	}
}

// for the time being this is basically a "translation" of OpenDoas C code.
// Fine for now, but I would like it to be handled cleaner in proper Go way.
func timestampSet(path string, secs int64) error {
	var ts [2]unix.Timespec

	timeout := unix.Timespec{
		Sec:  secs,
		Nsec: 0,
	}

	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts[0]); err != nil {
		return err
	}

	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &ts[1]); err != nil {
		return err
	}

	tv := [2]syscall.Timespec{
		syscall.NsecToTimespec(ts[0].Sec*1_000_000_000 + int64(ts[0].Nsec)),
		syscall.NsecToTimespec(ts[1].Sec*1_000_000_000 + int64(ts[1].Nsec)),
	}

	timespecAdd(&ts[0], &timeout)
	timespecAdd(&ts[1], &timeout)

	return syscall.UtimesNano(path, tv[:])
}

func timestampOpen(valid *int, secs int) error {

	return nil
}
