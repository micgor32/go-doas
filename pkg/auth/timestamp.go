package auth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"syscall"

	// "time"

	"golang.org/x/sys/unix"
	// "strings"
	//"time"
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
	// fmt.Println(string(buf[:p]))
	// fmt.Println(string(t[4]))  // this is ttyno
	// fmt.Println(string(t[19])) // this should be starttime
	// this should be handled cleaner, i.e. directly converting
	// byte field elem to int
	*ttyNo, err = strconv.Atoi(string(t[4]))
	if err != nil {
		return err
	}

	// same here
	*startTime, err = strconv.ParseUint(string(t[19]), 10, 64)
	if err != nil {
		return err
	}

	return nil
}

func timestampPath(file **os.File, path *string) error {
	var (
		ttynr     int
		starttime uint64
		fd        *os.File
	)
	ppid := os.Getppid()
	sid, err := unix.Getsid(0)
	if err != nil {
		return err
	}

	if err := ProcInfo(ppid, &ttynr, &starttime); err != nil {
		return err
	}

	p := fmt.Sprintf("%s/%d-%d-%d-%d-%d", TIMESTAMP_DIR, ppid, sid, ttynr, starttime, os.Getuid())

	// if _, err := os.Stat(p); err != nil {
	// 	// TODO: add distinction for the patricular err (non existent file)
	// 	fd, err = os.Create(p)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	if err = TimestampSet(p, secs); err != nil {
	// 		return err
	// 	}
	// 	// prob we could set pointers here and return already,
	// 	// doing it later is redundand (i think for now)
	// }

	fd, err = os.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			*file = nil
			*path = p
			return nil
		}
		return err
	}

	*file = fd
	*path = p

	return nil
}

// helpers based on time.h from OpenBSD
func timespecAdd(t, u *unix.Timespec) {
	t.Sec += u.Sec
	t.Nsec += u.Nsec
	if t.Nsec >= 1_000_000_000 {
		t.Sec++
		t.Nsec -= 1_000_000_000
	}
}

func timespecIsSet(ts syscall.Timespec) bool {
	return ts.Sec != 0 || ts.Nsec != 0
}

func timespecLess(a, b syscall.Timespec) bool {
	if a.Sec != b.Sec {
		return a.Sec < b.Sec
	}
	return a.Nsec < b.Nsec
}

func timespecGreater(a, b syscall.Timespec) bool {
	if a.Sec != b.Sec {
		return a.Sec > b.Sec
	}
	return a.Nsec > b.Nsec
}

// for the time being this is basically a "translation" of OpenDoas C code.
// Fine for now, but I would like it to be handled cleaner in proper Go way.
func TimestampSet(path string, secs int64) error {
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

	timespecAdd(&ts[0], &timeout)
	timespecAdd(&ts[1], &timeout)

	tv := [2]syscall.Timespec{
		{Sec: ts[0].Sec, Nsec: ts[0].Nsec},
		{Sec: ts[1].Sec, Nsec: ts[1].Nsec},
	}

	return syscall.UtimesNano(path, tv[:])
}

// similrly as with timestampSet, this is a "translation". We could limit the amount
// of syscalls and use more of Go unix package, specifically statx_t and its timestamp
func timestampCheck(path string, secs int64) (int, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0411)
	if err != nil {
		return 0, err
	}
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}

	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("not a syscall.Stat_t")
	}

	// if st.Uid != 0 ||
	// 	st.Gid != uint32(os.Getgid()) ||
	// 	(st.Mode&syscall.S_IFMT) != syscall.S_IFREG ||
	// 	(st.Mode&0777) != 0 {
	// 	return 0, fmt.Errorf("timestamp uid, gid or mode wrong")
	// }

	if !timespecIsSet(st.Atim) || !timespecIsSet(st.Mtim) {
		return 0, nil
	}

	var now [2]unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now[0]); err != nil {
		if err = timestampClear(); err != nil {
			return 0, err
		}
		return 0, nil
	}
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &now[1]); err != nil {
		if err = timestampClear(); err != nil {
			return 0, err
		}
		return 0, nil
	}

	// tsBoot := syscall.Timespec{Sec: now[0].Sec, Nsec: now[0].Nsec}
	// tsReal := syscall.Timespec{Sec: now[1].Sec, Nsec: now[1].Nsec}

	// if timespecLess(st.Atim, tsBoot) ||
	// 	timespecLess(st.Mtim, tsReal) {
	// 	if err = timestampClear(); err != nil {
	// 		return 0, err
	// 	}

	// 	return 0, nil
	// }

	// timeout := unix.Timespec{Sec: secs, Nsec: 0}
	// timespecAdd(&now[0], &timeout)
	// timespecAdd(&now[1], &timeout)

	// if timespecGreater(st.Atim, tsBoot) ||
	// 	timespecGreater(st.Mtim, tsReal) {
	// 	if err = timestampClear(); err != nil {
	// 		return 0, err
	// 	}

	// 	return 0, nil
	// }
	//
	// lower bound: now
	lowerBoot := syscall.Timespec{Sec: now[0].Sec, Nsec: now[0].Nsec}
	lowerReal := syscall.Timespec{Sec: now[1].Sec, Nsec: now[1].Nsec}

	// upper bound: now + timeout
	timeout := unix.Timespec{Sec: secs, Nsec: 0}
	timespecAdd(&now[0], &timeout)
	timespecAdd(&now[1], &timeout)

	upperBoot := syscall.Timespec{Sec: now[0].Sec, Nsec: now[0].Nsec}
	upperReal := syscall.Timespec{Sec: now[1].Sec, Nsec: now[1].Nsec}

	// must satisfy: lower <= timestamp <= upper
	if timespecLess(st.Atim, lowerBoot) ||
		timespecLess(st.Mtim, lowerReal) ||
		timespecGreater(st.Atim, upperBoot) ||
		timespecGreater(st.Mtim, upperReal) {
		_ = timestampClear()
		return 0, nil
	}

	return 1, nil

	return 1, nil
}

func timestampClear() error {
	var path string
	var f *os.File

	if err := timestampPath(&f, &path); err != nil {
		return err
	}

	if err := syscall.Unlink(path); err != nil {
		return err
	}

	f.Close()

	return nil
}

func TimestampOpen(valid *int, secs int64) error {
	var path string
	var fd *os.File
	//var ts [2]unix.Timespec
	*valid = 0

	if _, err := os.Stat(TIMESTAMP_DIR); err != nil {
		// could be handled better, for now let's just assume
		// that only error that can happen will be path not found
		os.Mkdir(TIMESTAMP_DIR, 0711)
	}

	err := timestampPath(&fd, &path)
	if err != nil {
		return err
	}

	// monkeypatch, reminder to check if we can remove
	if fd == nil {
		return nil
	}
	defer fd.Close()

	v, err := timestampCheck(path, secs)
	if err != nil {
		return err
	}

	*valid = v
	// for now let's skip the case when file does not exists here, and let
	// timestampPath handle everything
	return nil
}

func TimestampSetAfterAuth(secs int64) error {
	var path string
	var f *os.File

	if err := timestampPath(&f, &path); err != nil {
		return err
	}

	if f == nil {
		var err error
		f, err = os.Create(path)
		if err != nil {
			return err
		}
	}
	defer f.Close()

	return TimestampSet(path, secs)
}
