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

	"golang.org/x/sys/unix"
)

const (
	TIMESTAMP_DIR string = "/run/doas"
)

func ProcInfo(pid int) (int, uint64, error) {
	const bufSize = 1024
	buf := make([]byte, bufSize)
	path := fmt.Sprintf("/proc/%d/stat", pid)
	if _, err := os.Stat(path); err != nil {
		return 0, 0, err
	}

	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0444)
	if err != nil {
		return 0, 0, err
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
			return 0, 0, err
		}

		if tmp == 0 {
			break
		}
	}

	if tmp != 0 || bytes.IndexByte(buf[:p], 0) != -1 {
		return 0, 0, fmt.Errorf("NUL in: %s", path)
	}

	fld := bytes.IndexAny(buf[:p], ")")
	if fld == -1 {
		return 0, 0, fmt.Errorf("-1")
	}

	t := bytes.Fields(buf[fld+1 : p])

	// this should be handled cleaner, i.e. directly converting
	// byte field elem to int
	ttyNo, err := strconv.Atoi(string(t[4]))
	if err != nil {
		return 0, 0, err
	}

	// same here
	startTime, err := strconv.ParseUint(string(t[19]), 10, 64)
	if err != nil {
		return 0, 0, err
	}

	return ttyNo, startTime, nil
}

func timestampPath(file **os.File, path *string) error {
	var (
		fd *os.File
	)
	ppid := os.Getppid()
	sid, err := unix.Getsid(0)
	if err != nil {
		return err
	}

	ttynr, starttime, err := ProcInfo(ppid)
	if err != nil {
		return err
	}

	p := fmt.Sprintf("%s/%d-%d-%d-%d-%d", TIMESTAMP_DIR, ppid, sid, ttynr, starttime, os.Getuid())

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
	// 0411 is based on perms from OpenDoas. Reminder to verify correctness
	// here as well.
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0411)
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

	if st.Uid != 0 ||
		st.Gid != uint32(os.Getgid()) ||
		(st.Mode&syscall.S_IFMT) != syscall.S_IFREG || (st.Mode&0777) != 0 {
		if err := timestampClear(path, *f); err != nil {
			return 0, err
		}
		return 0, nil //fmt.Errorf("timestamp uid, gid or mode wrong") to be considered, we could fail "loudly" here as well
	}

	if !timespecIsSet(st.Atim) || !timespecIsSet(st.Mtim) {
		return 0, nil
	}

	var now [2]unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now[0]); err != nil {
		if err = timestampClear(path, *f); err != nil {
			return 0, err
		}
		return 0, nil
	}
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &now[1]); err != nil {
		if err = timestampClear(path, *f); err != nil {
			return 0, err
		}
		return 0, nil
	}

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
		err = timestampClear(path, *f)
		if err != nil {
			return 0, err
		}
		return 0, nil
	}

	return 1, nil
}

func timestampClear(path string, f os.File) error {
	// Originally OpenDoas uses unlink(2) syscall.
	// While we could just do the same here (which was
	// my original thought), os.Remove does exactly
	// that under the hood (see https://cs.opensource.google/go/go/+/go1.25.5:src/os/file_unix.go;l=356).
	// Use of standard library is obviously better idea than
	// raw syscalls, mainly cause I strongly believe that
	// people who wrote Go are smarter than me :D
	if err := os.Remove(path); err != nil {
		return err
	}

	f.Close()

	return nil
}

func TimestampOpen(secs int64) (int, error) {
	var path string
	var fd *os.File

	if _, err := os.Stat(TIMESTAMP_DIR); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			os.Mkdir(TIMESTAMP_DIR, 0711)
		} else {
			return 0, err
		}
	}

	err := timestampPath(&fd, &path)
	if err != nil {
		return 0, err
	}

	if fd == nil {
		return 0, nil
	}
	defer fd.Close()

	v, err := timestampCheck(path, secs)
	if err != nil {
		return 0, err
	}

	return v, nil
}

func TimestampSetAfterAuth(secs int64) error {
	var path string
	var f *os.File

	err := timestampPath(&f, &path)
	if err != nil {
		return err
	}

	if f == nil {
		// Rationale behind using os.OpenFile instead of NewFile is simple:
		// these are doing exaclty the same (given O_CREATE is passed for OpenFile),
		// but NewFile does not let us pass permissions for the new file.
		f, err = os.OpenFile(path, os.O_CREATE|os.O_TRUNC|unix.O_NOFOLLOW, 0000)
		if err != nil {
			return err
		}
	}
	defer f.Close()

	return TimestampSet(path, secs)
}
