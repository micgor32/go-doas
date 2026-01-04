# go-doas: A Go implementation of [OpenDoas](https://github.com/Duncaen/OpenDoas)
[![Go Report Card](https://goreportcard.com/badge/github.com/micgor32/go-doas)](https://goreportcard.com/report/github.com/micgor32/go-doas)


[`doas`](https://en.wikipedia.org/wiki/Doas) is a minimal replacement for the venerable `sudo`. It was
initially [written by Ted Unangst](http://www.tedunangst.com/flak/post/doas)
of the OpenBSD project to provide 95% of the features of `sudo` with a
fraction of the codebase. `go-doas` is a minimal Go implementation of [OpenDoas](https://github.com/Duncaen/OpenDoas) port. 

Authentication is based on [PAM](https://github.com/linux-pam/linux-pam), implemented using [Go PAM wrapper](https://github.com/msteinert/pam) (please note here
that this makes `go-doas` indirectly dependent on [cgo](https://go.dev/wiki/cgo)).

## Installation and Usage
The recommended way to install `go-doas` is to use the provided [`Taskfile`](https://github.com/go-task/task).

Usage:
```bash
doas <options> <command>

Options:
  -L	Clear any persisted authentications from previous invocations, then immediately exit. No command is executed.
  -i	Interactive session (eqv. to sudo -i)
  -u string
    	User as whom the following command should be executed (default "root")
```

## Configuration
`go-doas` is compatible with `doas` configuration. Please see the manpage dedicated to [`doas.conf`](https://man.openbsd.org/doas.conf.5) for more details.

## TODO
- setenv
- interactive session
- integration tests
- docs

## Disclaimer
This port is a hobby project, for the time being there is no clearly defined policy for reacting to potential security issues. Therefore, it should NOT
be seen as comparably secure as OpenDoas or sudo.
