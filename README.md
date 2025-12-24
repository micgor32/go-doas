# go-doas: A Go implementation of [OpenDoas](https://github.com/Duncaen/OpenDoas)
[![Go Report Card](https://goreportcard.com/badge/github.com/micgor32/go-doas)](https://goreportcard.com/report/github.com/micgor32/go-doas)


[`doas`](https://en.wikipedia.org/wiki/Doas) is a minimal replacement for the venerable `sudo`. It was
initially [written by Ted Unangst](http://www.tedunangst.com/flak/post/doas)
of the OpenBSD project to provide 95% of the features of `sudo` with a
fraction of the codebase. `go-doas` is a minimal Go implementation of [OpenDoas](https://github.com/Duncaen/OpenDoas) port. 

## Installation and Usage
The recommended way to install `go-doas` is to use the provided [`Taskfile`](https://github.com/go-task/task).

Usage:
```bash
doas <options> <command>

Options:
  -i	Interactive session (eqv. to sudo -i)
  -u string
    	User as whom the following command should be executed (default "root")
```

## Configuration
`go-doas` is mostly compatible with [`doas.conf`](https://man.openbsd.org/doas.conf.5) format, with one exception:
in `doas` the last matching rule determines the action taken. In `go-doas` the first matching rule determines the action taken.
If no rule matches, same as in `doas`, the action is denied.

## TODO
- Timestamps
- setenv
- interactive session

## Disclaimer
This port is a hobby project, for the time being there is no clearly defined policy for reacting to potential security issues. Therefore, it should NOT
be seen as comparably secure as OpenDoas or sudo.
