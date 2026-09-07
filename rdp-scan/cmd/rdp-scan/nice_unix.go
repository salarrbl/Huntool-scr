//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris || aix

package main

import (
	"syscall"
)

// prioProcess is the "adjust this process" selector of setpriority(2) —
// PRIO_PROCESS, which is 0 on every Unix we target. syscall does not export the
// name, only the call, so the constant is spelled out here.
const prioProcess = 0

// setNiceness lowers the CPU scheduling priority of the scanning process so a
// long sweep in the background does not fight the laptop's foreground work
// (editor, browser, video call). Lowering our own priority needs no privileges;
// only raising it does.
func setNiceness(level int) error {
	if level <= 0 {
		return nil
	}
	return syscall.Setpriority(prioProcess, 0, level)
}
