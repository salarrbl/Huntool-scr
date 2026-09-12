package main

import (
	"fmt"
	"runtime/debug"

	"syscall/js"
)

var globalPanicHandlerRegistered = false

// registerGlobalPanicHandler sets up a js.Global().Set('onerror') global panic handler.
// This is ONLY called from web environments; do NOT call from CLI.
func registerGlobalPanicHandler() error {
	if globalPanicHandlerRegistered {
		return nil
	}

	// Skip this in non-web environments (we are CLI)
	return fmt.Errorf("runtime is not a web environment")
}

// handlePanicForWeb is a thin wrapper for debugging: prints panic info.
func handlePanicForWeb() {
	if r := recover(); r != nil {
		// This prevents the panic from bubbling to the global handler.
		// For CLI, we let the panic break the process entirely.
		fmt.Printf("[PANIC CAUGHT] %v\n", r)
		debug.PrintStack()
	}
}