//go:build !linux

package main

import (
	"errors"
	"os"
	"syscall"
)

func openPTY() (*os.File, *os.File, error) { return nil, nil, errors.New("the terminal needs Linux") }
func setWinSize(*os.File, int, int)        {}
func termSupported() bool                  { return false }
func ttyAttrs() *syscall.SysProcAttr       { return nil }
