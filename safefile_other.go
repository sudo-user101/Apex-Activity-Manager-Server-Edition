//go:build !linux

package main

// The server runs on Linux (safefile_linux.go). This stand-in keeps the same
// rules by path so the tests also run on a Mac.

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func errLinked(name string) error {
	return errors.New(name + " is a link or not a plain file; Apex won't write through it")
}

func plainDir(dir, sub string, create bool, uid, gid int) (string, error) {
	if sub == "" {
		return dir, nil
	}
	p := filepath.Join(dir, sub)
	fi, err := os.Lstat(p)
	if os.IsNotExist(err) && create {
		if err = os.Mkdir(p, 0o700); err == nil && uid >= 0 {
			os.Lchown(p, uid, gid)
		}
		fi, err = os.Lstat(p)
	}
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", errLinked(sub)
	}
	return p, nil
}

func safeRead(dir, sub, name string, owner int) ([]byte, error) {
	d, err := plainDir(dir, sub, false, -1, -1)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(d, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errLinked(name)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, _ := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || st == nil || st.Nlink != 1 || owner >= 0 && int(st.Uid) != owner && st.Uid != 0 {
		return nil, errLinked(name)
	}
	return io.ReadAll(io.LimitReader(f, 8<<20))
}

func safeReplace(dir, sub, name string, data []byte, mode os.FileMode, uid, gid int) error {
	d, err := plainDir(dir, sub, true, uid, gid)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(d, "."+name+".apex-*")
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode.Perm())
	}
	if err == nil && uid >= 0 {
		err = f.Chown(uid, gid)
	}
	f.Close()
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(d, name))
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}
