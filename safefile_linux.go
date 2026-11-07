//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"
)

// Root writing into a folder another user owns: every step is relative to an
// open folder, a link in the user's part of the path is refused, and the new
// file is created exclusively and handed over by descriptor. A user can't plant
// a link that makes root write or chown a file of their choosing.

const dirFlags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_CLOEXEC

func errLinked(name string) error {
	return errors.New(name + " is a link or not a plain file; Apex won't write through it")
}

// openIn opens dir, then sub inside it (no links), creating sub if asked.
func openIn(dir, sub string, create bool, uid, gid int) (int, error) {
	dfd, err := syscall.Open(dir, dirFlags, 0)
	if err != nil || sub == "" {
		return dfd, err
	}
	defer syscall.Close(dfd)
	fd, err := syscall.Openat(dfd, sub, dirFlags|syscall.O_NOFOLLOW, 0)
	if err == syscall.ENOENT && create {
		if err = syscall.Mkdirat(dfd, sub, 0o700); err != nil && err != syscall.EEXIST {
			return -1, err
		}
		if fd, err = syscall.Openat(dfd, sub, dirFlags|syscall.O_NOFOLLOW, 0); err == nil && uid >= 0 {
			syscall.Fchown(fd, uid, gid)
		}
	}
	if err == syscall.ELOOP || err == syscall.ENOTDIR {
		return -1, errLinked(sub)
	}
	return fd, err
}

// safeRead reads dir/sub/name. owner >= 0: the file must belong to that user
// (or root) and have one name, so a hard link to someone else's file isn't read.
func safeRead(dir, sub, name string, owner int) ([]byte, error) {
	dfd, err := openIn(dir, sub, false, -1, -1)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dfd)
	fd, err := syscall.Openat(dfd, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err == syscall.ELOOP {
		return nil, errLinked(name)
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if err := plainFile(f, name, owner); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(f, 8<<20))
}

func plainFile(f *os.File, name string, owner int) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	st, _ := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || st == nil || st.Nlink != 1 || owner >= 0 && int(st.Uid) != owner && st.Uid != 0 {
		return errLinked(name)
	}
	return nil
}

// safeReplace writes dir/sub/name in one step (a new file beside it, renamed
// over it), with mode and owner set on the new file itself.
func safeReplace(dir, sub, name string, data []byte, mode os.FileMode, uid, gid int) error {
	dfd, err := openIn(dir, sub, true, uid, gid)
	if err != nil {
		return err
	}
	defer syscall.Close(dfd)
	r := make([]byte, 6)
	rand.Read(r)
	tmp := "." + name + ".apex-" + hex.EncodeToString(r)
	fd, err := syscall.Openat(dfd, tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode.Perm())
	}
	if err == nil && uid >= 0 {
		err = f.Chown(uid, gid)
	}
	if err == nil {
		err = f.Sync()
	}
	f.Close()
	if err == nil {
		err = syscall.Renameat(dfd, tmp, dfd, name)
	}
	if err != nil {
		syscall.Unlinkat(dfd, tmp)
	}
	return err
}
