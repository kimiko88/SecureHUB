package fusemount

import (
	"bytes"
	"io"
	"sync"

	"secureusb/internal/vault"

	"github.com/winfsp/cgofuse/fuse"
)

type openHandle struct {
	path   string
	seeker *vault.VaultReadSeeker
	buf    []byte
	dirty  bool
}

// VaultFuseFS adatta SecureVault all'interfaccia cgofuse (FUSE su Linux/macOS e WinFsp su Windows).
type VaultFuseFS struct {
	fuse.FileSystemBase
	vault   *vault.SecureVault
	mu      sync.Mutex
	nextFH  uint64
	handles map[uint64]*openHandle
}

func NewVaultFuseFS(v *vault.SecureVault) *VaultFuseFS {
	return &VaultFuseFS{
		vault:   v,
		nextFH:  1,
		handles: make(map[uint64]*openHandle),
	}
}

// MountDynamic monta il Vault su mountPoint (es. "Z:" su Windows o "/mnt/secureusb" su Linux/macOS)
// restituendo una funzione per smontare il disco virtuale.
func MountDynamic(v *vault.SecureVault, mountPoint string) (unmount func(), err error) {
	fs := NewVaultFuseFS(v)
	host := fuse.NewFileSystemHost(fs)
	host.SetCapReaddirPlus(true)

	go func() {
		_ = host.Mount(mountPoint, []string{"-o", "volname=SecureUSB"})
	}()

	return func() {
		host.Unmount()
	}, nil
}

func (f *VaultFuseFS) Getattr(path string, stat *fuse.Stat_t, fh uint64) int {
	entry, ok := f.vault.Stat(path)
	if !ok {
		return -fuse.ENOENT
	}

	ts := fuse.NewTimespec(entry.UpdatedAt)
	stat.Atim = ts
	stat.Mtim = ts
	stat.Ctim = ts

	if entry.IsDir {
		stat.Mode = fuse.S_IFDIR | 0755
		stat.Nlink = 2
	} else {
		stat.Mode = fuse.S_IFREG | 0644
		stat.Nlink = 1
		stat.Size = entry.OriginalSize
	}
	return 0
}

func (f *VaultFuseFS) Readdir(path string, fill func(name string, stat *fuse.Stat_t, ofst int64) bool, ofst int64, fh uint64) int {
	fill(".", nil, 0)
	fill("..", nil, 0)

	children := f.vault.ListDir(path)
	for _, c := range children {
		var st fuse.Stat_t
		if c.IsDir {
			st.Mode = fuse.S_IFDIR | 0755
		} else {
			st.Mode = fuse.S_IFREG | 0644
			st.Size = c.OriginalSize
		}
		name := c.VirtualPath
		for i := len(name) - 1; i >= 0; i-- {
			if name[i] == '/' {
				name = name[i+1:]
				break
			}
		}
		if !fill(name, &st, 0) {
			break
		}
	}
	return 0
}

func (f *VaultFuseFS) Mkdir(path string, mode uint32) int {
	if err := f.vault.CreateDir(path); err != nil {
		return -fuse.EIO
	}
	return 0
}

func (f *VaultFuseFS) Unlink(path string) int {
	if err := f.vault.Delete(path); err != nil {
		return -fuse.EIO
	}
	return 0
}

func (f *VaultFuseFS) Rmdir(path string) int {
	if err := f.vault.Delete(path); err != nil {
		return -fuse.EIO
	}
	return 0
}

func (f *VaultFuseFS) Rename(oldpath string, newpath string) int {
	if err := f.vault.Rename(oldpath, newpath); err != nil {
		return -fuse.EIO
	}
	return 0
}

func (f *VaultFuseFS) Create(path string, flags int, mode uint32) (int, uint64) {
	if err := f.vault.WriteFile(path, []byte{}); err != nil {
		return -fuse.EIO, ^uint64(0)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	fh := f.nextFH
	f.nextFH++
	f.handles[fh] = &openHandle{
		path:  path,
		buf:   []byte{},
		dirty: true,
	}
	return 0, fh
}

func (f *VaultFuseFS) Open(path string, flags int) (int, uint64) {
	seeker, err := f.vault.OpenReadSeeker(path)
	if err != nil {
		return -fuse.ENOENT, ^uint64(0)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	fh := f.nextFH
	f.nextFH++
	f.handles[fh] = &openHandle{
		path:   path,
		seeker: seeker,
	}
	return 0, fh
}

func (f *VaultFuseFS) Read(path string, buff []byte, ofst int64, fh uint64) int {
	if ofst < 0 {
		return -fuse.EINVAL
	}

	f.mu.Lock()
	h, ok := f.handles[fh]
	if !ok {
		f.mu.Unlock()
		return -fuse.EBADF
	}
	if h.dirty {
		if ofst >= int64(len(h.buf)) {
			f.mu.Unlock()
			return 0
		}
		n := copy(buff, h.buf[int(ofst):])
		f.mu.Unlock()
		return n
	}
	seeker := h.seeker
	f.mu.Unlock()

	if seeker == nil {
		return -fuse.EIO
	}
	n, err := seeker.ReadAt(buff, ofst)
	if err != nil && err != io.EOF {
		return -fuse.EIO
	}
	return n
}

func (f *VaultFuseFS) Write(path string, buff []byte, ofst int64, fh uint64) int {
	if ofst < 0 || uint64(ofst) > uint64(^uint(0)>>1)-uint64(len(buff)) {
		return -fuse.EINVAL
	}

	f.mu.Lock()
	h, ok := f.handles[fh]
	if !ok {
		f.mu.Unlock()
		return -fuse.EBADF
	}

	if !h.dirty {
		if h.seeker != nil {
			_ = h.seeker.Close()
			h.seeker = nil
		}
		existing, err := f.vault.ReadFile(path)
		if err != nil {
			f.mu.Unlock()
			return -fuse.EIO
		}
		h.buf = existing
		h.dirty = true
	}

	end := int(ofst) + len(buff)
	if end > len(h.buf) {
		newBuf := make([]byte, end)
		copy(newBuf, h.buf)
		h.buf = newBuf
	}
	copy(h.buf[int(ofst):], buff)
	f.mu.Unlock()
	return len(buff)
}

func (f *VaultFuseFS) Flush(path string, fh uint64) int {
	f.mu.Lock()
	h, ok := f.handles[fh]
	f.mu.Unlock()
	if !ok {
		return 0
	}
	if h.dirty {
		if err := f.vault.WriteStream(h.path, bytes.NewReader(h.buf), int64(len(h.buf)), nil); err != nil {
			return -fuse.EIO
		}
		h.dirty = false
	}
	return 0
}

func (f *VaultFuseFS) Release(path string, fh uint64) int {
	_ = f.Flush(path, fh)
	f.mu.Lock()
	if h, ok := f.handles[fh]; ok {
		if h.seeker != nil {
			_ = h.seeker.Close()
		}
		h.buf = nil
		delete(f.handles, fh)
	}
	f.mu.Unlock()
	return 0
}
