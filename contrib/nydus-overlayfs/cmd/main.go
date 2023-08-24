package main

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/fifo"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

const (
	extraOptionKey  = "extraoption="
	signalKilled    = "signal: killed"
	envNydusWorkDir = "NYDUS_WORKDIR"
	envNydusBuilder = "NYDUS_BUILDER"
)

var (
	Version   = "development"
	BuildTime = "unknown"
)

// IsSignalKilled returns true if the error is signal killed
func IsSignalKilled(err error) bool {
	return strings.Contains(err.Error(), signalKilled)
}

type CleanupFunc func()

var AllCleanupFuncs = make([]CleanupFunc, 0, 10)

// Without locking protection, this function will only operate at the beginning of the program.
func RegisterCleanupFunc(f CleanupFunc) {
	AllCleanupFuncs = append(AllCleanupFuncs, f)
}

/*
containerd run fuse.mount format: nydus-overlayfs overlay /tmp/ctd-volume107067851
-o lowerdir=/foo/lower2:/foo/lower1,upperdir=/foo/upper,workdir=/foo/work,extraoption={...},dev,suid]
*/
type mountArgs struct {
	fsType  string
	target  string
	options []string
}

type PackOption struct {
	// WorkDir is used as the work directory during layer pack.
	WorkDir string
	// BuilderPath holds the path of `nydus-image` binary tool.
	BuilderPath string
	// Compressor specifies nydus blob compression algorithm.
	Compressor string
	// Timeout cancels execution once exceed the specified time.
	Timeout *time.Duration
	// BuildType default is director
	BuildType string
	// SouthPath
	SourcePath string
	// BlobPath
	BlobPath string
}

func getBuilder(specifiedPath string) string {
	if specifiedPath != "" {
		return specifiedPath
	}

	builderPath := os.Getenv(envNydusBuilder)
	if builderPath != "" {
		return builderPath
	}

	return "nydus-image"
}

func NydusPack(option PackOption, source io.Reader) error {
	args := []string{
		"create",
		"--log-level",
		"warn",
		"--blob",
		option.BlobPath,
		"--source-type",
		option.BuildType,
		"--whiteout-spec",
		"none",
		"--fs-version",
		"6",
		"--inline-bootstrap",
	}

	// targz-ref don't need Compressor
	if option.Compressor != "" && option.BuildType != "targz-ref" {
		args = append(args, "--compressor", option.Compressor)
	}

	args = append(args, "/proc/self/fd/0")

	ctx := context.Background()
	var cancel context.CancelFunc
	if option.Timeout != nil {
		ctx, cancel = context.WithTimeout(ctx, *option.Timeout)
		defer cancel()
	}

	logrus.Debugf("\tCommand: %s %s", option.BuilderPath, strings.Join(args[:], " "))

	cmd := exec.CommandContext(ctx, option.BuilderPath, args...)
	cmd.Stdin = source
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	RegisterCleanupFunc(func() {
		syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
	})

	if err := cmd.Run(); err != nil {
		if IsSignalKilled(err) && option.Timeout != nil {
			logrus.WithError(err).Errorf("fail to run %v %+v, possibly due to timeout %v", option.BuilderPath, args, *option.Timeout)
		} else {
			logrus.WithError(err).Errorf("fail to run %v %+v", option.BuilderPath, args)
		}
		return err
	}

	return nil
}

func ensureWorkDir(specifiedBasePath string) (string, error) {
	var baseWorkDir string

	if specifiedBasePath != "" {
		baseWorkDir = specifiedBasePath
	} else {
		baseWorkDir = os.Getenv(envNydusWorkDir)
	}
	if baseWorkDir == "" {
		baseWorkDir = os.TempDir()
	}

	if err := os.MkdirAll(baseWorkDir, 0750); err != nil {
		return "", errors.Wrapf(err, "create base directory %s", baseWorkDir)
	}

	workDirPath, err := ioutil.TempDir(baseWorkDir, "nydus-converter-")
	if err != nil {
		return "", errors.Wrap(err, "create work directory")
	}

	return workDirPath, nil
}

func Pack(ctx context.Context, source io.Reader, dest io.Writer, opt PackOption) (func() error, error) {
	workDir, err := ensureWorkDir(opt.WorkDir)
	if err != nil {
		return nil, errors.Wrap(err, "ensure work directory")
	}

	defer func() {
		if err != nil {
			os.RemoveAll(workDir)
		}
	}()

	RegisterCleanupFunc(func() {
		os.RemoveAll(workDir)
	})

	return func() error {
		defer func() {
			os.RemoveAll(workDir)
		}()

		blobPath := filepath.Join(workDir, "blob")
		blobFifo, err := fifo.OpenFifo(ctx, blobPath, syscall.O_CREAT|syscall.O_RDONLY|syscall.O_NONBLOCK, 0644)
		if err != nil {
			return errors.Wrapf(err, "create fifo file")
		}
		defer blobFifo.Close()

		go func() {
			err := NydusPack(PackOption{
				BuilderPath: getBuilder(opt.BuilderPath),
				BlobPath:    blobPath,
				SourcePath:  opt.SourcePath,
				Compressor:  opt.Compressor,
				Timeout:     opt.Timeout,
				BuildType:   opt.BuildType,
			}, source)
			if err != nil {
				blobFifo.Close()
			}
		}()

		if _, err := io.Copy(dest, blobFifo); err != nil {
			return errors.Wrap(err, "pack nydus tar")
		}
		return nil
	}, nil
}

type seekReader struct {
	io.ReaderAt
	pos int64
}

func (ra *seekReader) Read(p []byte) (int, error) {
	n, err := ra.ReaderAt.ReadAt(p, ra.pos)
	ra.pos += int64(len(p))
	return n, err
}

func (ra *seekReader) Seek(offset int64, whence int) (int64, error) {
	if whence == io.SeekCurrent {
		ra.pos += offset
	} else if whence == io.SeekStart {
		ra.pos = offset
	} else {
		return 0, fmt.Errorf("unsupported whence %d", whence)
	}
	return ra.pos, nil
}

func newSeekReader(ra io.ReaderAt) *seekReader {
	return &seekReader{
		ReaderAt: ra,
		pos:      0,
	}
}

type FileMode = fs.FileMode
type fileStat struct {
	name    string
	size    int64
	mode    FileMode
	modTime time.Time
}

func (fs *fileStat) Size() int64        { return fs.size }
func (fs *fileStat) Mode() FileMode     { return fs.mode }
func (fs *fileStat) ModTime() time.Time { return fs.modTime }
func (fs *fileStat) Sys() any           { return nil }
func (fs *fileStat) IsDir() bool        { return false }
func (fs *fileStat) Name() string       { return fs.name }

func convertToNydusLayer(ctx context.Context, opt PackOption, source io.Reader,
	dest io.Writer) error {
	pr, pw := io.Pipe()
	action, err := Pack(ctx, source, pw, opt)
	if err != nil {
		return errors.Wrap(err, "pack tar to nydus")
	}

	go func() {
		defer pw.Close()
		if err := action(); err != nil {
			pw.CloseWithError(err)
			return
		}
	}()

	blobFileWorkDir, err := ensureWorkDir(opt.WorkDir)
	if err != nil {
		return errors.Wrap(err, "ensure work directory")
	}
	defer func() {
		os.RemoveAll(blobFileWorkDir)
	}()

	RegisterCleanupFunc(func() {
		os.RemoveAll(blobFileWorkDir)
	})

	blobFile, err := ioutil.TempFile(blobFileWorkDir, "converting-")
	if err != nil {
		return errors.Wrap(err, "create temp file for converting blob")
	}
	if _, err := io.Copy(blobFile, pr); err != nil {
		return errors.Wrap(err, "copy nydus blob to blobdir")
	}

	stat, err := blobFile.Stat()
	if err != nil {
		return errors.Wrap(err, "get blobfile fileinfo")
	}

	const headerSize = 512

	if headerSize > stat.Size() {
		return fmt.Errorf("invalid nydus tar size %d", stat.Size())
	}
	cur := stat.Size() - headerSize
	reader := newSeekReader(blobFile)

	// Try to seek the part of tar header.
	_, err = reader.Seek(cur, io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "seek %d for nydus tar header", cur)
	}

	// Parse tar header.
	tr := tar.NewReader(reader)
	hdr, err := tr.Next()
	if err != nil {
		return errors.Wrap(err, "parse nydus tar header")
	}

	if cur < hdr.Size {
		return fmt.Errorf("invalid nydus tar data, name %s, size %d", hdr.Name, hdr.Size)
	}

	if hdr.Name != "image.boot" {
		return fmt.Errorf("invalid nydus tar entry name: %s, expectd is image.boot", hdr.Name)
	}

	// Try to seek the part of tar data.
	_, err = reader.Seek(cur-hdr.Size, io.SeekStart)
	if err != nil {
		return errors.Wrap(err, "seek target data offset")
	}
	bootstrapReader := io.NewSectionReader(reader, cur-hdr.Size, hdr.Size)

	tw := tar.NewWriter(dest)
	bootstrapStat := fileStat{
		name: "bootstrap",
		size: hdr.Size,
		mode: stat.Mode(),
	}
	bootstrapHdr, err := tar.FileInfoHeader(&bootstrapStat, "")
	if err != nil {
		return errors.Wrap(err, "failed to get blob stat header")
	}
	tw.WriteHeader(bootstrapHdr)
	if _, err := io.Copy(tw, bootstrapReader); err != nil {
		return errors.Wrap(err, "copy nydus bootstrap to target tar")
	}

	blobSize := stat.Size() - headerSize - hdr.Size

	blobStat := fileStat{
		name: "blob",
		size: blobSize,
		mode: stat.Mode(),
	}
	blobHdr, err := tar.FileInfoHeader(&blobStat, "")
	if err != nil {
		return errors.Wrap(err, "failed to get blob stat header")
	}
	tw.WriteHeader(blobHdr)

	_, err = reader.Seek(0, io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "seek for nydus begin")
	}

	blobReader := io.NewSectionReader(reader, 0, blobSize)
	if _, err := io.Copy(tw, blobReader); err != nil {
		return errors.Wrap(err, "copy nydus blob to target tar")
	}
	return tw.Close()
}

func image_create(args []string) error {
	sg := make(chan os.Signal, 1)
	signal.Notify(sg, syscall.SIGINT)
	signal.Notify(sg, syscall.SIGPIPE)
	signal.Notify(sg, syscall.SIGQUIT)
	signal.Notify(sg, syscall.SIGTERM)
	signal.Notify(sg, syscall.SIGUSR1)
	signal.Notify(sg, syscall.SIGUSR2)
	signal.Notify(sg, syscall.SIGHUP)
	signal.Notify(sg, syscall.SIGABRT)
	signal.Notify(sg, syscall.SIGALRM)

	go func() {
		s := <-sg
		os.Stderr.WriteString(fmt.Sprintf("receive signal %v\n", s.String()))
		for _, f := range AllCleanupFuncs {
			f()
		}
		os.Exit(-3)
	}()

	opt := PackOption{
		WorkDir:   "",
		BuildType: "targz-ref",
	}
	source := os.Stdin
	if len(args) >= 2 {
		sourceFile, err := os.Open(args[1])
		if err != nil {
			return errors.Wrap(err, "failed to open source file")
		}
		defer sourceFile.Close()
		source = sourceFile
	}

	RegisterCleanupFunc(func() {
		source.Close()
	})

	defer func() {
		source.Close()
	}()

	target := os.Stdout

	if len(args) >= 3 {
		targetFile, err := os.OpenFile(args[2], os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0755)
		if err != nil {
			return errors.Wrap(err, "failed to open source file")
		}
		defer targetFile.Close()
		target = targetFile
	}
	return convertToNydusLayer(context.Background(), opt, source, target)
}

func parseArgs(args []string) (*mountArgs, error) {
	margs := &mountArgs{
		fsType: args[0],
		target: args[1],
	}

	if margs.fsType != "overlay" {
		return nil, errors.New("fsType only support overlay")
	}
	if len(margs.target) == 0 {
		return nil, errors.New("target can not be empty")
	}
	if args[2] == "-o" && len(args[3]) != 0 {
		for _, opt := range strings.Split(args[3], ",") {
			if strings.HasPrefix(opt, extraOptionKey) {
				// filter extraoption
				continue
			}
			margs.options = append(margs.options, opt)
		}
	}
	if len(margs.options) == 0 {
		return nil, errors.New("options can not be empty")
	}
	return margs, nil
}

func parseOptions(options []string) (int, string) {
	flagsTable := map[string]int{
		"async":         unix.MS_SYNCHRONOUS,
		"atime":         unix.MS_NOATIME,
		"bind":          unix.MS_BIND,
		"defaults":      0,
		"dev":           unix.MS_NODEV,
		"diratime":      unix.MS_NODIRATIME,
		"dirsync":       unix.MS_DIRSYNC,
		"exec":          unix.MS_NOEXEC,
		"mand":          unix.MS_MANDLOCK,
		"noatime":       unix.MS_NOATIME,
		"nodev":         unix.MS_NODEV,
		"nodiratime":    unix.MS_NODIRATIME,
		"noexec":        unix.MS_NOEXEC,
		"nomand":        unix.MS_MANDLOCK,
		"norelatime":    unix.MS_RELATIME,
		"nostrictatime": unix.MS_STRICTATIME,
		"nosuid":        unix.MS_NOSUID,
		"rbind":         unix.MS_BIND | unix.MS_REC,
		"relatime":      unix.MS_RELATIME,
		"remount":       unix.MS_REMOUNT,
		"ro":            unix.MS_RDONLY,
		"rw":            unix.MS_RDONLY,
		"strictatime":   unix.MS_STRICTATIME,
		"suid":          unix.MS_NOSUID,
		"sync":          unix.MS_SYNCHRONOUS,
	}
	var (
		flags int
		data  []string
	)
	for _, o := range options {
		if f, exist := flagsTable[o]; exist {
			flags |= f
		} else {
			data = append(data, o)
		}
	}
	return flags, strings.Join(data, ",")
}

func run(args cli.Args) error {
	margs, err := parseArgs(args.Slice())
	if err != nil {
		return errors.Wrap(err, "parseArgs err")
	}

	log.Printf("domount info: %v\n", margs)

	flags, data := parseOptions(margs.options)
	err = syscall.Mount(margs.fsType, margs.target, margs.fsType, uintptr(flags), data)
	if err != nil {
		return errors.Wrap(err, "doMount err")
	}
	return nil
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "create" {
		err := image_create(os.Args[1:])
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	app := &cli.App{
		Name:      "NydusOverlayfs",
		Usage:     "Binary for containerd mount helper to do mount operation in nydus env",
		Version:   fmt.Sprintf("%s.%s", Version, BuildTime),
		UsageText: "[Usage]: ./nydus-overlayfs overlay <target> -o <options>",
		Action: func(c *cli.Context) error {
			return run(c.Args())
		},
		Before: func(c *cli.Context) error {
			if c.NArg() != 4 {
				cli.ShowAppHelpAndExit(c, 1)
			}
			return nil
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(0)
}
