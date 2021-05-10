package libbpfgo

import "C"
import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"io/ioutil"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"
)
var (
	errClosed = errors.New("perf reader was closed")
	errEOR    = errors.New("end of ring")
)


type PerfCallbackV2 func(uintptr, []byte)
type PerfLostCallbackV2 func(uintptr, uint64)

// perfEventHeader must match 'struct perf_event_header` in <linux/perf_event.h>.
type perfEventHeader struct {
	Type uint32
	Misc uint16
	Size uint16
}

type  Reader struct {
	origFd int

	// mu protects read/write access to the Reader structure with the
	// exception of 'pauseFds', which is protected by 'pauseMu'.
	// If locking both 'mu' and 'pauseMu', 'mu' must be locked first.
	mu sync.Mutex

	// Closing a PERF_EVENT_ARRAY removes all event fds
	// stored in it, so we keep a reference alive.

	//array *ebpf.Map

	rings []*perfEventRing

	epollFd     int
	epollEvents []unix.EpollEvent
	epollRings  []*perfEventRing
	// Eventfds for closing
	closeFd int
	// Ensure we only close once
	closeOnce sync.Once

	// pauseFds are a copy of the fds in 'rings', protected by 'pauseMu'.
	// These allow Pause/Resume to be executed independently of any ongoing
	// Read calls, which would otherwise need to be interrupted.
	pauseMu  sync.Mutex
	pauseFds []int
}

type perfEventRing struct {
	Fd   int
	cpu  int
	mmap []byte
	*ringReader
}

type ringReader struct {
	meta       *unix.PerfEventMmapPage
	head, tail uint64
	mask       uint64
	ring       []byte
}

type unknownEventError struct {
	eventType uint32
}

// Record contains either a sample or a counter of the
// number of lost samples.
type Record struct {
	// The CPU this record was generated on.
	CPU int

	// The data submitted via bpf_perf_event_output.
	// Due to a kernel bug, this can contain between 0 and 7 bytes of trailing
	// garbage from the ring depending on the input sample's length.
	RawSample []byte

	// The number of samples which could not be output, since
	// the ring buffer was full.
	LostSamples uint64

	EventsCallback PerfCallbackV2
	LostEventsCallback PerfLostCallbackV2
}

var nativeEndian binary.ByteOrder

func isBigEndian() (ret bool) {
	i := int(0x1)
	bs := (*[int(unsafe.Sizeof(i))]byte)(unsafe.Pointer(&i))
	return bs[0] == 0
}
// NativeEndian is set to either binary.BigEndian or binary.LittleEndian,
// depending on the host's endianness.

func initNativeEndian() {
	if isBigEndian() {
		nativeEndian = binary.BigEndian
	} else {
		nativeEndian = binary.LittleEndian
	}
}

func perfCallbackV2(ctx uintptr, b []byte) {
	eventChannels[ctx] <- b
}

func perfLostCallbackV2(ctx uintptr, cnt uint64) {
	lostChan := lostChannels[ctx]
	if lostChan != nil {
		lostChan <- cnt
	}
}

func (rr *ringReader) Read(p []byte) (int, error) {
	start := int(rr.tail & rr.mask)

	n := len(p)
	// Truncate if the read wraps in the ring buffer
	if remainder := cap(rr.ring) - start; n > remainder {
		n = remainder
	}

	// Truncate if there isn't enough data
	if remainder := int(rr.head - rr.tail); n > remainder {
		n = remainder
	}

	copy(p, rr.ring[start:start+n])
	rr.tail += uint64(n)

	if rr.tail == rr.head {
		return n, io.EOF
	}

	return n, nil
}

// parseCPUs parses the number of cpus from a string produced
// by bitmap_list_string() in the Linux kernel.
// Multiple ranges are rejected, since they can't be unified
// into a single number.
// This is the format of /sys/devices/system/cpu/possible, it
// is not suitable for /sys/devices/system/cpu/online, etc.
func parseCPUs(spec string) (int, error) {
	if strings.Trim(spec, "\n") == "0" {
		return 1, nil
	}

	var low, high int
	n, err := fmt.Sscanf(spec, "%d-%d\n", &low, &high)
	if n != 2 || err != nil {
		return 0, fmt.Errorf("invalid format: %s", spec)
	}
	if low != 0 {
		return 0, fmt.Errorf("CPU spec doesn't start at zero: %s", spec)
	}

	// cpus is 0 indexed
	return high + 1, nil
}

func parseCPUsFromFile(path string) (int, error) {
	spec, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, err
	}

	n, err := parseCPUs(string(spec))
	if err != nil {
		return 0, fmt.Errorf("can't parse %s: %v", path, err)
	}

	return n, nil
}

func CPUsAmonut() (int, error) {
	num, err := parseCPUsFromFile("/sys/devices/system/cpu/possible")
	return num, err
}

func (rr *ringReader) loadHead() {
	rr.head = atomic.LoadUint64(&rr.meta.Data_head)
}

// TODO this is the THIRD func
func createPerfEvent(cpu, watermark int /* TODO understand what watermark is */) (int, error) {
	if watermark == 0 {
		watermark = 1
	}

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
		Bits:        unix.PerfBitWatermark,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Wakeup:      uint32(watermark),
	}

	attr.Size = uint32(unsafe.Sizeof(attr))
	fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("can't create perf event: %w", err)
	}
	return fd, nil
}
// passed to runtime as finalizer
func (ring *perfEventRing) Close() {
	runtime.SetFinalizer(ring, nil)

	_ = unix.Close(ring.Fd)
	_ = unix.Munmap(ring.mmap)

	ring.Fd = -1
	ring.mmap = nil
}
// TODO this is probably not needed...
func newRingReader(meta *unix.PerfEventMmapPage, ring []byte) *ringReader {
	return &ringReader{
		meta: meta,
		head: atomic.LoadUint64(&meta.Data_head),
		tail: atomic.LoadUint64(&meta.Data_tail),
		// cap is always a power of two
		mask: uint64(cap(ring) - 1),
		ring: ring,
	}
}

func newPerfEventRing(cpu, pageCount, watermark int) (*perfEventRing, error){
/*
	// TODO what's watermark
	if watermark >= perCPUBuffer {
		return nil, errors.New("watermark must be smaller than perCPUBuffer")
	}
*/

	fd, err := createPerfEvent(cpu, watermark)
	if err != nil {
		return nil, err
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}

	totalBytes := os.Getpagesize() * pageCount

	mmap, err := unix.Mmap(fd, 0, totalBytes, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("can't mmap: %v", err)
	}


	// This relies on the fact that we allocate an extra metadata page,
	// and that the struct is smaller than an OS page.
	// This use of unsafe.Pointer isn't explicitly sanctioned by the
	// documentation, since a byte is smaller than sampledPerfEvent.
	meta := (*unix.PerfEventMmapPage)(unsafe.Pointer(&mmap[0]))

	ring := &perfEventRing{
		Fd:         fd,
		cpu:        cpu,
		mmap:       mmap,
		ringReader: newRingReader(meta, mmap[meta.Data_offset:meta.Data_offset+meta.Data_size]), // TODO this probably not needed
	}
	// TODO understand whats this
	runtime.SetFinalizer(ring, (*perfEventRing).Close)

	return ring, nil
}


func addToEpoll(epollfd, fd int, cpu int) error {
	if int64(cpu) > math.MaxInt32 {
		return fmt.Errorf("unsupported CPU number: %d", cpu)
	}

	// The representation of EpollEvent isn't entirely accurate.
	// Pad is fully useable, not just padding. Hence we stuff the
	// CPU in there, which allows us to use a slice to access
	// the correct perf ring.
	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(fd),
		Pad:    int32(cpu),
	}

	if err := unix.EpollCtl(epollfd, unix.EPOLL_CTL_ADD, fd, &event); err != nil {
		return fmt.Errorf("can't add Fd to epoll: %v", err)
	}
	return nil
}

type temporaryError interface {
	Temporary() bool
}

func cpuForEvent(event *unix.EpollEvent) int {
	return int(event.Pad)
}

// Read the next record from the perf ring buffer.
//
// The function blocks until there are at least Watermark bytes in one
// of the per CPU buffers. Records from buffers below the Watermark
// are not returned.
//
// Records can contain between 0 and 7 bytes of trailing garbage from the ring
// depending on the input sample's length.
//
// Calling Close interrupts the function.
// TODO errror return...
// TODO change naming
func (pr *Reader) Read() error {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if pr.epollFd == -1 {
		return nil// TODO
	}

	for {
		if len(pr.epollRings) == 0 {
			nEvents, err := unix.EpollWait(pr.epollFd, pr.epollEvents, -1)
			if temp, ok := err.(temporaryError); ok && temp.Temporary() {
				// Retry the syscall if we we're interrupted, see https://github.com/golang/go/issues/20400
				continue
			}

			if err != nil {
				return err
			}

			for _, event := range pr.epollEvents[:nEvents] {
				if int(event.Fd) == pr.closeFd {
					return nil
				}

				ring := pr.rings[cpuForEvent(&event)]
				pr.epollRings = append(pr.epollRings, ring)

				// Read the current head pointer now, not every time
				// we read a record. This prevents a single fast producer
				// from keeping the reader busy.
				ring.loadHead()
			}
		}

		// Start at the last available event. The order in which we
		// process them doesn't matter, and starting at the back allows
		// resizing epollRings to keep track of processed rings.
		err := readRecordFromRing(pr.epollRings[len(pr.epollRings)-1])
		if err == errEOR {
			// We've emptied the current ring buffer, process
			// the next one.
			pr.epollRings = pr.epollRings[:len(pr.epollRings)-1]
			continue
		}

		return nil
	}
}


func (rr *ringReader) writeTail() {
	// Commit the new tail. This lets the kernel know that
	// the ring buffer has been consumed.
	atomic.StoreUint64(&rr.meta.Data_tail, rr.tail)
}

func readLostRecords(rd io.Reader) (uint64, error) {
	// lostHeader must match 'struct perf_event_lost in kernel sources.
	var lostHeader struct {
		ID   uint64
		Lost uint64
	}

	err := binary.Read(rd, nativeEndian, &lostHeader)
	if err != nil {
		return 0, fmt.Errorf("can't read lost records header: %v", err)
	}

	return lostHeader.Lost, nil
}

func readRawSample(rd io.Reader) ([]byte, error) {
	// This must match 'struct perf_event_sample in kernel sources.
	var size uint32
	if err := binary.Read(rd, nativeEndian, &size); err != nil {
		return nil, fmt.Errorf("can't read sample size: %v", err)
	}

	data := make([]byte, int(size))
	if _, err := io.ReadFull(rd, data); err != nil {
		return nil, fmt.Errorf("can't read sample: %v", err)
	}
	return data, nil
}

// NB: Has to be preceded by a call to ring.loadHead.
func readRecordFromRing(ring *perfEventRing) (error) {
	defer ring.writeTail()
	return readRecord(ring, ring.cpu, uintptr(ring.Fd))
}

func readRecord(rd io.Reader, cpu int, ctx uintptr) error {
	var header perfEventHeader
	err := binary.Read(rd, nativeEndian, &header)
	if err == io.EOF {
		return errEOR
	}

	if err != nil {
		return fmt.Errorf("can't read event header: %v", err)
	}

	switch header.Type {
	case unix.PERF_RECORD_LOST:
		lost, _ := readLostRecords(rd)
		perfLostCallbackV2(ctx, lost)
		//return Record{CPU: cpu, LostSamples: lost}, err

	case unix.PERF_RECORD_SAMPLE:
		sample, _ := readRawSample(rd)
		perfCallbackV2(ctx, sample)
		//return Record{CPU: cpu, RawSample: sample}, err

	default:
		return fmt.Errorf("unknown event received")
	}
	return nil
}

// TODO create object api to return
func InitPerfBufV2(fd int, pageCount int /* maybe add opt struct... */) (pr *Reader, err error) {
	if pageCount < 1 {
		return nil, fmt.Errorf("page count must be strictly positive")
	}

	initNativeEndian()

	// TODO for every cpu create buffer
	epollFd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}

	nCPU, err:= CPUsAmonut()
	if err != nil {
		return nil, fmt.Errorf("failed fetching CPUs amount")

	}

	var (
		fds      = []int{epollFd}
		rings    = make([]*perfEventRing, 0, nCPU)
		pauseFds = make([]int, 0, nCPU)
	)

	defer func() {
		if err != nil {
			for _, fd := range fds {
				unix.Close(fd)
			}
			for _, ring := range rings {
				if ring != nil {
					ring.Close()
				}
			}
		}
	}()

	for i := 0; i < nCPU; i++ {
		// TODO understand what is opts.Watermark
		ring, err := newPerfEventRing(i, pageCount, /*opts.Watermark TODO understand watermark */ 0)

		if errors.Is(err, unix.ENODEV) {
			// The requested CPU is currently offline, skip it.
			rings = append(rings, nil)
			pauseFds = append(pauseFds, -1)
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("failed to create perf ring for CPU %d: %v", i, err)
		}

		rings = append(rings, ring)
		pauseFds = append(pauseFds, ring.Fd)

		if err := addToEpoll(epollFd, ring.Fd, len(rings)-1); err != nil {
			return nil, err
		}
	}

	closeFd, err := unix.Eventfd(0, unix.O_CLOEXEC|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	fds = append(fds, closeFd)

	if err := addToEpoll(epollFd, closeFd, -1); err != nil {
		return nil, err
	}

	// TODO understand this part

	//array, err = array.Clone()
	//if err != nil {
	//	return nil, err
	//}

	pr = &Reader{
		origFd:   fd,
		rings:   rings,
		epollFd: epollFd,
		// Allocate extra event for closeFd
		epollEvents: make([]unix.EpollEvent, len(rings)+1),
		epollRings:  make([]*perfEventRing, 0, len(rings)),
		closeFd:     closeFd,
		pauseFds:    pauseFds,
	}

	// TODO pr.resume() is not ready done
	if err = pr.Resume(); err != nil {
		return nil, err
	}
	// TODO	reader.close()
	runtime.SetFinalizer(pr, (*Reader).Close)
	return pr, nil

}

// Resume allows this perf reader to emit notifications.
//
// Subsequent calls to Read will block until the next event notification.
func (pr *Reader) Resume() error {
	pr.pauseMu.Lock()
	defer pr.pauseMu.Unlock()

	if pr.pauseFds == nil {
		return errClosed
	}

	for _, fd := range pr.pauseFds {
		if fd == -1 {
			continue
		}

		// TODO ...
		//if err := pr.array.Put(uint32(i), uint32(fd)); err != nil {
		//	return fmt.Errorf("couldn't put event fd %d for CPU %d: %w", fd, i, err)
		//}
	}

	return nil
}

// Close frees resources used by the reader.
//
// It interrupts calls to Read.
//
// Calls to perf_event_output from eBPF programs will return
// ENOENT after calling this method.
func (pr *Reader) Close() error {
	var err error
	pr.closeOnce.Do(func() {
		runtime.SetFinalizer(pr, nil)

		// Interrupt Read() via the event fd.
		var value [8]byte
		nativeEndian.PutUint64(value[:], 1)
		_, err = unix.Write(pr.closeFd, value[:])
		if err != nil {
			err = fmt.Errorf("can't write event fd: %v", err)
			return
		}

		// Acquire the locks. This ensures that Read, Pause and Resume
		// aren't running.
		pr.mu.Lock()
		defer pr.mu.Unlock()
		pr.pauseMu.Lock()
		defer pr.pauseMu.Unlock()

		unix.Close(pr.epollFd)
		unix.Close(pr.closeFd)
		pr.epollFd, pr.closeFd = -1, -1

		// Close rings
		for _, ring := range pr.rings {
			if ring != nil {
				ring.Close()
			}
		}
		pr.rings = nil
		pr.pauseFds = nil

		// TODO not sure it is good enough
		unix.Close(pr.origFd)
	})
	if err != nil {
		return fmt.Errorf("close PerfReader: %w", err)
	}
	return nil
}