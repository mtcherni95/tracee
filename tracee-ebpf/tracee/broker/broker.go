package broker

import (
	"fmt"
	cmap "github.com/orcaman/concurrent-map"
	"strconv"
	"sync/atomic"

	"github.com/aquasecurity/tracee/tracee-ebpf/tracee"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/streamers"
)

type Broker struct {
	nextAvailStreamerId uint64
	Streamers           cmap.ConcurrentMap
	ChanPerStreamer     cmap.ConcurrentMap
	ChanEvents          <-chan external.Event
}

func (b *Broker) Register(streamer streamers.Streamer) error {
	nextAvailStreamerId := atomic.AddUint64(&b.nextAvailStreamerId, 1)
	atomic.StoreUint64(&b.nextAvailStreamerId, nextAvailStreamerId)
	if ok := b.Streamers.SetIfAbsent(strconv.FormatUint(nextAvailStreamerId, 10), streamer); !ok {
		return fmt.Errorf("failed to subscribe streamer")
	}
	c := make(chan *external.Event, 100)
	if ok := b.ChanPerStreamer.SetIfAbsent(strconv.FormatUint(nextAvailStreamerId, 10), c); !ok {
		return fmt.Errorf("failed to subscribe streamer")
	}

	streamer.SetId(nextAvailStreamerId)
	streamer.SetEventsChan(c)

	streamer.Preamble()
	go streamer.Run()
	return nil
}

func (b *Broker) Unregister(id uint64) (streamers.Streamer, error) {
	s, ok := b.Streamers.Get(strconv.FormatUint(id, 10))
	if !ok {
		return nil, fmt.Errorf("not existing subscriber: %v", id)
	}
	b.Streamers.Remove(strconv.FormatUint(id, 10))
	c, _ := b.ChanPerStreamer.Get(strconv.FormatUint(id, 10))
	close(c.(chan *external.Event))
	b.ChanPerStreamer.Remove(strconv.FormatUint(id, 10))
	return s.(streamers.Streamer), nil
}

func (b *Broker) Start(stats *tracee.StatsStore) error {
	errc := make(chan error, 1)
	go func() {
		defer close(errc)
		for e := range b.ChanEvents {
			// fan-out
			stats.EventCounter.Increment()
			cb := func(key string, v interface{}) {
				v.(chan *external.Event) <- &e
			}
			b.ChanPerStreamer.IterCb(cb)
		}
	}()
	return nil
	// TODO
	//return errc, nil
}

func (b *Broker) Stop(stats *tracee.StatsStore) {
	// closing handler channel
	cb := func(key string, v interface{}) {
		close (v.(chan *external.Event))
	}
	b.ChanPerStreamer.IterCb(cb)
	b.ChanPerStreamer.Clear()

	cb = func(key string, v interface{}) {
		v.(streamers.Streamer).Epilogue(*stats)
		v.(streamers.Streamer).Close()
	}
	b.Streamers.IterCb(cb)
	b.Streamers.Clear()

}
