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
	ChanEvents          <-chan external.Event
}

func (b *Broker) Register(streamer streamers.Streamer) error {
	nextAvailStreamerId := atomic.AddUint64(&b.nextAvailStreamerId, 1)
	atomic.StoreUint64(&b.nextAvailStreamerId, nextAvailStreamerId)
	if ok := b.Streamers.SetIfAbsent(strconv.FormatUint(b.nextAvailStreamerId, 10), streamer); !ok {
		return fmt.Errorf("failed to subscribe streamer")
	}
	streamer.SetId(b.nextAvailStreamerId)
	streamer.Preamble()
	return nil
}

func (b *Broker) Unregister(id uint64) (streamers.Streamer, error) {
	s, ok := b.Streamers.Get(strconv.FormatUint(id, 10))
	if !ok {
		return nil, fmt.Errorf("not existing subscriber: %v", id)
	}
	b.Streamers.Remove(strconv.FormatUint(id, 10))
	return s.(streamers.Streamer), nil
}

func (b *Broker) Start(stats *tracee.StatsStore) error {
	errc := make(chan error, 1)
	go func() {
		defer close(errc)
		for printEvent := range b.ChanEvents {
			stats.EventCounter.Increment()
			cb := func(key string, v interface{}) {
				v.(streamers.Streamer).Stream(&printEvent)
			}
			b.Streamers.IterCb(cb)
		}
	}()
	return nil
	// TODO
	//return errc, nil
}

func (b *Broker) Stop(stats *tracee.StatsStore) {
	cb := func(key string, v interface{}) {
		v.(streamers.Streamer).Epilogue(*stats)
		v.(streamers.Streamer).Close()
	}
	b.Streamers.IterCb(cb)
	b.Streamers.Clear()
}
