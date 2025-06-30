package antireplay

import (
	"sync"

	ss_bloomring "github.com/v2fly/ss-bloomring"
)

type BloomRing struct {
	*ss_bloomring.BloomRing
	lock *sync.Mutex
}

func (b BloomRing) Interval() int64 {
	return 9999999
}

func (b BloomRing) Check(sum []byte) bool {
	b.lock.Lock()
	defer b.lock.Unlock()
	if b.Test(sum) {
		return false
	}
	b.Add(sum)
	return true
}

func NewBloomRing() BloomRing {
	const (
		DefaultSFCapacity = 1e6
		// FalsePositiveRate
		DefaultSFFPR  = 1e-6
		DefaultSFSlot = 10
	)
	return BloomRing{ss_bloomring.NewBloomRing(DefaultSFSlot, DefaultSFCapacity, DefaultSFFPR), &sync.Mutex{}}
}

// 🔴 新增：更小的Bloom Filter用于大量用户场景
func NewSmallBloomRing() BloomRing {
	const (
		SmallSFCapacity = 1e4  // 减少容量
		SmallSFFPR      = 1e-4 // 稍微提高误判率
		SmallSFSlot     = 5    // 减少槽位
	)
	return BloomRing{ss_bloomring.NewBloomRing(SmallSFSlot, SmallSFCapacity, SmallSFFPR), &sync.Mutex{}}
}
