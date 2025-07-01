package shadowsocks

import (
	"testing"
	"time"
)

func TestValidatorCache(t *testing.T) {
	// 创建新的验证器
	v := NewValidator()

	// 测试缓存统计
	validCount, expiredCount := v.GetCacheStats()
	if validCount != 0 || expiredCount != 0 {
		t.Errorf("初始缓存统计错误: valid=%d, expired=%d", validCount, expiredCount)
	}

	// 测试缓存TTL设置
	v.SetCacheTTL(30 * time.Minute)

	// 测试清空缓存
	v.ClearCache()
	validCount, expiredCount = v.GetCacheStats()
	if validCount != 0 || expiredCount != 0 {
		t.Errorf("清空缓存后统计错误: valid=%d, expired=%d", validCount, expiredCount)
	}

	// 测试过期缓存检查
	cacheKey := "test_key"
	if v.isKeyInExpiredCache(cacheKey) {
		t.Error("空缓存中不应该找到key")
	}
}

func TestValidatorCacheCleanup(t *testing.T) {
	v := NewValidator()

	// 设置较短的TTL用于测试
	v.SetCacheTTL(100 * time.Millisecond)

	// 添加一些测试数据到有效缓存
	v.cacheMutex.Lock()
	v.validCache["test1"] = &CacheEntry{
		user:    nil,
		aead:    nil,
		expires: time.Now().Add(-50 * time.Millisecond), // 已过期
	}
	v.validCache["test2"] = &CacheEntry{
		user:    nil,
		aead:    nil,
		expires: time.Now().Add(200 * time.Millisecond), // 未过期
	}
	v.cacheMutex.Unlock()

	// 等待一段时间让过期条目过期
	time.Sleep(150 * time.Millisecond)

	// 清理过期缓存
	v.cleanupExpiredCache()

	// 检查结果
	v.cacheMutex.RLock()
	_, exists1 := v.validCache["test1"]
	_, exists2 := v.validCache["test2"]
	_, expiredExists := v.expiredCache["test1"]
	v.cacheMutex.RUnlock()

	if exists1 {
		t.Error("过期的条目应该被移动到过期缓存")
	}
	if !exists2 {
		t.Error("未过期的条目应该保留在有效缓存中")
	}
	if !expiredExists {
		t.Error("过期的条目应该存在于过期缓存中")
	}
}
