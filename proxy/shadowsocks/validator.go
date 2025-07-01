package shadowsocks

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// CacheEntry 缓存条目
type CacheEntry struct {
	user    *protocol.MemoryUser
	aead    cipher.AEAD
	expires time.Time
}

// Validator stores valid Shadowsocks users.
type Validator struct {
	sync.RWMutex
	users []*protocol.MemoryUser

	behaviorSeed  uint64
	behaviorFused bool

	// 缓存相关字段
	validCache   map[string]*CacheEntry // 有效缓存
	expiredCache map[string]*CacheEntry // 过期缓存
	cacheMutex   sync.RWMutex
	cacheTTL     time.Duration // 缓存过期时间
}

var ErrNotFound = errors.New("Not Found")

// NewValidator 创建新的验证器实例
func NewValidator() *Validator {
	return &Validator{
		validCache:   make(map[string]*CacheEntry),
		expiredCache: make(map[string]*CacheEntry),
		cacheTTL:     time.Hour, // 1小时过期时间
	}
}

// generateCacheKey 生成缓存key
func (v *Validator) generateCacheKey(bs []byte, command protocol.RequestCommand) string {
	// 使用前32字节作为key的一部分，加上命令类型
	keyLen := 32
	if len(bs) < keyLen {
		keyLen = len(bs)
	}
	return string(bs[:keyLen]) + "_" + string(command)
}

// cleanupExpiredCache 清理过期缓存
func (v *Validator) cleanupExpiredCache() {
	v.cacheMutex.Lock()
	defer v.cacheMutex.Unlock()

	now := time.Now()

	// 清理有效缓存中的过期条目
	for key, entry := range v.validCache {
		if now.After(entry.expires) {
			v.expiredCache[key] = entry
			delete(v.validCache, key)
		}
	}

	// 清理过期缓存中的过期条目
	for key, entry := range v.expiredCache {
		if now.After(entry.expires.Add(v.cacheTTL)) { // 过期缓存保留1小时
			delete(v.expiredCache, key)
		}
	}
}

// checkAndRestoreExpiredCache 检查过期缓存中的用户是否仍然存在，如果存在则恢复
func (v *Validator) checkAndRestoreExpiredCache() {
	v.cacheMutex.Lock()
	defer v.cacheMutex.Unlock()

	// 检查过期缓存中的用户是否仍然在当前users列表中
	for key, entry := range v.expiredCache {
		// 检查用户是否仍然存在
		v.RLock()
		userExists := false
		for _, user := range v.users {
			if user == entry.user {
				userExists = true
				break
			}
		}
		v.RUnlock()

		// 如果用户仍然存在，说明key没有过期，移回有效缓存
		if userExists {
			entry.expires = time.Now().Add(v.cacheTTL) // 重新设置过期时间
			v.validCache[key] = entry
			delete(v.expiredCache, key)
		}
	}
}

// cleanupUserCache 清理指定用户的缓存
func (v *Validator) cleanupUserCache(user *protocol.MemoryUser) {
	v.cacheMutex.Lock()
	defer v.cacheMutex.Unlock()

	// 清理有效缓存中与该用户相关的条目
	for key, entry := range v.validCache {
		if entry.user == user {
			delete(v.validCache, key)
		}
	}

	// 清理过期缓存中与该用户相关的条目
	for key, entry := range v.expiredCache {
		if entry.user == user {
			delete(v.expiredCache, key)
		}
	}
}

// Add a Shadowsocks user.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	if !account.Cipher.IsAEAD() && len(v.users) > 0 {
		return errors.New("The cipher is not support Single-port Multi-user")
	}
	v.users = append(v.users, u)

	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
		hashkdf.Write(account.Key)
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	// 清理与该用户相关的旧缓存（如果存在）
	v.cleanupUserCache(u)

	return nil
}

// Del a Shadowsocks user with a non-empty Email.
func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	idx := -1
	var deletedUser *protocol.MemoryUser
	for i, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			idx = i
			deletedUser = u
			break
		}
	}

	if idx == -1 {
		return errors.New("User ", email, " not found.")
	}
	ulen := len(v.users)

	v.users[idx] = v.users[ulen-1]
	v.users[ulen-1] = nil
	v.users = v.users[:ulen-1]

	// 清理与该用户相关的缓存
	v.cleanupUserCache(deletedUser)

	return nil
}

// GetByEmail Get a Shadowsocks user with a non-empty Email.
func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	for _, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			return u
		}
	}
	return nil
}

// GetAll get all users
func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.Lock()
	defer v.Unlock()
	dst := make([]*protocol.MemoryUser, len(v.users))
	copy(dst, v.users)
	return dst
}

// GetCount get users count
func (v *Validator) GetCount() int64 {
	v.Lock()
	defer v.Unlock()
	return int64(len(v.users))
}

// Get a Shadowsocks user.
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	// 1. 清理过期缓存
	v.cleanupExpiredCache()

	// 2. 检查并恢复过期缓存中的有效条目
	v.checkAndRestoreExpiredCache()

	// 3. 生成缓存key
	cacheKey := v.generateCacheKey(bs, command)

	// 4. 检查是否在过期缓存中
	if v.isKeyInExpiredCache(cacheKey) {
		// 如果在过期缓存中，直接返回NotFound，避免重复的全量遍历
		return nil, nil, nil, 0, ErrNotFound
	}

	// 5. 先检查有效缓存
	v.cacheMutex.RLock()
	if entry, exists := v.validCache[cacheKey]; exists {
		// 找到有效缓存，延长过期时间
		entry.expires = time.Now().Add(v.cacheTTL)
		v.cacheMutex.RUnlock()

		// 使用缓存的数据进行解密验证
		user := entry.user
		account := user.Account.(*MemoryAccount)

		if account.Cipher.IsAEAD() {
			if len(bs) < 32 {
				return nil, nil, nil, 0, ErrNotFound
			}

			aeadCipher := account.Cipher.(*AEADCipher)
			ivLen = aeadCipher.IVSize()
			iv := bs[:ivLen]

			var matchErr error
			switch command {
			case protocol.RequestCommandTCP:
				data := make([]byte, 4+entry.aead.NonceSize())
				ret, matchErr = entry.aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
			case protocol.RequestCommandUDP:
				data := make([]byte, 8192)
				ret, matchErr = entry.aead.Open(data[:0], data[8192-entry.aead.NonceSize():8192], bs[ivLen:], nil)
			}

			if matchErr == nil {
				u = user
				aead = entry.aead
				err = account.CheckIV(iv)
				return
			}
		} else {
			u = user
			ivLen = account.Cipher.IVSize()
			return
		}
	}
	v.cacheMutex.RUnlock()

	// 6. 缓存未命中，遍历全量users
	v.RLock()
	defer v.RUnlock()

	for _, user := range v.users {
		if account := user.Account.(*MemoryAccount); account.Cipher.IsAEAD() {
			// AEAD payload decoding requires the payload to be over 32 bytes
			if len(bs) < 32 {
				continue
			}

			aeadCipher := account.Cipher.(*AEADCipher)
			ivLen = aeadCipher.IVSize()
			iv := bs[:ivLen]
			subkey := make([]byte, 32)
			subkey = subkey[:aeadCipher.KeyBytes]
			hkdfSHA1(account.Key, iv, subkey)
			aead = aeadCipher.AEADAuthCreator(subkey)

			var matchErr error
			switch command {
			case protocol.RequestCommandTCP:
				data := make([]byte, 4+aead.NonceSize())
				ret, matchErr = aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
			case protocol.RequestCommandUDP:
				data := make([]byte, 8192)
				ret, matchErr = aead.Open(data[:0], data[8192-aead.NonceSize():8192], bs[ivLen:], nil)
			}

			if matchErr == nil {
				u = user
				err = account.CheckIV(iv)

				// 7. 找到匹配的用户，添加到缓存
				v.cacheMutex.Lock()
				v.validCache[cacheKey] = &CacheEntry{
					user:    user,
					aead:    aead,
					expires: time.Now().Add(v.cacheTTL),
				}
				v.cacheMutex.Unlock()

				return
			}
		} else {
			u = user
			ivLen = user.Account.(*MemoryAccount).Cipher.IVSize()
			// err = user.Account.(*MemoryAccount).CheckIV(bs[:ivLen]) // The IV size of None Cipher is 0.

			// 对于非AEAD加密，也添加到缓存
			v.cacheMutex.Lock()
			v.validCache[cacheKey] = &CacheEntry{
				user:    user,
				aead:    nil,
				expires: time.Now().Add(v.cacheTTL),
			}
			v.cacheMutex.Unlock()

			return
		}
	}

	// 8. 全量遍历未找到匹配用户，添加到过期缓存
	v.cacheMutex.Lock()
	v.expiredCache[cacheKey] = &CacheEntry{
		user:    nil, // 没有找到用户
		aead:    nil,
		expires: time.Now().Add(v.cacheTTL),
	}
	v.cacheMutex.Unlock()

	return nil, nil, nil, 0, ErrNotFound
}

func (v *Validator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}

// GetCacheStats 获取缓存统计信息
func (v *Validator) GetCacheStats() (validCount, expiredCount int) {
	v.cacheMutex.RLock()
	defer v.cacheMutex.RUnlock()

	validCount = len(v.validCache)
	expiredCount = len(v.expiredCache)
	return
}

// ClearCache 清空所有缓存
func (v *Validator) ClearCache() {
	v.cacheMutex.Lock()
	defer v.cacheMutex.Unlock()

	v.validCache = make(map[string]*CacheEntry)
	v.expiredCache = make(map[string]*CacheEntry)
}

// SetCacheTTL 设置缓存过期时间
func (v *Validator) SetCacheTTL(ttl time.Duration) {
	v.cacheMutex.Lock()
	defer v.cacheMutex.Unlock()

	v.cacheTTL = ttl
}

// isKeyInExpiredCache 检查key是否在过期缓存中
func (v *Validator) isKeyInExpiredCache(cacheKey string) bool {
	v.cacheMutex.RLock()
	defer v.cacheMutex.RUnlock()

	_, exists := v.expiredCache[cacheKey]
	return exists
}
