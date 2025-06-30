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

// 🔴 新增：AEAD加密器缓存
type AEADCache struct {
	aead    cipher.AEAD
	created time.Time
}

// Validator stores valid Shadowsocks users.
type Validator struct {
	sync.RWMutex
	users []*protocol.MemoryUser

	// 🔴 新增：基于用户密钥的快速索引
	userIndex map[string]*protocol.MemoryUser // key: base64(userKey), value: user
	keyHashes map[string]string               // key: hash(userKey), value: base64(userKey)

	// 🔴 新增：AEAD加密器缓存
	aeadCache  map[string]*AEADCache // key: userKey+iv, value: cached AEAD
	cacheMutex sync.RWMutex

	behaviorSeed  uint64
	behaviorFused bool
}

var ErrNotFound = errors.New("Not Found")

// Add a Shadowsocks user.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	if !account.Cipher.IsAEAD() && len(v.users) > 0 {
		return errors.New("The cipher is not support Single-port Multi-user")
	}
	v.users = append(v.users, u)

	// 🔴 新增：初始化索引
	if v.userIndex == nil {
		v.userIndex = make(map[string]*protocol.MemoryUser)
		v.keyHashes = make(map[string]string)
		v.aeadCache = make(map[string]*AEADCache)
	}

	// 添加用户到索引
	userKey := string(account.Key)
	v.userIndex[userKey] = u

	// 预计算密钥哈希用于快速查找
	keyHash := sha256.Sum256(account.Key)
	keyHashStr := string(keyHash[:])
	v.keyHashes[keyHashStr] = userKey

	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
		hashkdf.Write(account.Key)
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

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
	var targetUser *protocol.MemoryUser
	for i, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			idx = i
			targetUser = u
			break
		}
	}

	if idx == -1 {
		return errors.New("User ", email, " not found.")
	}

	// 🔴 新增：从索引中删除用户
	if targetUser != nil && v.userIndex != nil {
		account := targetUser.Account.(*MemoryAccount)
		userKey := string(account.Key)
		delete(v.userIndex, userKey)

		// 删除密钥哈希
		keyHash := sha256.Sum256(account.Key)
		keyHashStr := string(keyHash[:])
		delete(v.keyHashes, keyHashStr)
	}

	ulen := len(v.users)
	v.users[idx] = v.users[ulen-1]
	v.users[ulen-1] = nil
	v.users = v.users[:ulen-1]

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
	v.RLock()
	defer v.RUnlock()

	// 🔴 优化：使用索引快速查找用户
	if v.userIndex != nil && len(bs) >= 32 {
		// 尝试从预计算的哈希中快速匹配
		for _, userKey := range v.keyHashes {
			if len(bs) < 32 {
				continue
			}

			user := v.userIndex[userKey]
			if user == nil {
				continue
			}

			account := user.Account.(*MemoryAccount)
			if !account.Cipher.IsAEAD() {
				continue
			}

			aeadCipher := account.Cipher.(*AEADCipher)
			ivLen = aeadCipher.IVSize()
			iv := bs[:ivLen]

			// 🔴 新增：尝试从缓存获取AEAD
			cacheKey := string(account.Key) + string(iv)
			v.cacheMutex.RLock()
			if cached, exists := v.aeadCache[cacheKey]; exists && time.Since(cached.created) < 5*time.Minute {
				aead = cached.aead
				v.cacheMutex.RUnlock()
			} else {
				v.cacheMutex.RUnlock()
				// 创建新的AEAD并缓存
				subkey := make([]byte, 32)
				subkey = subkey[:aeadCipher.KeyBytes]
				hkdfSHA1(account.Key, iv, subkey)
				aead = aeadCipher.AEADAuthCreator(subkey)

				// 缓存AEAD（限制缓存大小）
				v.cacheMutex.Lock()
				if len(v.aeadCache) < 1000 { // 限制缓存大小
					v.aeadCache[cacheKey] = &AEADCache{
						aead:    aead,
						created: time.Now(),
					}
				}
				v.cacheMutex.Unlock()
			}

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
				return
			}
		}
	}

	// 🔴 回退到原始线性搜索（仅用于非AEAD加密）
	for _, user := range v.users {
		if account := user.Account.(*MemoryAccount); account.Cipher.IsAEAD() {
			// AEAD payload decoding requires the payload to be over 32 bytes
			if len(bs) < 32 {
				continue
			}

			aeadCipher := account.Cipher.(*AEADCipher)
			ivLen = aeadCipher.IVSize()
			iv := bs[:ivLen]

			// 🔴 新增：尝试从缓存获取AEAD
			cacheKey := string(account.Key) + string(iv)
			v.cacheMutex.RLock()
			if cached, exists := v.aeadCache[cacheKey]; exists && time.Since(cached.created) < 5*time.Minute {
				aead = cached.aead
				v.cacheMutex.RUnlock()
			} else {
				v.cacheMutex.RUnlock()
				// 创建新的AEAD并缓存
				subkey := make([]byte, 32)
				subkey = subkey[:aeadCipher.KeyBytes]
				hkdfSHA1(account.Key, iv, subkey)
				aead = aeadCipher.AEADAuthCreator(subkey)

				// 缓存AEAD（限制缓存大小）
				v.cacheMutex.Lock()
				if len(v.aeadCache) < 1000 { // 限制缓存大小
					v.aeadCache[cacheKey] = &AEADCache{
						aead:    aead,
						created: time.Now(),
					}
				}
				v.cacheMutex.Unlock()
			}

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
				return
			}
		} else {
			u = user
			ivLen = user.Account.(*MemoryAccount).Cipher.IVSize()
			// err = user.Account.(*MemoryAccount).CheckIV(bs[:ivLen]) // The IV size of None Cipher is 0.
			return
		}
	}

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
