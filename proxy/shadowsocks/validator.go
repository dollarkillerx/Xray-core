package shadowsocks

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid Shadowsocks users.
type Validator struct {
	sync.RWMutex
	users []*protocol.MemoryUser

	behaviorSeed  uint64
	behaviorFused bool

	hotCache []*protocol.MemoryUser
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

	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
		hashkdf.Write(account.Key)
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	// 初始化 hotCache
	if v.hotCache == nil {
		v.hotCache = make([]*protocol.MemoryUser, 0)
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
	for i, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			idx = i
			break
		}
	}

	if idx == -1 {
		return errors.New("User ", email, " not found.")
	}
	ulen := len(v.users)

	// 保存被删除用户的 email，用于清理 hotCache
	deletedEmail := v.users[idx].Email

	v.users[idx] = v.users[ulen-1]
	v.users[ulen-1] = nil
	v.users = v.users[:ulen-1]

	// 删除 hotCache 中对应的条目
	v.deleteHotCache(deletedEmail)

	return nil
}

func (v *Validator) deleteHotCache(email string) {
	for i, user := range v.hotCache {
		if user.Email == email {
			// 从 slice 中删除元素
			v.hotCache = append(v.hotCache[:i], v.hotCache[i+1:]...)
			break
		}
	}
}

func (v *Validator) addToHotCache(user *protocol.MemoryUser) {
	// 检查用户是否已经在 hotCache 中
	for _, cachedUser := range v.hotCache {
		if cachedUser.Email == user.Email {
			return // 已存在，不需要重复添加
		}
	}

	// 添加到 hotCache 开头（最近使用的用户）
	v.hotCache = append([]*protocol.MemoryUser{user}, v.hotCache...)
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

// Get 根据传入的数据包获取匹配的 Shadowsocks 用户
// 参数:
//   - bs: 接收到的数据包字节数组
//   - command: 请求命令类型 (TCP/UDP)
//
// 返回值:
//   - u: 匹配的用户对象
//   - aead: AEAD 加密器 (仅 AEAD 模式)
//   - ret: 解密后的数据
//   - ivLen: 初始化向量长度
//   - err: 错误信息
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	// 获取读锁，允许多个并发读取
	v.RLock()
	defer v.RUnlock()

	// 首先检查 hotCache 中的用户
	for _, user := range v.hotCache {
		account, ok := user.Account.(*MemoryAccount)
		if !ok {
			continue // 跳过无效账户类型
		}
		if account.Cipher.IsAEAD() {
			// AEAD 模式：需要至少 32 字节的数据包才能进行解密
			if len(bs) < 32 {
				continue
			}

			// 获取 AEAD 加密器
			aeadCipher, ok := account.Cipher.(*AEADCipher)
			if !ok {
				continue // 跳过无效加密器类型
			}
			// 获取初始化向量长度
			ivLen = aeadCipher.IVSize()
			// 检查数据包长度是否足够
			if len(bs) < int(ivLen) {
				continue
			}
			// 从数据包开头提取初始化向量
			iv := bs[:ivLen]

			// 创建子密钥缓冲区
			subkey := make([]byte, 32)
			subkey = subkey[:aeadCipher.KeyBytes]
			// 使用 HKDF-SHA1 从主密钥和 IV 生成子密钥
			hkdfSHA1(account.Key, iv, subkey)
			// 创建 AEAD 认证加密器
			aead = aeadCipher.AEADAuthCreator(subkey)

			var matchErr error
			// 根据协议类型进行不同的解密处理
			switch command {
			case protocol.RequestCommandTCP:
				// TCP 模式：解密前 18 字节的数据
				data := make([]byte, 4+aead.NonceSize())
				ret, matchErr = aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
			case protocol.RequestCommandUDP:
				// UDP 模式：解密整个数据包
				data := make([]byte, 8192)
				ret, matchErr = aead.Open(data[:0], data[8192-aead.NonceSize():8192], bs[ivLen:], nil)
			}

			// 如果解密成功，返回匹配的用户
			if matchErr == nil {
				u = user
				// 检查 IV 是否有效（防止重放攻击）
				err = account.CheckIV(iv)
				return
			}
		} else {
			// 非 AEAD 模式：直接返回用户（单用户模式）
			u = user
			ivLen = user.Account.(*MemoryAccount).Cipher.IVSize()
			return
		}
	}

	// 遍历所有用户，尝试匹配
	for _, user := range v.users {
		account, ok := user.Account.(*MemoryAccount)
		if !ok {
			continue // 跳过无效账户类型
		}
		if account.Cipher.IsAEAD() {
			// AEAD 模式：需要至少 32 字节的数据包才能进行解密
			if len(bs) < 32 {
				continue
			}

			// 获取 AEAD 加密器
			aeadCipher, ok := account.Cipher.(*AEADCipher)
			if !ok {
				continue // 跳过无效加密器类型
			}
			// 获取初始化向量长度
			ivLen = aeadCipher.IVSize()
			// 检查数据包长度是否足够
			if len(bs) < int(ivLen) {
				continue
			}
			// 从数据包开头提取初始化向量
			iv := bs[:ivLen]

			// 创建子密钥缓冲区
			subkey := make([]byte, 32)
			subkey = subkey[:aeadCipher.KeyBytes]
			// 使用 HKDF-SHA1 从主密钥和 IV 生成子密钥
			hkdfSHA1(account.Key, iv, subkey)
			// 创建 AEAD 认证加密器
			aead = aeadCipher.AEADAuthCreator(subkey)

			var matchErr error
			// 根据协议类型进行不同的解密处理
			switch command {
			case protocol.RequestCommandTCP:
				// TCP 模式：解密前 18 字节的数据
				data := make([]byte, 4+aead.NonceSize())
				ret, matchErr = aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
			case protocol.RequestCommandUDP:
				// UDP 模式：解密整个数据包
				data := make([]byte, 8192)
				ret, matchErr = aead.Open(data[:0], data[8192-aead.NonceSize():8192], bs[ivLen:], nil)
			}

			// 如果解密成功，返回匹配的用户
			if matchErr == nil {
				u = user
				// 检查 IV 是否有效（防止重放攻击）
				err = account.CheckIV(iv)

				// 将用户添加到 hotCache（需要写锁）
				v.addToHotCache(user)
				return
			}
		} else {
			// 非 AEAD 模式：直接返回用户（单用户模式）
			u = user
			ivLen = user.Account.(*MemoryAccount).Cipher.IVSize()
			// 注释掉的 IV 检查：None 加密的 IV 大小为 0
			// err = user.Account.(*MemoryAccount).CheckIV(bs[:ivLen])
			return
		}
	}

	// 没有找到匹配的用户
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
