package shadowsocks

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash/crc64"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid Shadowsocks users.
type Validator struct {
	users sync.Map // 使用 sync.Map 存储用户，key 为 email，value 为 *protocol.MemoryUser

	behaviorSeed  uint64
	behaviorFused bool

	hotCache sync.Map // 使用 sync.Map 存储热点用户，key 为 email，value 为 *protocol.MemoryUser
}

var ErrNotFound = errors.New("Not Found")

// Add a Shadowsocks user.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	account, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("invalid account type")
	}

	// 检查是否支持多用户
	if !account.Cipher.IsAEAD() {
		// 检查是否已有其他用户
		hasOtherUser := false
		v.users.Range(func(key, value interface{}) bool {
			hasOtherUser = true
			return false // 停止遍历
		})
		if hasOtherUser {
			return errors.New("The cipher is not support Single-port Multi-user")
		}
	}

	// 添加用户到 sync.Map
	v.users.Store(strings.ToLower(u.Email), u)

	// 更新 behavior seed
	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
		hashkdf.Write(account.Key)
		atomic.AddUint64(&v.behaviorSeed, crc64.Update(0, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil)))
	}

	fmt.Println("-------------------- hotCache init --------------------")
	return nil
}

// Del a Shadowsocks user with a non-empty Email.
func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	email = strings.ToLower(email)

	// 从 users 中删除
	if _, loaded := v.users.LoadAndDelete(email); !loaded {
		return errors.New("User ", email, " not found.")
	}

	// 从 hotCache 中删除
	v.hotCache.Delete(email)
	fmt.Println("-------------------- hotCache delete --------------------")

	return nil
}

// GetByEmail Get a Shadowsocks user with a non-empty Email.
func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	email = strings.ToLower(email)
	if user, ok := v.users.Load(email); ok {
		return user.(*protocol.MemoryUser)
	}
	return nil
}

// GetAll get all users
func (v *Validator) GetAll() []*protocol.MemoryUser {
	var users []*protocol.MemoryUser
	v.users.Range(func(key, value interface{}) bool {
		users = append(users, value.(*protocol.MemoryUser))
		return true
	})
	return users
}

// GetCount get users count
func (v *Validator) GetCount() int64 {
	var count int64
	v.users.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
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
	// 获取 hotCache 长度
	var cacheLen int64
	v.hotCache.Range(func(key, value interface{}) bool {
		cacheLen++
		return true
	})
	fmt.Println("-------------------- hotCache len --------------------", cacheLen)

	// 首先检查 hotCache 中的用户
	v.hotCache.Range(func(key, value interface{}) bool {
		user, ok := value.(*protocol.MemoryUser)
		if !ok {
			return true // 继续遍历，跳过无效类型
		}
		account, ok := user.Account.(*MemoryAccount)
		if !ok {
			return true // 继续遍历
		}

		if account.Cipher.IsAEAD() {
			// AEAD 模式：需要至少 32 字节的数据包才能进行解密
			if len(bs) < 32 {
				return true // 继续遍历
			}

			// 获取 AEAD 加密器
			aeadCipher, ok := account.Cipher.(*AEADCipher)
			if !ok {
				return true // 继续遍历
			}
			// 获取初始化向量长度
			ivLen = aeadCipher.IVSize()
			// 检查数据包长度是否足够
			if len(bs) < int(ivLen) {
				return true // 继续遍历
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
				fmt.Println("-------------------- 缓存命中 用户", user.Email, "--------------------")
				return false // 停止遍历
			}
		} else {
			// 非 AEAD 模式：直接返回用户（单用户模式）
			u = user
			ivLen = account.Cipher.IVSize() // 使用已检查的 account
			return false                    // 停止遍历
		}
		return true // 继续遍历
	})

	if u != nil {
		return // 在 hotCache 中找到匹配用户
	}

	fmt.Println("-------------------- 缓存未命中 --------------------")

	// 遍历所有用户，尝试匹配
	v.users.Range(func(key, value interface{}) bool {
		user, ok := value.(*protocol.MemoryUser)
		if !ok {
			return true // 继续遍历，跳过无效类型
		}
		account, ok := user.Account.(*MemoryAccount)
		if !ok {
			return true // 继续遍历
		}

		if account.Cipher.IsAEAD() {
			// AEAD 模式：需要至少 32 字节的数据包才能进行解密
			if len(bs) < 32 {
				return true // 继续遍历
			}

			// 获取 AEAD 加密器
			aeadCipher, ok := account.Cipher.(*AEADCipher)
			if !ok {
				return true // 继续遍历
			}
			// 获取初始化向量长度
			ivLen = aeadCipher.IVSize()
			// 检查数据包长度是否足够
			if len(bs) < int(ivLen) {
				return true // 继续遍历
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

				// 将用户添加到 hotCache
				v.hotCache.Store(user.Email, user)
				fmt.Println("-------------------- 缓存记录 用户", user.Email, "--------------------")
				return false // 停止遍历
			}
		} else {
			// 非 AEAD 模式：直接返回用户（单用户模式）
			u = user
			ivLen = account.Cipher.IVSize() // 使用已检查的 account
			return false                    // 停止遍历
		}
		return true // 继续遍历
	})

	// 没有找到匹配的用户
	if u == nil {
		return nil, nil, nil, 0, ErrNotFound
	}
	return
}

func (v *Validator) GetBehaviorSeed() uint64 {
	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}
