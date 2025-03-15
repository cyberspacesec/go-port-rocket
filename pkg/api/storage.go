package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// StorageInterface 定义存储接口，兼容Redis和内存存储
type StorageInterface interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	ScanKeys(ctx context.Context, pattern string) ([]string, error)
	Close() error
}

// MemoryStorage 内存存储实现
type MemoryStorage struct {
	data  map[string]storageItem
	mutex sync.RWMutex
}

// storageItem 存储项
type storageItem struct {
	value      string
	expiration time.Time
}

// NewMemoryStorage 创建内存存储
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		data: make(map[string]storageItem),
	}
}

// Set 设置值
func (m *MemoryStorage) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var expirationTime time.Time
	if expiration > 0 {
		expirationTime = time.Now().Add(expiration)
	}

	// 转换值为字符串
	strValue, ok := value.(string)
	if !ok {
		return fmt.Errorf("value must be string")
	}

	m.data[key] = storageItem{
		value:      strValue,
		expiration: expirationTime,
	}

	return nil
}

// Get 获取值
func (m *MemoryStorage) Get(ctx context.Context, key string) (string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	item, exists := m.data[key]
	if !exists {
		return "", errors.New("key not found")
	}

	// 检查过期时间
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		delete(m.data, key)
		return "", errors.New("key expired")
	}

	return item.value, nil
}

// ScanKeys 扫描匹配的键
func (m *MemoryStorage) ScanKeys(ctx context.Context, pattern string) ([]string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 获取匹配的键
	var matchedKeys []string
	pattern = strings.ReplaceAll(pattern, "*", "")
	for key := range m.data {
		if strings.Contains(key, pattern) {
			matchedKeys = append(matchedKeys, key)
		}
	}

	return matchedKeys, nil
}

// Close 关闭存储
func (m *MemoryStorage) Close() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.data = make(map[string]storageItem)
	return nil
}
