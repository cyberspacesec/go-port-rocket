package fingerprint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// FileDB 基于文件的指纹数据库实现
type FileDB struct {
	osFingerprints      []OSFingerprint
	serviceFingerprints []ServiceFingerprint
	osDBPath            string
	serviceDBPath       string
}

// NewFileDB 创建新的文件数据库
func NewFileDB(osDBPath, serviceDBPath string) *FileDB {
	return &FileDB{
		osDBPath:      osDBPath,
		serviceDBPath: serviceDBPath,
	}
}

// LoadOSFingerprints 加载操作系统指纹
func (db *FileDB) LoadOSFingerprints() error {
	data, err := os.ReadFile(db.osDBPath)
	if err != nil {
		if os.IsNotExist(err) {
			// 如果文件不存在，创建空数据库
			db.osFingerprints = make([]OSFingerprint, 0)
			return db.SaveOSFingerprints()
		}
		return err
	}

	return json.Unmarshal(data, &db.osFingerprints)
}

// SaveOSFingerprints 保存操作系统指纹
func (db *FileDB) SaveOSFingerprints() error {
	// 确保目录存在
	dir := filepath.Dir(db.osDBPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(db.osFingerprints, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(db.osDBPath, data, 0644)
}

// AddOSFingerprint 添加操作系统指纹
func (db *FileDB) AddOSFingerprint(fp *OSFingerprint) error {
	// 检查是否已存在
	for i, existing := range db.osFingerprints {
		if existing.Name == fp.Name && existing.Version == fp.Version {
			// 更新现有指纹
			db.osFingerprints[i] = *fp
			return db.SaveOSFingerprints()
		}
	}

	// 添加新指纹
	db.osFingerprints = append(db.osFingerprints, *fp)
	return db.SaveOSFingerprints()
}

// MatchOSFingerprint 匹配操作系统指纹
func (db *FileDB) MatchOSFingerprint(fp *OSFingerprint) ([]OSFingerprint, error) {
	matches := make([]OSFingerprint, 0)

	for _, existing := range db.osFingerprints {
		// 计算匹配度
		confidence := calculateOSMatch(fp, &existing)
		if confidence > 0 {
			existing.Confidence = confidence
			matches = append(matches, existing)
		}
	}

	// 按置信度排序
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Confidence > matches[j].Confidence
	})

	return matches, nil
}

// LoadServiceFingerprints 加载服务指纹
func (db *FileDB) LoadServiceFingerprints() error {
	data, err := os.ReadFile(db.serviceDBPath)
	if err != nil {
		if os.IsNotExist(err) {
			// 如果文件不存在，创建空数据库
			db.serviceFingerprints = make([]ServiceFingerprint, 0)
			return db.SaveServiceFingerprints()
		}
		return err
	}

	return json.Unmarshal(data, &db.serviceFingerprints)
}

// SaveServiceFingerprints 保存服务指纹
func (db *FileDB) SaveServiceFingerprints() error {
	// 确保目录存在
	dir := filepath.Dir(db.serviceDBPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(db.serviceFingerprints, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(db.serviceDBPath, data, 0644)
}

// AddServiceFingerprint 添加服务指纹
func (db *FileDB) AddServiceFingerprint(fp *ServiceFingerprint) error {
	// 检查是否已存在
	for i, existing := range db.serviceFingerprints {
		if existing.Name == fp.Name && existing.Version == fp.Version {
			// 更新现有指纹
			db.serviceFingerprints[i] = *fp
			return db.SaveServiceFingerprints()
		}
	}

	// 添加新指纹
	db.serviceFingerprints = append(db.serviceFingerprints, *fp)
	return db.SaveServiceFingerprints()
}

// MatchServiceFingerprint 匹配服务指纹
func (db *FileDB) MatchServiceFingerprint(fp *ServiceFingerprint) ([]ServiceFingerprint, error) {
	matches := make([]ServiceFingerprint, 0)

	for _, existing := range db.serviceFingerprints {
		// 计算匹配度
		confidence := calculateServiceMatch(fp, &existing)
		if confidence > 0 {
			existing.Confidence = confidence
			matches = append(matches, existing)
		}
	}

	// 按置信度排序
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Confidence > matches[j].Confidence
	})

	return matches, nil
}

// calculateOSMatch 计算操作系统指纹匹配度
func calculateOSMatch(fp1, fp2 *OSFingerprint) float64 {
	confidence := 0.0
	totalWeight := 0.0

	// 比较特征
	for key, value1 := range fp1.Features {
		if value2, exists := fp2.Features[key]; exists {
			if value1 == value2 {
				confidence += 1.0
			}
			totalWeight += 1.0
		}
	}

	// 如果没有匹配的特征，返回0
	if totalWeight == 0 {
		return 0
	}

	// 计算置信度百分比
	return (confidence / totalWeight) * 100
}

// calculateServiceMatch 计算服务指纹匹配度
func calculateServiceMatch(fp1, fp2 *ServiceFingerprint) float64 {
	confidence := 0.0
	totalWeight := 0.0

	// 比较特征
	for key, value1 := range fp1.Features {
		if value2, exists := fp2.Features[key]; exists {
			if value1 == value2 {
				confidence += 1.0
			}
			totalWeight += 1.0
		}
	}

	// 如果没有匹配的特征，返回0
	if totalWeight == 0 {
		return 0
	}

	// 计算置信度百分比
	return (confidence / totalWeight) * 100
}
