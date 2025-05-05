package tasks

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/songquanpeng/one-api/common/logger"
	"github.com/songquanpeng/one-api/model"
)

const cozeTokenURL = "https://api.coze.cn/api/permission/oauth2/token"

// 获取私钥
func getPrivateKey() (*rsa.PrivateKey, error) {
	privateKeyPEM := os.Getenv("COZE_PRIVATE_KEY")
	if privateKeyPEM == "" {
		return nil, errors.New("COZE_PRIVATE_KEY environment variable not set")
	}

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("failed to parse private key PEM block")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}

	rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}

	return rsaPrivKey, nil
}

// 生成 JWT
func generateJWT() (string, error) {
	privateKey, err := getPrivateKey()
	if err != nil {
		return "", fmt.Errorf("getPrivateKey failed: %w", err)
	}

	appID := os.Getenv("COZE_APP_ID")
	if appID == "" {
		return "", errors.New("COZE_APP_ID environment variable not set")
	}

	kid := os.Getenv("COZE_KID")
	if kid == "" {
		return "", errors.New("COZE_KID environment variable not set")
	}

	sessionName := fmt.Sprintf("session-%s", uuid.New().String())

	claims := jwt.MapClaims{
		"iss":          appID,
		"aud":          "api.coze.cn",
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(time.Hour).Unix(),
		"jti":          fmt.Sprintf("%d", time.Now().UnixNano()),
		"session_name": sessionName,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("signing JWT failed: %w", err)
	}
	return signedToken, nil
}

// 请求 access_token
func requestAccessToken(jwtToken string) (string, error) {
	data := map[string]interface{}{
		"duration_seconds": 86399,
		"grant_type":       "urn:ietf:params:oauth:grant-type:jwt-bearer",
	}
	jsonData, _ := json.Marshal(data)

	req, _ := http.NewRequest("POST", cozeTokenURL, bytes.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	logger.SysLogf("access token request response: %s", string(body))

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("token request failed, status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	logger.SysLogf("Access Token: %s, Expires In: %d", result.AccessToken, result.ExpiresIn)
	return result.AccessToken, nil
}

// 更新渠道表
func updateChannelKey(token string) error {
	logger.SysLogf("updating channel key in database...")
	result := model.DB.Exec("UPDATE channels SET `key` = ? WHERE name like '%coze%'", token)
	if result.Error != nil {
		return fmt.Errorf("database update failed: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.New("no rows affected in database update, 'coze' channel might not exist")
	}
	return nil
}

// 刷新 Coze Token 主流程
func refreshCoze() {
	var lastErr error
	for i := 0; i < 3; i++ {
		logger.SysLogf("========== Refresh attempt #%d ==========", i+1)

		jwtToken, err := generateJWT()
		if err != nil {
			logger.SysLogf("generateJWT failed: %v", err)
			lastErr = err
			continue
		}
		logger.SysLogf("generateJWT succeeded")

		accessToken, err := requestAccessToken(jwtToken)
		if err != nil {
			logger.SysLogf("requestAccessToken failed: %v", err)
			lastErr = err
			continue
		}
		logger.SysLogf("requestAccessToken succeeded")

		err = updateChannelKey(accessToken)
		if err != nil {
			logger.SysLogf("updateChannelKey failed: %v", err)
			lastErr = err
			continue
		}

		logger.SysLogf("Coze token refreshed and saved to DB successfully")
		logger.SysLogf("Coze token is : " + accessToken)
		return
	}

	logger.SysLogf("refreshCoze failed after 3 attempts: %v", lastErr)
}

// 定时任务入口
func RefreshCozeTokenTask() {
	ticker := time.NewTicker(12 * time.Hour)
	// ticker := time.NewTicker(1 * time.Minute) // 用于调试
	go func() {
		refreshCoze() // 启动先执行一次
		for range ticker.C {
			refreshCoze()
		}
	}()
}
