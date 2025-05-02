package tasks

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
		logger.FatalLog("COZE_PRIVATE_KEY environment variable not set")
		return nil, errors.New("private key not set")
	}

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil || block.Type != "PRIVATE KEY" {
		logger.FatalLog("failed to parse private key PEM block")
		return nil, errors.New("invalid private key format")
	}

	// 解析 PKCS#8 格式的私钥
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		logger.FatalLog("failed to parse PKCS8 private key: " + err.Error())
		return nil, errors.New("invalid private key format")
	}

	// 将解析得到的私钥类型转换为 rsa.PrivateKey
	rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		logger.FatalLog("private key is not RSA")
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
		logger.FatalLog("COZE_APP_ID environment variable not set")
		return "", errors.New("appID not set")
	}

	kid := os.Getenv("COZE_KID")
	if kid == "" {
		logger.FatalLog("COZE_KID environment variable not set")
		return "", errors.New("kid not set")
	}

	sessionName := fmt.Sprintf("session-%d", time.Now().UnixNano())

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

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("token request failed, status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("JSON unmarshal failed: %w", err)
	}
	return result.Data.AccessToken, nil
}

// 更新渠道表
func updateChannelKey(token string) error {
	logger.SysLogf("updating channel key in database...")
	result := model.DB.Exec("UPDATE channels SET `key` = ? WHERE name = 'coze'", token)
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
	var err error
	for i := 0; i < 3; i++ {
		logger.SysLogf("========== Refresh attempt #%d ==========", i+1)

		jwtToken, err := generateJWT()
		if err != nil {
			logger.FatalLog("generateJWT failed: %v" + err.Error())
			continue
		}
		logger.SysLogf("generateJWT succeeded")

		accessToken, err := requestAccessToken(jwtToken)
		if err != nil {
			logger.FatalLog("requestAccessToken failed: %v" + err.Error())
			continue
		}
		logger.SysLogf("requestAccessToken succeeded")

		err = updateChannelKey(accessToken)
		if err != nil {
			logger.FatalLog("updateChannelKey failed: %v" + err.Error())
			continue
		}
		logger.SysLogf("Coze token refreshed and saved to DB successfully")
		logger.SysLogf("Coze token is : " + accessToken)
		return
	}
	logger.FatalLog("refreshCoze failed after 3 attempts: " + fmt.Sprint(err))
}

// 定时任务
func RefreshCozeTokenTask() {
	ticker := time.NewTicker(10 * time.Hour)
	go func() {
		refreshCoze() // 启动时先执行一次
		for range ticker.C {
			refreshCoze() // 每 10 小时执行一次
		}
	}()
}
