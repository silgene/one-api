package tasks

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/songquanpeng/one-api/common/logger"
	"github.com/songquanpeng/one-api/model"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

const cozeTokenURL = "https://api.coze.cn/api/permission/oauth2/token"

// 获取私钥
func getPrivateKey() (*rsa.PrivateKey, error) {
	privateKeyPEM := os.Getenv("COZE_PRIVATE_KEY")
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// 生成jwt
func generateJWT() (string, error) {
	privateKey, err := getPrivateKey()
	if err != nil {
		return "", err
	}

	appID := os.Getenv("COZE_APP_ID")
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
	token.Header["kid"] = os.Getenv("COZE_KID") // 公钥

	return token.SignedString(privateKey)
}

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
		return "", err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("token request failed: %s", body)
	}

	var result struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	return result.Data.AccessToken, nil
}

func updateChannelKey(token string) error {
	return model.DB.Exec("UPDATE channels SET `key` = ? WHERE name = 'coze'", token).Error
}

func refreshCoze() {
	var err error
	for i := 0; i < 3; i++ {
		jwtToken, err := generateJWT()
		if err != nil {
			continue
		}
		accessToken, err := requestAccessToken(jwtToken)
		if err != nil {
			continue
		}
		err = updateChannelKey(accessToken)
		if err == nil {
			logger.SysLogf("refresh success")
			return
		}
	}
	logger.FatalLog("refresh error" + err.Error())
}

func RefreshCozeTokenTask() {
	ticker := time.NewTicker(10 * time.Hour)
	go func() {
		refreshCoze() // 启动时先执行一次
		for range ticker.C {
			refreshCoze() // 每 10 小时执行一次
		}
	}()
}
