package utils

import (
	"crypto/tls"
	"log"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/httplib"
)

var (
	CENTER_SERVICE string = beego.AppConfig.String("center_service")
	DOMAIN         string = beego.AppConfig.String("domain")
)

type PermCenter struct {
	AccessToken string `json:"access_token"`
}

func NewPermCenter(accessToken string) *PermCenter {
	pc := new(PermCenter)
	pc.AccessToken = accessToken
	return pc
}

/**
 * 检查权限
 */
func (pc *PermCenter) CheckPerm(perm string) bool {
	req := httplib.Post(CENTER_SERVICE + "/user/perm/check")
	req.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	req.Header("Authorization", "Bearer "+pc.AccessToken)
	req.Param("perm", perm)
	req.Param("domain", DOMAIN)
	result := make(map[string]interface{})
	err := req.ToJSON(&result)
	if err != nil {
		log.Println("查询出错：", err)
		return false
	}
	if code, ok := result["code"]; ok {
		if code == "0" {
			return true
		}
	}
	return false
}
