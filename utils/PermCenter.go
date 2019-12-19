package utils

import (
	"crypto/tls"
	"log"

	"github.com/astaxie/beego/httplib"
)

const (
	CENTER_SERVICE string = "http://api.admin.bullteam.cn"
)

var (
	accessToken, domain string
)

type PermCenter struct {
	AccessToken string `json:"access_token"`
	Domain      string `json:"domain"`
}

func NewPermCenter(accessToken, domain string) *PermCenter {
	pc := new(PermCenter)
	pc.AccessToken = accessToken
	pc.Domain = domain
	return pc
}

/**
 * 检查权限
 */
func (pc *PermCenter) checkPerm(perm string) bool {
	req := httplib.Post(CENTER_SERVICE + "/user/perm/check")
	req.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	req.Header("Authorization", "Bearer"+pc.AccessToken)
	req.Param("perm", perm)
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
