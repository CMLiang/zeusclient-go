package controllers

import (
	"errors"
	"fmt"
	"strings"

	"github.com/astaxie/beego"
	"github.com/dgrijalva/jwt-go"
)

const (
	JWT_PUBLIC_KEY string = "-----BEGIN PUBLIC KEY-----\n" +
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/TYKuXsgYdoICfEZOiy1L12Cb\n" +
		"yPdudhrCjrjwVcIrhGNn6Udq/SY5rh0ixm09I2tXPWLYuA1R55kyeo5RPFX+FrD+\n" +
		"mQwfJkV/QfhaPsNjU4nCEHFMtrsYCcLYJs9uX0tJdAtE6sg/VSulg1aMqCNWvtVt\n" +
		"jrrVXSbu4zbyWzVkxQIDAQAB\n" +
		"-----END PUBLIC KEY-----"
)

type BaseController struct {
	beego.Controller
}

func (c *BaseController) Prepare() {
	//附值
	// c.controllerName, c.actionName = c.GetControllerAndAction()
	//从Session里获取数据 设置用户信息
	// c.adapterUserInfo()
}

// JsonResult 用于返回ajax请求的基类
type JsonResult struct {
	Code    int
	Message string
}

//返回json结果，并中断
func (c *BaseController) jsonResult(code int, msg string, data interface{}) {
	r := &JsonResult{Code: code, Message: msg}
	c.Data["json"] = map[string]interface{}{"Result": r, "Data": data}
	c.ServeJSON()
	c.StopRun()
}

//返回json更多结果，并中断
func (c *BaseController) jsonResultMore(code int, msg string, data interface{}, m interface{}) {
	r := &JsonResult{Code: code, Message: msg}
	c.Data["json"] = map[string]interface{}{"Result": r, "Data": data, "More": m}
	c.ServeJSON()
	c.StopRun()
}

//返回json分页结果，并中断
func (c *BaseController) jsonResultByPage(code int, msg string, data interface{}, p interface{}) {
	r := &JsonResult{Code: code, Message: msg}
	c.Data["json"] = map[string]interface{}{"Result": r, "Data": data, "Page": p}
	c.ServeJSON()
	c.StopRun()
}

// ParseToken parse JWT token in http header.
func (base *BaseController) ParseToken() (t *jwt.Token, e error) {
	authString := base.Ctx.Input.Header("Authorization")
	beego.Debug("AuthString:", authString)

	kv := strings.Split(authString, " ")
	if len(kv) != 2 || kv[0] != "Bearer" {
		beego.Error("AuthString invalid:", authString)
		return nil, errors.New("AuthString invalid:" + authString)
	}
	tokenString := kv[1]

	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 必要的验证 RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		//// 可选项验证  'aud' claim
		//aud := "https://api.cn.atomintl.com"
		//checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
		//if !checkAud {
		//  return token, errors.New("Invalid audience.")
		//}
		// 必要的验证 'iss' claim
		// iss := "https://atomintl.auth0.com/"
		// checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
		// if !checkIss {
		// 	return token, errors.New("Invalid issuer.")
		// }

		k5c := JWT_PUBLIC_KEY
		result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(k5c))
		//result := []byte(cert) // 不是正确的 PUBKEY 格式 都会 报  key is of invalid type
		return result, nil
	})
	if err != nil {
		beego.Error("Parse token:", err)
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				// That's not even a token
				return nil, errors.New("ValidationErrorMalformed")
			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				// Token is either expired or not active yet
				return nil, errors.New("ValidationErrorNotValidYet")
			} else {
				// Couldn't handle this token
				return nil, errors.New("ValidationErrorOther")
			}
		} else {
			// Couldn't handle this token
			return nil, errors.New("ValidationError")
		}
	}
	if !token.Valid {
		beego.Error("Token invalid:", tokenString)
		return nil, errors.New("Token invalid:" + tokenString)
	}
	beego.Debug("Token:", token)

	return token, nil
}
