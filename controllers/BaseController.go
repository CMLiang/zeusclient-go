package controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/dgrijalva/jwt-go"
)

var JWT_PUBLIC_KEY []byte

func init() {
	f, err := os.Open("keys/jwt_public_key.pem")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	fd, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}
	JWT_PUBLIC_KEY = fd
}

// Ignored FilterToken
var ignoredTokenRouter = map[string]bool{
	"get@/demo/:id": true,
}

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

func (base *BaseController) GetAccessToken() string {
	actData := base.Ctx.Input.GetData("JWTToken")
	act, ok := actData.(string)
	if ok {
		return act
	}
	return ""
}

// Parse JWTClaims in Ctx.Data["JWTClaims"]
func (base *BaseController) ParseClaims() map[string]interface{} {
	cl := base.Ctx.Input.GetData("JWTClaims")
	if cl != nil {
		clmap, ok := cl.(map[string]interface{})
		if ok {
			return clmap
		}
		return nil
	}
	return nil
}

// Recover Route
func RecoverRoute(ctx *context.Context) string {
	route := strings.Split(ctx.Request.URL.RequestURI(), "?")[0]
	// 将路径中的参数值替换为参数名
	for k, v := range ctx.Input.Params() {
		// 如果参数是 :splat等预定义的，则跳过
		if k == ":splat" || k == ":path" || k == ":ext" {
			continue
		}
		route = strings.Replace(route, "/"+v, "/"+k, 1)
	}
	// 路径格式均为 请求类型@路径
	route = strings.ToLower(ctx.Request.Method) + "@" + route
	return route
}

// 路由拦截器的Filter
var FilterToken = func(ctx *context.Context) {
	// 路径格式均为 请求类型@路径
	route := RecoverRoute(ctx)
	// 直接通过map查询是否忽略
	if _, ok := ignoredTokenRouter[route]; ok {
		return
	}
	authString := ctx.Input.Header("Authorization")
	beego.Debug("AuthString:", authString)

	kv := strings.Split(authString, " ")
	if len(kv) != 2 || kv[0] != "Bearer" {
		beego.Error("Authorization格式不对或Token为空！")
		http.Error(ctx.ResponseWriter, "Authorization格式不对或Token为空！", http.StatusUnauthorized)
		return
	}
	tokenString := kv[1]
	ctx.Input.SetData("JWTToken", tokenString)

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
		iss := "https://atomintl.auth0.com/"
		checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
		if !checkIss {
			return token, errors.New("Invalid issuer.")
		}

		result, _ := jwt.ParseRSAPublicKeyFromPEM(JWT_PUBLIC_KEY)
		//result := []byte(cert) // 不是正确的 PUBKEY 格式 都会 报  key is of invalid type
		return result, nil
	})
	if err != nil {
		beego.Error("Parse token error:", err)
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				// That's not even a token
				http.Error(ctx.ResponseWriter, "Token 格式有误！", http.StatusUnauthorized)
				return
			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				// Token is either expired or not active yet
				http.Error(ctx.ResponseWriter, "Token 已过期！", http.StatusUnauthorized)
				return
			} else {
				// Couldn't handle this token
				http.Error(ctx.ResponseWriter, "验证Token的过程中发生其他错误！", http.StatusUnauthorized)
				return
			}
		} else {
			// Couldn't handle this token
			http.Error(ctx.ResponseWriter, "无法处理此Token！", http.StatusUnauthorized)
			return
		}
	}
	if !token.Valid {
		beego.Error("Token invalid:", tokenString)
		http.Error(ctx.ResponseWriter, "Token 不合法:"+tokenString, http.StatusUnauthorized)
		return
	}
	beego.Debug("Token:", token)
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		beego.Debug("转换为jwt.MapClaims失败")
		return
	}
	var claimsMIF = make(map[string]interface{})
	jsonM, _ := json.Marshal(&claims)
	json.Unmarshal(jsonM, &claimsMIF)
	ctx.Input.SetData("JWTClaims", claimsMIF)
}
