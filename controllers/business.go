package controllers

import (
	"github.com/CMLiang/zeusclient-go/utils"
	"github.com/astaxie/beego"
)

// TokenClaimsControllers operations for TokenClaims
type BusinessControllers struct {
	BaseController
}

/*
	下面是业务Controllers获取JWTClaims的示例
	1、调用BaseController的ParseClaims()方法，返回的是map[string]interface{}或nil
	2、如果为nil，则其中发生了错误
	3、如果非nil，则可以通过map的形式获取value，注意类型断言
*/
func (c *BusinessControllers) GetTokenClaims() {
	//get claims
	claims := c.ParseClaims()
	if claims == nil {
		c.jsonResult(400, "JWTClaims为空！", nil)
	}
	var userName string = claims["Name"].(string)
	beego.Debug("UserName:", userName)
	c.jsonResult(200, "JWTClaims", claims)
}

/*
	下面是业务Controllers获取CheckPerm的示例
	1、调用BaseController的GetAccessToken()方法，返回的是string或""
	2、如果为""，则其中发生了错误
	3、如果非""，则调用utils包的NewPermCenter()方法，返回PermCenter对象
	4、用PermCenter对象调用CheckPerm获取通行boolen值
*/
func (c *BusinessControllers) CheckPerm() {
	route := RecoverRoute(c.Ctx)
	act := c.GetAccessToken()
	pc := utils.NewPermCenter(act)
	via := pc.CheckPerm(route)
	if !via {
		c.jsonResult(400, "检测权限不通过，没有权限！", nil)
	}
}
