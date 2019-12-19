package controllers

import (
	"github.com/astaxie/beego"
	"github.com/dgrijalva/jwt-go"
)

// TokenClaimsControllers operations for TokenClaims
type TokenClaimsControllers struct {
	BaseController
}

func (c *TokenClaimsControllers) GetTokenClaims() {
	//get token
	token, e := c.ParseToken()
	if e != nil {
		beego.Debug("ParseToken error")
		c.jsonResult(400, "ParseToken error", e)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		beego.Debug("get ParseToken claims error")
		c.jsonResult(400, "get ParseToken claims error", nil)
	}
	beego.Debug("claims:", claims)
	var Email string = claims["Email"].(string)
	beego.Debug("Email:", Email)
	c.jsonResult(200, "TokenClaims", claims)
}
