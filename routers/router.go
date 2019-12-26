// @APIVersion 1.0.0
// @Title beego Test API
// @Description beego has a very cool tools to autogenerate documents for your API
// @Contact astaxie@gmail.com
// @TermsOfServiceUrl http://beego.me/
// @License Apache 2.0
// @LicenseUrl http://www.apache.org/licenses/LICENSE-2.0.html
package routers

import (
	"github.com/CMLiang/zeusclient-go/controllers"

	"github.com/astaxie/beego"
)

func init() {
	// router增加一个拦截器，更多使用方法见https://beego.me/docs/mvc/controller/filter.md
	beego.InsertFilter("/*", beego.BeforeExec, controllers.FilterToken, true, false)
	ns := beego.NewNamespace("/v1",

		beego.NSNamespace("/base",
			beego.NSInclude(
				&controllers.BaseController{},
			),
		),
	)
	beego.AddNamespace(ns)
}
