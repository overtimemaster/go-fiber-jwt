/*
 * @Author       : email:overtimemaster-cn@outlook.com vx:overtimemaster
 * @Date         : 2022-03-24 11:19:05
 * @Description  : fiber + jwt 示例
 */
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	jwtware "github.com/gofiber/jwt/v3"
	"github.com/golang-jwt/jwt/v4"
)

//定义加密key值 HS256
var jwtkey = []byte("test")

// RS256 加密算法
//声明私钥变量
var private_key *rsa.PrivateKey

//声明公钥变量
var public_key crypto.PublicKey

func main() {
	app := fiber.New(fiber.Config{
		Prefork:       true,
		CaseSensitive: true,
		StrictRouting: true,
		ServerHeader:  "OvertimeMaster Server,VX:overtimemaster",
		AppName:       "fiber-jwt v1.0.0",
	})
	app.Use(cors.New(cors.ConfigDefault))
	app.Use(logger.New())
	// 获取token
	app.Post("/api/get-token", getToken)

	// 以上无需token验证即可访问
	app.Use(jwtware.New(jwtware.Config{
		SigningMethod: "RS256",
		SigningKey:    getPublicKey(),
	}))

	// 以下访问需要token验证
	app.Post("/api/get-userinfo", returnUserInfo)
	app.Listen(":6688")
}

/**
 * @description: 颁发token
 * @param {*}
 * @return {*}
 * @author: email:overtimemaster-cn@outlook.com vx:overtimemaster
 */
func getToken(c *fiber.Ctx) error {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var body request
	err := c.BodyParser(&body)
	// 判断提交过来的数据是否能解析为json
	if err != nil {
		c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "无法解析为json",
		})
		return nil
	}

	// 判断提交过来的用户名密码是否正确
	if body.Email != "overtimemaster-cn@outlook.com" || body.Password != "password123" {
		c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "用户名不存在或密码错误",
		})
		return nil
	}

	// 配置声明
	claims := jwt.MapClaims{
		"name":  "overtimemaster",
		"admin": true,
		"exp":   time.Now().Add(time.Hour * 72).Unix(), //过期时间设置为一周
	}
	// 生成token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// 使用加密
	t, err := token.SignedString(private_key)
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	return c.JSON(fiber.Map{"token": t})

}

// 返回用户数据
func returnUserInfo(c *fiber.Ctx) error {
	user := c.Locals("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	// name := claims["name"].(string)
	return c.JSON(fiber.Map{
		"msg":   "登录成功",
		"name":  claims["name"],
		"admin": claims["admin"],
	})
}

//生成公钥
func getPublicKey() crypto.PublicKey {
	//生成私钥
	rng := rand.Reader
	private_key, _ = rsa.GenerateKey(rng, 2048)
	//生成公钥
	public_key = private_key.Public()
	return public_key
}
