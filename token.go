package common

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

//用于jwt签名的secret
var SECRET_KEY = []byte("hi this is Marco-X,welcome!")

//生成token
type TOKEN_TYPE int

const (
	TOKEN_TYPE_ACCESS TOKEN_TYPE = iota
	TOKEN_TYPE_REFRESH
)

type MyCustomClaims struct {
	Uid uint64 `json:"uid"`
	jwt.StandardClaims
}

func GenerateToken(uid uint64, tokenType TOKEN_TYPE) (err error, token string) {
	var expireSecs int64
	switch tokenType {
	case TOKEN_TYPE_ACCESS:
		{
			expireSecs = Cursvr.AccessTokenExpiredSecs
		}
	case TOKEN_TYPE_REFRESH:
		{
			expireSecs = Cursvr.RefreshTokenExpiredSecs
		}
	}

	//生成jwt token
	claims := MyCustomClaims{
		uid,
		jwt.StandardClaims{
			Id:        fmt.Sprint(uid),
			NotBefore: int64(time.Now().Unix()),
			ExpiresAt: int64(time.Now().Unix() + expireSecs),
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err = t.SignedString(SECRET_KEY)
	if err != nil {
		LOG_FUNC_ERROR("生成token失败 : %v", err)
		return
	}

	return
}

//校验token是否过期
func CheckToken(tokenType TOKEN_TYPE, token string) (bool, uint64) {
	//校验签名是否正确
	err, t := ParseToken(token)
	if err != nil {
		return false, 0
	}

	if claims, ok := t.Claims.(*MyCustomClaims); ok && t.Valid {
		//校验与当前缓存中的token是否一致
		if !checkTokenSignature(tokenType, claims.Uid, t.Signature) {
			return false, 0
		}

		return true, claims.Uid
	} else {
		LOG_FUNC_ERROR("解析token失败 %v", err)
		return false, 0
	}
}

//获取token中的uid，不管是否过期
func GetUidFromToken(token string) (uid uint64) {
	//校验签名是否正确
	t, _ := jwt.ParseWithClaims(token, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return SECRET_KEY, nil
	})

	if claims, ok := t.Claims.(*MyCustomClaims); ok {
		return claims.Uid
	}

	return
}

//校验token是否有效
func checkTokenSignature(tokenType TOKEN_TYPE, uid uint64, signature string) bool {
	var index CACHE_INDEX
	switch tokenType {
	case TOKEN_TYPE_ACCESS:
		{
			index = CACHE_INDEX_ACCESS_TOKEN
		}
	case TOKEN_TYPE_REFRESH:
		{
			index = CACHE_INDEX_REFRESH_TOKEN
		}
	default:
		return false
	}

	//从缓存中获取当前的token签名
	err, v := MEMORYCACHE_GET(index, fmt.Sprint(uid))
	if err != nil {
		LOG_FUNC_ERROR("从缓存中获取用户 %d 的token(%d) 失败 : %v", uid, index, err)
		return false
	}

	if v == nil {
		LOG_FUNC_ERROR("未获取到用户 %d 的token(%d)", uid, index)
		return false
	}

	item, ok := v.(*TokenMemItem)
	if !ok || item == nil {
		LOG_FUNC_ERROR("转换用户 %d 的token(%v) 失败 : %v", uid, v)
		return false
	}

	//校验是否匹配
	if signature != item.Signature() {
		LOG_FUNC_WARNING("用户%d请求签名(%s)和缓存中的签名(%s)不匹配，可能存在账号信息泄漏，请确认！", uid, signature, item.Signature())
		return false
	}

	return true
}

func ParseToken(tokenStr string) (err error, t *jwt.Token) {
	//校验签名是否正确
	t, err = jwt.ParseWithClaims(tokenStr, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return SECRET_KEY, nil
	})

	if err != nil {
		LOG_FUNC_ERROR("解析token失败 ： %v %v", t, err)
		return err, nil
	}

	return
}

type TokenMemItem struct {
	signature string
}

func NewTokenMemItem(signature string) *TokenMemItem {
	return &TokenMemItem{
		signature: signature,
	}
}

func (this *TokenMemItem) Signature() string {
	return this.signature
}
