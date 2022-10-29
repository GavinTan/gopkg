package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Sha256Key sha256 加密
func Sha256Key(key string) []byte {
	h := sha256.New()
	h.Write([]byte(key))
	newKey := h.Sum(nil)
	return newKey
}

// PKCS7Padding 填充数据
func PKCS7Padding(src []byte) []byte {
	bs := aes.BlockSize
	length := len(src)
	if length == 0 {
		return nil
	}

	paddingSize := bs - len(src)%bs
	if paddingSize == 0 {
		paddingSize = bs
	}

	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(src, paddingText...)
}

// PKCS7UnPadding 放出数据
func PKCS7UnPadding(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return nil
	}

	unpadding := int(src[length-1])
	if length-unpadding < 0 {
		return nil
	}
	return src[:(length - unpadding)]
}

// AesEncrypt 加密
func AesEncrypt(src, key string) (string, error) {
	newKey := Sha256Key(key)
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return "", err
	}
	newsrc := []byte(src)
	newsrc = PKCS7Padding(newsrc)
	blockMode := cipher.NewCBCEncrypter(block, newKey[:16])
	crypted := make([]byte, len(newsrc))
	blockMode.CryptBlocks(crypted, newsrc)
	return base64.StdEncoding.EncodeToString(crypted), nil
}

// AesDecrypt 解密
func AesDecrypt(crypted, key string) (string, error) {
	newKey := Sha256Key(key)
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return "", err
	}
	newCrypted, _ := base64.StdEncoding.DecodeString(crypted)
	if len(newCrypted)%block.BlockSize() != 0 {
		return "", errors.New("无效的解密字符串")
	}

	blockMode := cipher.NewCBCDecrypter(block, newKey[:16])
	src := make([]byte, len(newCrypted))
	blockMode.CryptBlocks(src, newCrypted)
	src = PKCS7UnPadding(src)
	return string(src), nil
}
