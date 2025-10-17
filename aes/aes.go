package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// sha256 加密
func Sha256Key(key string) []byte {
	sum := sha256.Sum256([]byte(key))
	return sum[:]
}

// 进行 PKCS7 填充
func PKCS7Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	return append(src, bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)...)
}

// 移除 PKCS7 填充
func PKCS7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, errors.New("encrypted data is empty")
	}

	unpadding := int(src[length-1])
	if unpadding > length || unpadding == 0 {
		return nil, errors.New("invalid padding size")
	}

	for i := length - unpadding; i < length; i++ {
		if src[i] != byte(unpadding) {
			return nil, errors.New("invalid padding")
		}
	}
	return src[:(length - unpadding)], nil
}

// 加密
func AesEncrypt(text, key string) (string, error) {
	newKey := Sha256Key(key)
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return "", err
	}

	paddedPlaintext := PKCS7Padding([]byte(text), block.BlockSize())
	ciphertext := make([]byte, aes.BlockSize+len(paddedPlaintext))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(ciphertext[aes.BlockSize:], paddedPlaintext)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// 解密
func AesDecrypt(text, key string) (string, error) {
	newKey := Sha256Key(key)
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return "", err
	}

	decodedCiphertext, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}

	if len(decodedCiphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := decodedCiphertext[:aes.BlockSize]

	decodedCiphertext = decodedCiphertext[aes.BlockSize:]
	if len(decodedCiphertext)%block.BlockSize() != 0 {
		return "", errors.New("plaintext is not a multiple of the block size")
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(decodedCiphertext))
	blockMode.CryptBlocks(plaintext, decodedCiphertext)

	unpaddedPlaintext, err := PKCS7UnPadding(plaintext)
	if err != nil {
		return "", err
	}
	return string(unpaddedPlaintext), nil
}
