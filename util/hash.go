package util

import (
	"crypto/md5"
	"crypto/sha256"
)

func HashMd5(data []byte) []byte{
	hashMd5 := md5.New()
	hashMd5.Write(data)
	return hashMd5.Sum(nil)
}
func HashSha256(data []byte) []byte{
	hashSha256 :=sha256.New()
	hashSha256.Write(data)
	return hashSha256.Sum(nil)
	
}
