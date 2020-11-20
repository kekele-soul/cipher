package util

import (
	"bytes"
)
/**
 *为加密文件进pkcs5进行尾部填充
 */

func Pkcs5Padding (data []byte, blockSize int ) []byte{
	//计算填充多少
	size :=blockSize-len(data) % blockSize
	//fmt.Println("size:",size)
	//准备要填充的内容
	paddingTex :=bytes.Repeat([]byte{byte(size)},size)
	//fmt.Println("paddingTex:", paddingTex)
	//填充
	return append(data,paddingTex...)
}
//去除pkcs5尾部填充
func ClearPacs5padding(data []byte,blockSize int) []byte{
	//claerize := int(data[len(data)-1)]
	clearSize := int(data[len(data)-1])
	return data[:len(data)-clearSize]
}
/**
 *为加密文件进行zeros填充
 */

func ZerosPadding (data []byte,blockSize int) []byte {
	//计算填充多少
	size := blockSize - len(data) % blockSize
	//准备要填充的内容
	paddingTex := bytes.Repeat([]byte{byte(0)},size)
	//填充
	return append(data,paddingTex...)
}
//去除Zeros尾部填充
func ClearZerosPadding(data []byte,blockSize int) []byte{
	size1 := blockSize - len(data) % blockSize
	return data[:len(data)-size1]
}