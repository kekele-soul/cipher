package des

import (
	"cipher/util"
	"crypto/cipher"
	"crypto/des"
)
/**
 *des加密
 */
func DESEnCrypt(data []byte ,key []byte)([]byte,error){
	//block,err :=des.NewCipher(key)
	//if err != nil {
	//	return nil,err
	//}
	////填充边距
	//dataText :=util.Pkcs5Padding(data, block.BlockSize())
	//blockMone :=cipher.NewCBCEncrypter(block,key)
	//dst := make([]byte,len(dataText))
	//blockMone.CryptBlocks(dst,dataText)
	//return dst,nil
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//对明文进行尾部填充
	originText := util.Pkcs5Padding(data, block.BlockSize())
	//fmt.Println("**********************","originText:",originText,len(originText))
	//mode
	blockMode := cipher.NewCBCEncrypter(block, key)
	cipherText := make([]byte, len(originText))
	blockMode.CryptBlocks(cipherText, originText)
	return cipherText, nil
}
/**
 *des解密
 */
func DESDeCrypt (data []byte,key []byte)([]byte,error){
	block,err :=des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMone :=cipher.NewCBCDecrypter(block,key)
	original :=make([]byte,len(data))
	blockMone.CryptBlocks(original,data)
	//去除尾部边距
	original = util.Pkcs5Padding(original,block.BlockSize())
	return original,nil
}
