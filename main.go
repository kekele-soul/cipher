package main

import (
	_des "cipher/3des"
	"cipher/des"
	"cipher/rsa"
	"fmt"
)

func main() {

/**
	des算法
 */
	key := []byte("20201112") //des秘钥长度：8
	data := "穷在闹市无人问，富在深山有远亲"
	//加密
	cipherText, err := des.DESEnCrypt([]byte(data), key)
	if err != nil {
		fmt.Println("加密失败：", err.Error())
		return
	}
	//解密
	original,err :=des.DESDeCrypt(cipherText,key)
	if err != nil {
		fmt.Println("解密失败",err.Error())
	}
	fmt.Println("des解密后的明文",string(original))

/**
 *3des算法
 */
	key1 :=[]byte("110011001100110011001100")
	data1 := "说话的方式简单点"
	//加密
	cipher1,err :=_des.TripleDesEncrypt([]byte(data1),key1)
	if err != nil {
		fmt.Println("加密失败",err.Error())
		return
	}
	fmt.Println("加密后的",string(cipher1))
	//解密
	originaln,err :=_des.TripleDesDecrypt(cipher1,key1)
	if err != nil {
		fmt.Println("解密失败",err.Error())
		return
	}
	fmt.Println("3des解密后的数据",string(originaln))


/**
 *调用rsa算法
 */
	//将私钥保存到文件中
	err =rsa.GenerateKeysPem("xl")
	if err != nil {
		fmt.Println(err.Error())
		return
	}


	//生成密钥对
	//data := "落日余晖，待你而归"
	//pri,err :=rsa.RSAcreatKey()
	//if err != nil {
	//	fmt.Println("生成密钥失败",err.Error())
	//}

	//使用生成的密钥对对数据进行加密
	//cipherText,err :=rsa.RSAEncrypt(pri.PublicKey,[]byte(data))
	//if err != nil {
	//	fmt.Println("抱歉！加密失败",err.Error())
	//	return
	//}
	////使用私钥进行解密
	//originalText, err :=rsa.RSADecrypt(pri,cipherText)
	//if err != nil {
	//	fmt.Println("抱歉！加密失败",err.Error())
	//	return
	//}
	//fmt.Println("解密过后的明文",string(originalText))
	//
	////使用rsa私钥进行签名
	//RsasignText,err :=rsa.RSASign(pri,[]byte(data))
	//if err != nil {
	//	fmt.Println("抱歉签名失败",err.Error())
	//}
	////使用rsa公钥进行验证
	//verifyResult ,err:=rsa.RSAveri(pri.PublicKey,[]byte(data),RsasignText,)
	//if err != nil {
	//	fmt.Println("抱歉！验证失败",err.Error())
	//}
	//if verifyResult {
	//	fmt.Println("恭喜，验证成功")
	//}else {
	//	fmt.Println("抱歉！验证失败")
	//}
}