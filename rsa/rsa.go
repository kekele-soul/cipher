package rsa

import (
	"cipher/util"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

const RSA_PRIVATE_KEY = "RSA_PRIVATE_KEY"
const RSA_PUBLIC_KEY = "RSA_PUBLIC_KEY"
/**
 *该函数用于生成一对rsa密钥对，并返回密钥
 */
func RSAcreatKey () (*rsa.PrivateKey,error){
	var bits int
	flag.IntVar(&bits,"b",2048,"rsa密钥的长度")
	//私钥
	pirvatKey,err :=rsa.GenerateKey(rand.Reader,bits)
	if err != nil {
		fmt.Println("生成密钥失败",err.Error())
	}
	//返回私钥
	return pirvatKey,err
}
/**
 *使用RSA算法对数据进行加密，并返回密文
 */
func RSAEncrypt (pub rsa.PublicKey,data []byte) ([]byte,error){
	return rsa.EncryptPKCS1v15(rand.Reader,&pub,data)
}

/**
 *使用RSAD进行解密，返回解密后的明文
 */
func RSADecrypt (pri *rsa.PrivateKey,cipher []byte)([]byte,error){
	return rsa.DecryptPKCS1v15(rand.Reader,pri,cipher)
}


/**
 *使用RSA对数据进行签名
 */
func RSASign (pri *rsa.PrivateKey , data []byte) ([]byte,error){
	hashMd5Text := util.HashMd5(data)
	return rsa.SignPKCS1v15(rand.Reader,pri,crypto.MD5,hashMd5Text)
}
/**
 *使用RSA算伐对数据进行验证
 */
func RSAveri (pub rsa.PublicKey,data []byte,sign []byte)(bool,error){
	hashMd5Text := util.HashMd5(data)
	verifyResult :=rsa.VerifyPKCS1v15(&pub, crypto.MD5,hashMd5Text,sign)
	return verifyResult == nil,verifyResult
}

func GenerateKeysPem(file_name string)(error){
	//先生成私钥
	pri,err :=RSAcreatKey()
	if err != nil {
		fmt.Println("生成错误")
	}
	//生成私钥证书
	err = generatePriPem(pri,file_name)
	if err != nil{
		return err
	}
	//生成公钥证书
	err = generatePubPem(pri.PublicKey,file_name)
	if err != nil {
		return err
	}
	return nil
}

/**
 *生成一对密钥，并以pem文件格式进行保存，即生成两个证书文件
 */
func generatePriPem(pri *rsa.PrivateKey ,file_name string)(error){
	//通过x509标准得到的ras私钥序列化为ASN.1的DER编码字符串
	priBytes :=x509.MarshalPKCS1PrivateKey(pri)
	//要组织一个 pem.Block
	block := pem.Block{
		Type:RSA_PRIVATE_KEY,
		Bytes:priBytes,
	}
	//新建文件
	file,err :=os.Create("rsa_pri"+file_name+".pem")
	if err != nil {
		return err
	}
	//、写入
	 return pem.Encode(file,&block)

}
/**
 *将公钥生成文件
 */
func generatePubPem(pub rsa.PublicKey,file_name string)(error){
	//通过x509标准得到的ras私钥序列化为ASN.1的DER编码字符串
	pubBytes :=x509.MarshalPKCS1PublicKey(&pub)
	//要组织一个 pem.Block
	block := pem.Block{
		Type:  RSA_PUBLIC_KEY,
		Bytes: pubBytes,
	}
	//pem编码
	file,err :=os.Create("rsa_pub"+file_name+".pem")
	if err != nil {
		panic(err)

	}
	return pem.Encode(file,&block) 




}


