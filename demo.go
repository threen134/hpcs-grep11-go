package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/asn1"
	"encoding/base64"
	"fmt"

	"github.com/IBM-Cloud/hpcs-grep11-go/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/util"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// The following IBM Cloud HPCS service items need to be changed prior to running the sample program
var (
	Address        = "ep11.us-east.hs-crypto.cloud.ibm.com:13412"
	APIKey         = ""
	HPCSInstanceID = ""
	IAMEndpoint    = "https://iam.cloud.ibm.com"
)

var callOpts = []grpc.DialOption{
	grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
	grpc.WithPerRPCCredentials(&util.IAMPerRPCCredentials{
		APIKey:   APIKey,
		Endpoint: IAMEndpoint,
	}),
}

func main() {
	fmt.Println("------------- 第一部分 产生密钥对 加密密钥对")
	fmt.Println("开始产生椭圆曲线密钥对")
	pubKey, privateKey := generateECKeyPair()
	fmt.Println("成功产生椭圆曲线密钥对")
	fmt.Println("说明： 密钥对由HPCS产生，私钥被master key 包裹")
	// base64output(pubKey)
	// base64output(privateKey)
	fmt.Println("开始产生KEK密钥")
	kek := generateAESKey()
	fmt.Println("成功产生KEK密钥")
	fmt.Println("说明： 密钥KEK由HPCS产生并被master key 包裹返回")
	// base64output(kek)
	fmt.Println("开始使用KEK 包裹私钥")
	encryptedPrivateKey := encryptAES(kek, privateKey)
	fmt.Println("成功包裹私钥")
	fmt.Println("说明： HPCS 解包裹KEK，在HPCS内部得到明文KEK， 使用明文KEK加密被包裹的私钥")
	fmt.Println("todo: 存储KEK到HPVS的可信执行环境")
	fmt.Println("说明： 签名服务器一定要跑在可信的执行环境下（机密计算， 因为它有访问HPCS的权限, 对于黑客来说，他为了盗取您的资产，不一定需要得到明文的私钥，黑客只要获取到签名的权限，他依然可以盗取您的资产")
	fmt.Println("todo: 保存公私钥对到 HPDBaaS 进行持久化")
	fmt.Println("说明： 虽然数据库被窃取，并不会导致有任何的资产的损失，但是我们依然建议您把数据跑在一个可信的HPDBaaS上")

	fmt.Println("------------- 第二部分 签名")
	fmt.Println("todo: 从HPDBaaS 提取 私钥")
	fmt.Println("使用KEK解密，得到被包裹的私钥")
	unencryptedPrivateKey := decryptAES(kek, encryptedPrivateKey)
	fmt.Println("成功使用KEK解密，得到被包裹的私钥")
	fmt.Println("说明： HPCS 解包裹KEK，得到明文KEK，使用明文KEK解密私钥，得到被master key 包裹的私钥，并反回这个私钥")
	fmt.Println("签名数据")
	data := bytes.NewBufferString("hi, can you help to sign me  ?")
	signature := signEC(unencryptedPrivateKey, data.Bytes())
	fmt.Println("成功签名数据")
	fmt.Println("说明：HPCS 使用master key 解包裹私钥，在hpcs内部得到明文的私钥， 使用明文的私钥签名，返回签名指纹，并丢弃明文的私钥，明文私钥没有离开过hpcs内部")
	fmt.Println("------------- 第三部分 验证签名")
	fmt.Println("开始验证数据")
	verifyEC(signature, pubKey, data.Bytes())
	fmt.Println("说明：使用公钥验证签名")
	fmt.Println("验证数据成功")
}

func base64output(input []byte) {
	fmt.Println(base64.RawStdEncoding.EncodeToString(input))
}

// 产生KEK
func generateAESKey() []byte {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)
	keyLen := 128 // bits

	// Setup the AES key's attributes
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VALUE_LEN:   keyLen / 8,
		ep11.CKA_WRAP:        false,
		ep11.CKA_UNWRAP:      false,
		ep11.CKA_ENCRYPT:     true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_EXTRACTABLE: false, // set to false!
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}

	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKey KEK Error: %s", err))
	}

	fmt.Println("产生 KEK 成功")
	return generateKeyResponse.GetKeyBytes()
}

// 通过KEK加密私钥
func encryptAES(kek, plain []byte) []byte {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	encryptRequest := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_ECB},
		Key:   kek,
		Plain: plain,
	}

	encryptResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptRequest)
	if err != nil {
		panic(fmt.Errorf("通过KEK加密私钥失败, [%s]", err))
	}
	fmt.Println("通过KEK加密私钥成功")
	return encryptResponse.GetCiphered()
}

// 通过KEK解密私钥
func decryptAES(kek, ciphered []byte) []byte {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	decryptSingleRequest := &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_ECB},
		Key:      kek,
		Ciphered: ciphered,
	}

	decryptResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptSingleRequest)
	if err != nil {
		panic(fmt.Errorf("通过KEK解密私钥失败, [%s]", err))
	}
	fmt.Println("通过KEK解密私钥成功")
	return decryptResponse.GetPlain()
}

// 创建EC Key pair
func generateECKeyPair() (public, private []byte) {
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)
	ecParameters, err := asn1.Marshal(util.OIDNamedCurveED25519)
	if err != nil {
		panic(fmt.Errorf("unable to encode parameter OID: %s", err))
	}

	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_EC_PARAMS:   ecParameters,
		ep11.CKA_VERIFY:      true,
		ep11.CKA_EXTRACTABLE: false,
	}
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:        true,
		ep11.CKA_EXTRACTABLE: false,
	}
	generateKeyPairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}
	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeyPairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateECKeyPair error: %s", err))
	}
	fmt.Println("成功产生EC key pair")
	return generateKeyPairResponse.GetPubKeyBytes(), generateKeyPairResponse.GetPrivKeyBytes()
}

func signEC(privateKey, data []byte) (signature []byte) {
	fmt.Println("使用椭圆曲线算法私钥签名数据")
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	signRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_IBM_ED25519_SHA512},
		PrivKey: privateKey,
		Data:    data,
	}

	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	fmt.Println("签名成功")
	return signSingleResponse.GetSignature()
}

func verifyEC(signature, pubKey, data []byte) {
	fmt.Println("使用椭圆曲线算法公钥验证签名")
	conn, err := grpc.Dial(Address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_IBM_ED25519_SHA512},
		PubKey:    pubKey,
		Data:      data,
		Signature: signature,
	}

	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Println("invalid signature")
			return
		}
		panic(fmt.Errorf("verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
	}
	fmt.Println("验签成功")
}
