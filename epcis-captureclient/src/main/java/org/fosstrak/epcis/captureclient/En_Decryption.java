package org.fosstrak.epcis.captureclient;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import sun.misc.BASE64Decoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;

/**
 * Package_name org.fosstrak.epcis.captureclient
 * Project_name fosstrak-epcis1
 * Created by lenovo on 2015/11/8 13:34
 */
public class En_Decryption
{

    //生成密钥（公钥和私钥），并保存在HashMap<String,String>keyMap中
    public static void setECCKey() throws NoSuchProviderException, NoSuchAlgorithmException
{
    Security.addProvider(new BouncyCastleProvider());
    Security.insertProviderAt(new BouncyCastleProvider(), 1);//显式添加安全提供者
    //Map<String,String>keyMap=new HashMap<String,String>();//建立一个图存储密钥对
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECIES", "BC");//指明安全提供者
    kpg.initialize(256);//设置密钥长度为256位
    KeyPair keyPair = kpg.generateKeyPair();//获取密钥对
    ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();//获取公钥
    ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();//获取密钥
    keyMap.put("ECCPUBLICKEY", Base64.toBase64String(publicKey.getEncoded()));//将密钥转换为Base64String的字符串格式并存储在Map中
    keyMap.put("ECCPRIVATEKEY", Base64.toBase64String(privateKey.getEncoded()));//将公钥转换为Base64String的字符串格式并存储在Map中
    }


    //获取公钥
    public static ECPublicKey getECCPublicKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        String eccPublicKey = "ECCPUBLICKEY";
        byte[] eccPublicKey2 = (Base64.decode(keyMap.get(eccPublicKey)));//解码
        X509EncodedKeySpec X509PublicKeyObject = new X509EncodedKeySpec(eccPublicKey2);//生成X509EncodedKeySpec格式的密钥规范
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");//获取密钥工厂对象
        return (ECPublicKey) keyFactory.generatePublic(X509PublicKeyObject);
    }

    //获取私钥
    public static ECPrivateKey getECCPrivateKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        String eccPrivateKey = "ECCPRIVATEKEY";
        byte[] eccPrivateKey2 = (Base64.decode(keyMap.get(eccPrivateKey)));//解码
        PKCS8EncodedKeySpec PKCS8PrivateKeyObject = new PKCS8EncodedKeySpec(eccPrivateKey2);//生成PKCS8EncodedKeySpec格式的密钥规范
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");//获取密钥工厂对象
        return (ECPrivateKey) keyFactory.generatePrivate(PKCS8PrivateKeyObject);
    }

    //加密
    public static String encryption(byte[] text) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        ECPublicKey eccPublicKey = getECCPublicKey();
        Cipher cipher = Cipher.getInstance("ECIES", "BC");//获取密码引擎对象
        cipher.init(Cipher.ENCRYPT_MODE, eccPublicKey);//初始化加密模式和公钥
        byte[] cipherText = cipher.doFinal(text);//加密
        return Base64.toBase64String(cipherText);
    }

    //解密
    public static String decryption(String text) throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, IOException {
        ECPrivateKey eccPrivateKey = getECCPrivateKey();
        Cipher cipher = Cipher.getInstance("ECIES", "BC");//获取密码引擎对象
        cipher.init(Cipher.DECRYPT_MODE, eccPrivateKey);//初始化解密模式和私钥
        //对密文进行Base64解码

        BASE64Decoder decoder = new BASE64Decoder();
        byte[] text3 = decoder.decodeBuffer(text);
        byte[] text4 = cipher.doFinal(text3);//解密
        return Base64.toBase64String(text4);
    }

    private static String setSignature(String text) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException
    {
        ECPrivateKey eccPrivateKey = getECCPrivateKey();
        Signature signature = Signature.getInstance("ECDSA", "BC");
        signature.initSign(eccPrivateKey);
        byte[] text2=text.getBytes();
        signature.update(text2);
        byte[] sign=signature.sign();
        return Base64.toBase64String(sign);
    }

    public static boolean isRightSignature(String text,String sign) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException, IOException
    {
        ECPublicKey eccPublicKey=getECCPublicKey();
        Signature signature=Signature.getInstance("ECDSA","BC");
        signature.initVerify(eccPublicKey)  ;
        byte[] text2=text.getBytes();
        signature.update(text2);
        BASE64Decoder decoder=new BASE64Decoder();
        byte[] sign2=decoder.decodeBuffer(sign);
        return signature.verify(sign2);
    }

    public static HashMap<String, String> keyMap = new HashMap<String, String>();
}
