package org.fosstrak.epcis.ency;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import sun.misc.BASE64Decoder;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Package_name org.fosstrak.epcis.captureclient
 * Project_name fosstrak-epcis1
 * Created by lenovo on 2015/11/8 13:34
 */
public class En_Decryption {
    public enum En_DecryMethod {
        PUB_ENCRY, PRI_SIGNATRUE, PUB_SIGNATRUE, PRI_DECRY
    }

    private final static String DES = "DES";

    private static NodeList user_nodeList;
    private static NodeList admin_nodeList;

    private static byte[] key = null;

    public static byte[] getDESKey() {
        return key;
    }

    //初始化DESKey，初始化加密或者解密端所需要的ECC公钥和私钥，用Nodelist保存
    public static void keyStore_List(String admin, String user, En_DecryMethod method) throws IOException, SAXException, ParserConfigurationException, NoSuchAlgorithmException {

        key = initSecretKey();
        Security.addProvider(new BouncyCastleProvider());
        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dbBuilder = dbFactory.newDocumentBuilder();
        Document doc = null;
        switch (method) {
            case PUB_ENCRY:
                final String user_loc = "D:/document/JavaProjects/fosstrak_epcis_wwh/fosstrak-epcis_wwh/" + user + "_pub.xml";
                final String admin_loc = "D:/document/JavaProjects/fosstrak_epcis_wwh/fosstrak-epcis_wwh/" + admin + "_key.xml";
                File file = new File(user_loc);
                if (file.exists()) {
                    doc = dbBuilder.parse(file.getAbsoluteFile());
                    user_nodeList = doc.getElementsByTagName("key");
                } else {
                    System.out.println("file don't exists.");
                }
                File file2 = new File(admin_loc);
                if (file.exists()) {
                    doc = dbBuilder.parse(file2.getAbsoluteFile());
                    admin_nodeList = doc.getElementsByTagName("key");
                } else {
                    System.out.println("file don't exists.");
                }
                break;
            case PUB_SIGNATRUE:
                final String user_loc2 = "D:/document/JavaProjects/fosstrak_epcis_wwh/fosstrak-epcis_wwh/" + user + "_key.xml";
                final String admin_loc2 = "D:/document/JavaProjects/fosstrak_epcis_wwh/fosstrak-epcis_wwh/" + admin + "_pub.xml";
                File file3 = new File(user_loc2);
                if (file3.exists()) {
                    doc = dbBuilder.parse(file3.getAbsoluteFile());
                    user_nodeList = doc.getElementsByTagName("key");
                } else {
                    System.out.println("file isn't exists.");
                }
                File file4 = new File(admin_loc2);
                if (file4.exists()) {
                    doc = dbBuilder.parse(file4.getAbsoluteFile());
                    admin_nodeList = doc.getElementsByTagName("key");
                } else {
                    System.out.println("file isn't exists.");
                }
                break;
            case PRI_SIGNATRUE:
            case PRI_DECRY:
                try {
                    throw new Exception("Wrong method.");
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            default:
                break;
        }
    }

    //获取公钥
    public static ECPublicKey getECCPublicKey(En_DecryMethod method) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, ParserConfigurationException, SAXException, IOException {

        String publicKey = null;
        switch (method) {
            case PUB_ENCRY:
                for (int i = 0; i < user_nodeList.getLength(); i++) {
                    NodeList subNode = user_nodeList.item(i).getChildNodes();
                    for (int j = 0; j < subNode.getLength(); j++) {
                        if (subNode.item(j).getNodeName().equals("publicKey")) {
                            publicKey = subNode.item(j).getTextContent();
                        }
                    }
                }
                break;
            case PUB_SIGNATRUE:
                for (int i = 0; i < admin_nodeList.getLength(); i++) {
                    NodeList subNode = admin_nodeList.item(i).getChildNodes();
                    for (int j = 0; j < subNode.getLength(); j++) {
                        if (subNode.item(j).getNodeName().equals("publicKey"))
                            publicKey = subNode.item(j).getTextContent();
                    }
                }
                break;
            case PRI_DECRY:
            case PRI_SIGNATRUE:
                try {
                    throw new Exception("Wrong method.");
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            default:
                break;
        }
        byte[] eccPublicKey2 = (Base64.decode(publicKey));
        X509EncodedKeySpec X509PublicKeyObject = new X509EncodedKeySpec(eccPublicKey2);//生成X509EncodedKeySpec格式的密钥规范
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");//获取密钥工厂对象
        return (ECPublicKey) keyFactory.generatePublic(X509PublicKeyObject);
    }

    //获取私钥
    public static ECPrivateKey getECCPrivateKey(En_DecryMethod method) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, ParserConfigurationException, SAXException, IOException {

        String privateKey = null;
        switch (method) {
            case PRI_SIGNATRUE:
                for (int i = 0; i < admin_nodeList.getLength(); i++) {
                    NodeList subNode = admin_nodeList.item(i).getChildNodes();
                    for (int j = 0; j < subNode.getLength(); j++) {
                        if (subNode.item(j).getNodeName().equals("privateKey")) {
                            privateKey = subNode.item(j).getTextContent();
                        }
                    }
                }
                break;
            case PRI_DECRY:
                for (int i = 0; i < user_nodeList.getLength(); i++) {
                NodeList subNode = user_nodeList.item(i).getChildNodes();
                for (int j = 0; j < subNode.getLength(); j++) {
                    if (subNode.item(j).getNodeName().equals("privateKey"))
                        privateKey = subNode.item(j).getTextContent();
                }
            }
                break;
            case PUB_SIGNATRUE:
            case PUB_ENCRY:
                try {
                    throw new Exception("Wrong method.");
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            default:
                break;
        }

        byte[] eccPrivateKey2 = (Base64.decode(privateKey));
        PKCS8EncodedKeySpec PKCS8PrivateKeyObject = new PKCS8EncodedKeySpec(eccPrivateKey2);//生成PKCS8EncodedKeySpec格式的密钥规范
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");//获取密钥工厂对象
        return (ECPrivateKey) keyFactory.generatePrivate(PKCS8PrivateKeyObject);
    }

    //加密
    public static String encryption(byte[] text) throws ParserConfigurationException, NoSuchAlgorithmException, SAXException, IOException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        ECPublicKey eccPublicKey = getECCPublicKey(En_DecryMethod.PUB_ENCRY);
        Cipher cipher2 = Cipher.getInstance("ECIES", "BC");//获取密码引擎对象
        cipher2.init(Cipher.ENCRYPT_MODE, eccPublicKey);//初始化加密模式和公钥
        byte[] cipherText2 = cipher2.doFinal(text);//加密
        return Base64.toBase64String(cipherText2);
    }

    //解密
    public static byte[] decryption(String text) throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, IOException, ParserConfigurationException, SAXException {
        ECPrivateKey eccPrivateKey = getECCPrivateKey(En_DecryMethod.PRI_DECRY);
        Cipher cipher = Cipher.getInstance("ECIES", "BC");//获取密码引擎对象
        cipher.init(Cipher.DECRYPT_MODE, eccPrivateKey);//初始化解密模式和私钥
        //对密文进行Base64解码
        BASE64Decoder decoder = new BASE64Decoder();
        byte[] text3 = decoder.decodeBuffer(text);
        byte[] text4 = cipher.doFinal(text3);//解密
        return text4;
    }

    //DES decryption
    private static byte[] initSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator kg=KeyGenerator.getInstance(DES);
        kg.init(56);
        SecretKey secretKey=kg.generateKey();
        return secretKey.getEncoded();
    }

    public static String DES_encrypt(byte[] src,byte[]key) throws InvalidKeyException, InvalidKeySpecException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        SecureRandom sr=new SecureRandom();
        DESKeySpec desKeySpec=new DESKeySpec(key);
        SecretKeyFactory keyFactory=SecretKeyFactory.getInstance(DES);
        SecretKey securekey=keyFactory.generateSecret(desKeySpec);

        Cipher cipher=Cipher.getInstance(DES);
        cipher.init(Cipher.ENCRYPT_MODE,securekey,sr);
        return Base64.toBase64String(cipher.doFinal(src));
    }

    public static String DES_decrypt(byte[] src, byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecureRandom sr = new SecureRandom();
        DESKeySpec dks = new DESKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
        SecretKey securekey = keyFactory.generateSecret(dks);
        Cipher cipher = Cipher.getInstance(DES);
        cipher.init(Cipher.DECRYPT_MODE, securekey, sr);
        return new String(cipher.doFinal(src));
}

    public static String setSignature(String text) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException, IOException, SAXException, ParserConfigurationException {
        ECPrivateKey eccPrivateKey = getECCPrivateKey(En_DecryMethod.PRI_SIGNATRUE);
        Signature signature = Signature.getInstance("ECDSA", "BC");
        signature.initSign(eccPrivateKey);
        byte[] text2=text.getBytes();
        signature.update(text2);
        byte[] sign=signature.sign();
        return Base64.toBase64String(sign);
    }

    public static boolean isRightSignature(String text,String sign) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException, IOException, ParserConfigurationException, SAXException {
        ECPublicKey eccPublicKey=getECCPublicKey(En_DecryMethod.PUB_SIGNATRUE);
        Signature signature=Signature.getInstance("ECDSA","BC");
        signature.initVerify(eccPublicKey);
        byte[] text2=text.getBytes();
        signature.update(text2);
        BASE64Decoder decoder=new BASE64Decoder();
        byte[] sign2=decoder.decodeBuffer(sign);
        return signature.verify(sign2);
    }
}
