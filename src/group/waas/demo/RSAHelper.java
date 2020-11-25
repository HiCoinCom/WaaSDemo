package group.waas.demo;

import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.Cipher;

public class RSAHelper {
	/**
     * 加密算法RSA
     */
    public static final String KEY_ALGORITHM = "RSA";

    /** *//**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 234;

    /** *//**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 256;


    private static final String CHARSET ="UTF-8";



    /**
     * 公钥解密
     *
     * @param encryptedData 已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey)
                    throws Exception {
            byte[] keyBytes =  decryptBASE64(publicKey);
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            Key publicK = keyFactory.generatePublic(x509KeySpec);
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, publicK);
            int inputLen = encryptedData.length;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段解密
            while (inputLen - offSet > 0) {
                    if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                            cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
                    } else {
                            cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
                    }
                    out.write(cache, 0, cache.length);
                    i++;
                    offSet = i * MAX_DECRYPT_BLOCK;
            }
            byte[] decryptedData = out.toByteArray();
            out.close();
            return decryptedData;
    }

    /**
     *  公钥分段解密
     * @param encryptedData 加密的base64数据
     * @param publicKey rsa 公钥
     * @return
     */
    public static String decryptByPublicKey(String encryptedData, String publicKey){
            if(encryptedData==null || encryptedData.isEmpty() || publicKey==null || publicKey.isEmpty()) {
            	return "";
            }

            try {
                encryptedData = encryptedData.replace("\r", "").replace("\n", "");
                byte[] data = decryptByPublicKey(decryptBASE64(encryptedData), publicKey);
                if(data == null || data.length < 1){
                        return  "";
                }
                return new String(data);
            }catch (Exception ex){
                    ex.printStackTrace();
            }
            return "";
    }

    /**
     * 私钥加密
     *
     * @param data 源数据
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String privateKey)
                    throws Exception {
            byte[] keyBytes =  decryptBASE64(privateKey);
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, privateK);
            int inputLen = data.length;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段加密
            while (inputLen - offSet > 0) {
                    if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                            cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
                    } else {
                            cache = cipher.doFinal(data, offSet, inputLen - offSet);
                    }
                    out.write(cache, 0, cache.length);
                    i++;
                    offSet = i * MAX_ENCRYPT_BLOCK;
            }
            byte[] encryptedData = out.toByteArray();
            out.close();
            return encryptedData;
    }

    /**
     *  私钥分段加密数据
     * @param data 待加密数据
     * @param privateKey  私钥
     * @return
     */
    public static String encryptByPrivateKey(String data, String privateKey){
            if(data==null || privateKey==null || data.isEmpty()|| privateKey.isEmpty()) {
            	return "";
            }

            try {
                    byte[] encryptedData = encryptByPrivateKey(data.getBytes(CHARSET), privateKey);
                    if(encryptedData == null || encryptedData.length < 1){
                            return  "";
                    }

        byte[] dataBytes = encryptBASE64(encryptedData).getBytes(CHARSET);
        return new String(dataBytes).replace("\r", "").replace("\n", "");
            }catch (Exception ex){
                    ex.printStackTrace();
            }
            return "";
    }
    
    /**
     * BASE64Encoder 加密
     * 
     * @param data
     *            要加密的数据
     * @return 加密后的字符串
     */
    public static String encryptBASE64(byte[] data) {
    	//JDK 1.8以下环境，使用下列2行代码
        // BASE64Encoder encoder = new BASE64Encoder();
        // String encode = encoder.encode(data);
        // 从JKD 9开始rt.jar包已废除，从JDK 1.8开始使用java.util.Base64.Encoder
        Encoder encoder = Base64.getEncoder();
        String encode = encoder.encodeToString(data);
        //不管使用什么环境，下面的+/替换成-_都需要完成。
        String safeBase64Str = encode.replace('+', '-');
        safeBase64Str = safeBase64Str.replace('/', '_');
        safeBase64Str = safeBase64Str.replaceAll("=", "");
        return safeBase64Str;
    }
    /**
     * BASE64Decoder 解密
     * 
     * @param data
     *            要解密的字符串
     * @return 解密后的byte[]
     * @throws Exception
     */
    public static byte[] decryptBASE64(String data) throws Exception {
    	//JDK 1.8以下环境，使用下列2行代码
        // BASE64Decoder decoder = new BASE64Decoder();
        // byte[] buffer = decoder.decodeBuffer(data);
        // 从JKD 9开始rt.jar包已废除，从JDK 1.8开始使用java.util.Base64.Decoder
        Decoder decoder = Base64.getDecoder();
        
        //不管使用什么环境，下面的-_替换成+/都需要完成。
        String base64Str = data.replace('-', '+');
        base64Str = base64Str.replace('_', '/');
        int mod4 = base64Str.length()%4;
        if(mod4 > 0){
            base64Str = base64Str + "====".substring(mod4);
        }
        
        byte[] buffer = decoder.decode(base64Str);
        return buffer;
    }
}
