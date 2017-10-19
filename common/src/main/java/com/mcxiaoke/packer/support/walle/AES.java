package com.mcxiaoke.packer.support.walle;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Package Name：com.mcxiaoke.packer.support.walle
 * Class Describe：
 * Author：BaiXigang
 * Creation Time：2017/10/16 下午6:47
 * Modifier：
 * Modification Time：
 * Modify Describe：
 */
public class AES {
    private static final String strDefaultKey = "national";
    /**
     * AES 加密
     *
     * @param seed      密钥
     * @param cleartext 明文
     * @return 密文
     */
    public static String encrypt(String seed, String cleartext) {
        //对密钥进行加密
        byte[] rawkey = getRawKey(seed.getBytes());
        //加密数据
        byte[] result = encrypt(rawkey, cleartext.getBytes());
        //将十进制数转换为十六进制数
        return toHex(result);
    }

    /**
     * AES 加密(使用默认密钥)
     *
     * @param cleartext 明文
     * @return 密文
     */
    public static String encrypt(String cleartext) {
        return encrypt(strDefaultKey, cleartext);
    }


    /**
     * AES 解密
     *
     * @param seed      密钥
     * @param encrypted 密文
     * @return 明文
     */
    public static String decrypt(String seed, String encrypted) {
        byte[] rawKey = getRawKey(seed.getBytes());
        byte[] enc = toByte(encrypted);
        byte[] result = decrypt(rawKey, enc);
        return new String(result);
    }

    /**
     * AES 解密(使用默认密钥)
     *
     * @param encrypted 密文
     * @return 明文
     */
    public static String decrypt(String encrypted) {
        return decrypt(strDefaultKey, encrypted);
    }


    private static byte[] getRawKey(byte[] seed) {

        try {
            //获取密钥生成器
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            sr.setSeed(seed);
            //生成位的AES密码生成器
            kgen.init(128, sr);
            //生成密钥
            SecretKey skey = kgen.generateKey();
            //编码格式
            byte[] raw = skey.getEncoded();
            return raw;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;

    }


    private static byte[] encrypt(byte[] raw, byte[] clear) {

        try {
            //生成一系列扩展密钥，并放入一个数组中
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            //使用ENCRYPT_MODE模式，用skeySpec密码组，生成AES加密方法
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            //得到加密数据
            byte[] encrypted = cipher.doFinal(clear);
            return encrypted;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] decrypt(byte[] raw, byte[] encrypted) {

        try {
            //生成一系列扩展密钥，并放入一个数组中
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = null;
            cipher = Cipher.getInstance("AES");
            //使用DECRYPT_MODE模式，用skeySpec密码组，生成AES解密方法
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            //得到加密数据
            byte[] decrypted = cipher.doFinal(encrypted);
            return decrypted;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;

    }


    //将十进制数转为十六进制
    public static String toHex(String txt) {
        return toHex(txt.getBytes());
    }

    //将十六进制字符串转换位十进制字符串
    public static String fromHex(String hex) {
        return new String(toByte(hex));
    }

    //将十六进制字符串转为十进制字节数组
    public static byte[] toByte(String hexString) {
        int len = hexString.length() / 2;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = Integer.valueOf(hexString.substring(2 * i, 2 * i + 2), 16).byteValue();
        }
        return result;
    }

    //将十进制字节数组转换为十六进制
    public static String toHex(byte[]buf){
        if(buf==null){
            return "";
        }
        StringBuffer result=new StringBuffer(2*buf.length);
        for(int i=0;i<buf.length;i++){
            appendHex(result,buf[i]);
        }
        return result.toString();
    }


    private final static String HEX="0123456789ABCDEF";

    private static void appendHex(StringBuffer sb,byte b){
        sb.append(HEX.charAt((b>>4)&0x0f)).append(HEX.charAt(b&0x0f));
    }
}
