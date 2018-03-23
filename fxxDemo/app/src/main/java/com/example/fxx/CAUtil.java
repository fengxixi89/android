package com.example.fxx;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.UUID;

import javax.crypto.Cipher;


public class CAUtil {
	/**
	 * Java��Կ��(Java ��Կ�⣬JKS)KEY_STORE
	 */
	public static final String KEY_STORE = "JKS";
    
    /**
     * ����ļ����ܿ�
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;
    
    /**
     * ����ļ����ܿ�
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

	/**
     * <p>
     * �����Կ��
     * </p>
     * 
     * @param keyStorePath ��Կ��洢·��
     * @param storeFilePass ��Կ�⣨JKS�ļ������룩
     * @return
     * @throws Exception
     */
    private static KeyStore getKeyStore(String keyStorePath, String storeFilePass)
            throws Exception {
    	 FileInputStream in=null;
    	 KeyStore keyStore=null;
    	try{
        in = new FileInputStream(keyStorePath);
        keyStore = KeyStore.getInstance(KEY_STORE);
        keyStore.load(in, storeFilePass.toCharArray());
        KeyStore.getDefaultType();
    	}finally{
    		 in.close();
    	}
        return keyStore;
    }
    
    /**
     * <p>
     * ������Կ����˽Կ
     * </p>
     * 
     * @param keyStorePath ��Կ��洢·��
     * @param storeFilePass ��Կ������
     * @param alias ��Կ�����
     * @param privateKeyPassword ˽Կ����
     * @return
     * @throws Exception
     */
    private static PrivateKey getPrivateKey(String keyStorePath,String storeFilePass,String alias, String privateKeyPassword) 
            throws Exception {
        KeyStore keyStore = getKeyStore(keyStorePath, storeFilePass);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, privateKeyPassword.toCharArray());
        return privateKey;
    }
    
    /**
     * <p>
     * ������Կ����֤��
     * </p>
     * 
     * @param keyStorePath ��Կ��洢·��
     * @param storeFilePass ��Կ������
     * @param alias ��Կ�����
     * @return
     * @throws Exception
     */
    private static Certificate getCertificate(String keyStorePath,String storeFilePass,String alias) 
            throws Exception {
        KeyStore keyStore = getKeyStore(keyStorePath, storeFilePass);
        Certificate certificate = keyStore.getCertificate(alias);
        return certificate;
    }

    /**
     * <p>
     * ������Կ����˽Կ
     * </p>
     * 
     * @param keyStorePath ��Կ��洢·��
     * @param storeFilePass ��Կ������
     * @param alias ��Կ�����
     * @return
     * @throws Exception
     */
    private static PublicKey getPublicKey(String keyStorePath,String storeFilePass,String alias) 
            throws Exception {
    	Certificate cer=getCertificate(keyStorePath,storeFilePass,alias);
    	return cer.getPublicKey();
    }

    /**
     * <p>
     * ��Կ����
     * </p>
     * 
     * @param data Դ����
     * @param keyStorePath ֤��洢·��
     * @param storeFilePass ֤��洢·��
     * @param alias ֤��洢·��
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String keyStorePath,String storeFilePass,String alias)
            throws Exception {
        // ȡ�ù�Կ
        PublicKey publicKey = getPublicKey(keyStorePath,storeFilePass,alias);
        Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // �����ݷֶμ���
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
     * <p>
     * ��Կ����
     * </p>
     * 
     * @param encryptedData �Ѽ�������
     * @param keyStorePath ֤��洢·��
     * @param storeFilePass ֤��洢·��
     * @param alias ֤��洢·��
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, String keyStorePath,String storeFilePass,String alias)
            throws Exception {
        PublicKey publicKey = getPublicKey(keyStorePath,storeFilePass,alias);
        Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // �����ݷֶν���
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
     * <p>
     * ˽Կ����
     * </p>
     * 
     * @param data Դ����
     * @param keyStorePath ��Կ��洢·��
     * @param storeFilePass ��Կ������
     * @param alias ��Կ�����
     * @param privateKeyPassword ˽Կ����
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String keyStorePath,String storeFilePass,String alias, String privateKeyPassword) 
            throws Exception {
        // ȡ��˽Կ
        PrivateKey privateKey = getPrivateKey(keyStorePath,storeFilePass,alias,privateKeyPassword);
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // �����ݷֶμ���
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
     * <p>
     * ˽Կ����
     * </p>
     * 
     * @param encryptedData �Ѽ�������
     * @param keyStorePath ��Կ��洢·��
     * @param storeFilePass ��Կ������
     * @param alias ��Կ�����
     * @param privateKeyPassword ˽Կ����
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData,String keyStorePath,String storeFilePass,String alias, String privateKeyPassword) 
            throws Exception {
        // ȡ��˽Կ
        PrivateKey privateKey = getPrivateKey(keyStorePath,storeFilePass,alias,privateKeyPassword);
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        // ����byte������󳤶�����: 128
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // �����ݷֶν���
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
     * <p>
     * ��������ǩ��
     * </p>
     * 
     * @param data Դ����
     * @param keyStorePath ��Կ��洢·��
     * @param storeFilePass ��Կ������
     * @param alias ��Կ�����
     * @param privateKeyPassword ˽Կ����
     * @return
     * @throws Exception
     */
    public static byte[] sign(byte[] data, String keyStorePath,String storeFilePass,String alias, String privateKeyPassword) 
            throws Exception {
        // ���֤��
    	//Certificate cert = getCertificate(keyStorePath,storeFilePass,alias);
    	X509Certificate x509Certificate = (X509Certificate) getCertificate(keyStorePath,storeFilePass,alias);
    	PrivateKey privateKey = getPrivateKey(keyStorePath,storeFilePass,alias,privateKeyPassword);
        // ����ǩ��
        Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
    
    /**
     * <p>
     * ��������ǩ������BASE64����
     * </p>
     * 
     * @param data Դ����
     * @param keyStorePath ��Կ��洢·��
     * @param alias ��Կ�����
     * @param password ��Կ������
     * @return
     * @throws Exception
     */
    public static String signToBase64(byte[] data, String keyStorePath,String storeFilePass,String alias, String privateKeyPassword) 
            throws Exception {
        //return new sun.misc.BASE64Encoder().encode(sign(data, keyStorePath,storeFilePass, alias, privateKeyPassword));
        return Base64Util.encodeForUrl(sign(data, keyStorePath,storeFilePass, alias, privateKeyPassword));
    }
    
    /**
     * <p>
     * ��֤ǩ��
     * </p>
     * 
     * @param data �Ѽ�������
     * @param sign ����ǩ��[BASE64]
     * @param keyStorePath ��Կ��洢·��
     * @param alias ��Կ�����
     * @param password ��Կ������
     * @return
     * @throws Exception
     */
    public static boolean verifySign(byte[] data, String sign,String keyStorePath,String storeFilePass,String alias) 
            throws Exception {
        // ���֤��
        X509Certificate x509Certificate = (X509Certificate) getCertificate(keyStorePath,storeFilePass,alias);
        // ��ù�Կ
        PublicKey publicKey = x509Certificate.getPublicKey();
        // ����ǩ��
        Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
        signature.initVerify(publicKey);
        signature.update(data);
        //return signature.verify(new sun.misc.BASE64Decoder().decodeBuffer(sign));
        return signature.verify(Base64Util.decodeForUrl(sign));
    }
    
    /**
     * <p>
     * ��֤����֤�����ڸ����������Ƿ���Ч
     * </p>
     * 
     * @param keyStorePath ��Կ��洢·��
     * @param alias ��Կ�����
     * @param password ��Կ������
     * @return
     */
    public static boolean verifyCertificate(Date date,String keyStorePath,String storeFilePass,String alias) {
        Certificate certificate;
        try {
            certificate = getCertificate(keyStorePath,storeFilePass,alias);
            return verifyCertificate(date,certificate);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * <p>
     * ��֤֤���Ƿ���ڻ���Ч
     * </p>
     * 
     * @param date ����
     * @param certificate ֤��
     * @return
     */
    public static boolean verifyCertificate(Date date, Certificate certificate) {
        boolean isValid = true;
        try {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            x509Certificate.checkValidity(date);
        } catch (Exception e) {
            isValid = false;
        }
        return isValid;
    }

   
	public static void main(String[] str) throws Exception {
		
		
		String alias="wbxtws";//֤���ͨ����
		String keyStorePath = "d:/ca/"+alias+".jks";
		String storeFilePass="wbxtws20160104";//JKS�ļ�������
		String privateKeyPassword="wbxtws20160104";//˽Կ����
		System.out.println("֤���Ƿ���Ч:"+verifyCertificate(new Date(),keyStorePath, storeFilePass, alias));
		
		
        String source =UUID.randomUUID().toString();
        System.out.println(source.length());
        byte[] data = source.getBytes();
        System.err.println("====˽Կ����=====");
        //˽Կ����
        byte[] encrypt =CAUtil.encryptByPrivateKey(data, keyStorePath, storeFilePass, alias, privateKeyPassword);
        //"ISO-8859-1"
        String baseS = Base64Util.encode(encrypt);
        System.out.println("baseS=== "+baseS);
        baseS= baseS.replaceAll("\r\n","");
        System.out.println("baseS=== "+baseS);
        encrypt=Base64Util.decode(baseS);
        
        System.err.println("====��Կ����=====");
        
        //��Կ����
        byte[] decrypt =CAUtil.decryptByPublicKey(encrypt, keyStorePath, storeFilePass, alias);
        
        System.err.println("====ǩ��=====");
        String sign=CAUtil.signToBase64(decrypt, keyStorePath, storeFilePass, alias, privateKeyPassword);
//        System.out.println("����ǩ����"+sign);
        
        //�Խ��ܺ�����ݽ�����֤ǩ��
        System.out.println("ǩ���Ƿ���Ч:"+verifySign(decrypt,sign,keyStorePath, storeFilePass, alias));
        System.out.println("");
        String outputStr = new String(decrypt);

        System.out.println("����ǰ: \r\n" + source + "\r\n" + "���ܺ�: \r\n" + outputStr);
       
       
      
	}
	
}
