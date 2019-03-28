package com.src.jca.cryptography;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SymmetricKeyUtils {
	
	private static String AES = "AES";
	private static String AES_ALGO = "AES/CBC/PKCS5Padding";
	
	public static SecretKey createAESSecretKey() throws NoSuchAlgorithmException {
		SecureRandom secureRandom = new SecureRandom();	
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256,secureRandom);
		SecretKey aesSecretKey = keyGenerator.generateKey();
		return aesSecretKey;		
	}
	
	public static byte[] createInitializationVector() {
		byte[] initializationVector = new byte[16];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(initializationVector);
		return initializationVector;
	}
	
	public static byte[] performAESEncryption(String plainText, SecretKey secretKey, byte[] initializationVector) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher aesCipher = Cipher.getInstance(AES_ALGO);
		IvParameterSpec ivParamSpec = new IvParameterSpec(initializationVector);
		aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParamSpec);
		return aesCipher.doFinal(plainText.getBytes());		
	}

	public static byte[] performDESDecryption(byte[] encryptedData, SecretKey secretKey, byte[] initVector) throws Exception {
		Cipher cipher = Cipher.getInstance(AES_ALGO);
		IvParameterSpec ivParamSpec = new IvParameterSpec(initVector);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParamSpec);
		byte[] decryptedData = cipher.doFinal(encryptedData);
		return decryptedData;
	}

}
