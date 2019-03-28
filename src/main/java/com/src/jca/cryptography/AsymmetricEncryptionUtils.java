package com.src.jca.cryptography;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;

public class AsymmetricEncryptionUtils {
	private static final String RSA = "RSA";
	
	public static KeyPair createKeyPairForRSA() throws Exception {
		SecureRandom secureRandom = new SecureRandom();
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
		keyPairGenerator.initialize(4096, secureRandom);
		return keyPairGenerator.generateKeyPair();
	}

	public static byte[] encryptDataWithRSA(String plainText, PrivateKey privateKey) throws Exception {
		Cipher cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		return cipher.doFinal(plainText.getBytes());
	}
	
	public static byte[] decryptDataWithRSA(byte[] encryptedData, PublicKey publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(encryptedData);		
	}

}
