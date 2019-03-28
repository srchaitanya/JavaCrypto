package com.src.jca.crypto.symmetric;

import static org.junit.Assert.assertNotNull;

import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import org.junit.Test;

public class SymmetricEncryptionUtilsTest {

	@Test
	public void testCreateAESSecretKey() throws NoSuchAlgorithmException {
		SecretKey secretKey = SymmetricEncryptionUtils.createAESSecretKey();
		assertNotNull("Secret Key is Null !!!!",secretKey);
	}
	
	@Test
	public void testCreateInitializationVector() {
		byte[] initVector = SymmetricEncryptionUtils.createInitializationVector();
		assertNotNull("IVParam spec is null!!!",initVector);
	}
	
	@Test
	public void testPerformAESEncryption() throws Exception {
		String plainText = "This is for AES/CBC/PKCS5Padding encryption";
		SecretKey secretKey = SymmetricEncryptionUtils.createAESSecretKey();
		byte[] initVector = SymmetricEncryptionUtils.createInitializationVector();
		byte[] encryptedData = SymmetricEncryptionUtils.performAESEncryption(plainText, secretKey, initVector);
		assertNotNull("Encrypted Data is null",encryptedData);
		System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(encryptedData));		
	}
	
	@Test
	public void testPerformAESDecryption() throws Exception {
		SecretKey secretKey = SymmetricEncryptionUtils.createAESSecretKey();
		assertNotNull("Secret key is null!!!",secretKey);
		byte[] initVector = SymmetricEncryptionUtils.createInitializationVector();
		assertNotNull("initialization vector null",initVector);
		String plainText = "This is for AES/CBC/PKCS5Padding encryption";
		byte[] encryptedData = SymmetricEncryptionUtils.performAESEncryption(plainText, secretKey, initVector);
		assertNotNull("encrypted data is null",encryptedData);
		byte[] decryptedData = SymmetricEncryptionUtils.performDESDecryption(encryptedData,secretKey,initVector);
		String decryptedString = new String(decryptedData);
		org.junit.Assert.assertEquals("Decryption not working !!! ",plainText, decryptedString);
	}
	
	
}
