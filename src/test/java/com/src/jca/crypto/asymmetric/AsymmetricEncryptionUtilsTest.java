package com.src.jca.crypto.asymmetric;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.KeyPair;
import java.security.PrivateKey;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class AsymmetricEncryptionUtilsTest {

	@BeforeClass
	public static void printBeforeClass() {
		System.out.println("printBeforeClass");
	}
	
	@Before
	public void printBefore() {
		System.out.println("printBefore");
	}
	
	@Test
	public void testCreateKeyPairForRSA() throws Exception {
		KeyPair keyPair = AsymmetricEncryptionUtils.createKeyPairForRSA();
		assertNotNull("RSA KeyPair null!!!",keyPair);
	}
	
	@Test
	public void testEncryptDataWithRSA() throws Exception {
		String plainText = "This is RSA Text for RSA encryption";
		KeyPair keyPair = AsymmetricEncryptionUtils.createKeyPairForRSA();
		PrivateKey privateKey = keyPair.getPrivate();
		byte[] encryptedData = AsymmetricEncryptionUtils.encryptDataWithRSA(plainText, privateKey);
		assertNotNull(encryptedData);
	}
	
	@Test
	public void testDecryptionDataWithRSA() throws Exception {
		String plainText = "This is RSA plain text in hiding";
		KeyPair keyPair = AsymmetricEncryptionUtils.createKeyPairForRSA();
		assertNotNull(keyPair);
		byte[] encryptedData = AsymmetricEncryptionUtils.encryptDataWithRSA(plainText, keyPair.getPrivate());
		assertNotNull(encryptedData);
		byte[] decryptedData = AsymmetricEncryptionUtils.decryptDataWithRSA(encryptedData, keyPair.getPublic());
		assertNotNull(decryptedData);
		String decryptedText = new String(decryptedData);
		assertEquals(plainText, decryptedText);
	}
	
	@After
	public void printAfter() {
		System.out.println("printAfter");
	}
	
	@AfterClass
	public static void printAfterClass() {
		System.out.println("printAfterClass");
	}
	
}
