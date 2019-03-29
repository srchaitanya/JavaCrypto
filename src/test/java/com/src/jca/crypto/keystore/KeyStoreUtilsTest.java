package com.src.jca.crypto.keystore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.Key;
import java.security.KeyStore;

import javax.crypto.SecretKey;

import org.junit.Test;

import com.src.jca.crypto.symmetric.SymmetricEncryptionUtils;



public class KeyStoreUtilsTest {

	
	@Test
	public void testKeyStore() throws Exception {
		String keyStorePwd="keyStorePwd";
		String keyPwd = "keyPwd";
		String keyAlias = "mykey";
		SecretKey secretKey = SymmetricEncryptionUtils.createAESSecretKey();
		
		String secretKeyHex = javax.xml.bind.DatatypeConverter.printHexBinary(secretKey.getEncoded());
		
		KeyStore keyStore = KeyStoreUtils.createKeyStore(keyStorePwd,keyAlias,secretKey,keyPwd);
		assertNotNull(keyStore);
		
		Key storedInKeyStore = KeyStoreUtils.getKey(keyStore, keyStorePwd, keyAlias, keyPwd);
		String storedSecretKeyHex = javax.xml.bind.DatatypeConverter.printHexBinary(storedInKeyStore.getEncoded());
		
		assertEquals("KeyStore not working",secretKeyHex, storedSecretKeyHex);
		
		System.out.println(secretKeyHex);
		System.out.println(storedSecretKeyHex);
		
	}
	
}
