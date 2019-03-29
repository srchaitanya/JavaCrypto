package com.src.jca.crypto.keystore;

import java.security.Key;
import java.security.KeyStore;

import javax.crypto.SecretKey;

public class KeyStoreUtils {
	
	private static final String keyStoreType = "JCEKS";
	
	
	public static KeyStore createKeyStore(String keyStorePw, String keyAlias, SecretKey secretKey, String keyPassword) throws Exception {
		KeyStore keyStore = KeyStore.getInstance(keyStoreType);
		keyStore.load(null, keyStorePw.toCharArray());
		KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(keyPassword.toCharArray());
		KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
		keyStore.setEntry(keyAlias, secretKeyEntry, protectionParam);
		return keyStore;
	}
	
	public static Key getKey(KeyStore keyStore, String storePw, String keyAlias, String keyPw) throws Exception {
		keyStore.load(null, storePw.toCharArray());
		return keyStore.getKey(keyAlias, keyPw.toCharArray());
	}
	
}
