package com.src.jca.crypto.hash;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.mindrot.jbcrypt.BCrypt;

public class HashUtils {
	private static final String SHA2 = "SHA-256";
	
	public static byte[] getSalt() throws Exception {
		byte[] salt = new byte[16];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(salt);
		return salt;
	}
	
	public static byte[] createSHA2Hash(String plainText, byte[] salt) throws Exception {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(salt);
		outputStream.write(plainText.getBytes());
		MessageDigest messageDigest = MessageDigest.getInstance(SHA2);
		byte[] valueToHash = outputStream.toByteArray();
		return messageDigest.digest(valueToHash);
	}
	
	public static String hashPasword(String plainPassword) throws Exception {
		return BCrypt.hashpw(plainPassword, BCrypt.gensalt());
	}
	
	public static boolean checkPassword(String plainPassword, String hashedPassword) throws Exception {
		return BCrypt.checkpw(plainPassword, hashedPassword);
	}	
	
}
