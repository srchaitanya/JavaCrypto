package com.src.jca.crypto.hash;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class HashUtilsTest {
	
	@Test
	public void testSalt() throws Exception {
		byte[] salt = HashUtils.getSalt();
		assertNotNull("Salt is null",salt);
	}
	
	@Test
	public void testCreateSHA2Hash() throws Exception {
		byte[] salt = HashUtils.getSalt();
		String plainText = "This is plain text to be digested";
		byte [] hash1 = HashUtils.createSHA2Hash(plainText, salt);
		assertNotNull(hash1);
		byte[] hash2 = HashUtils.createSHA2Hash(plainText, salt);
		assertNotNull(hash2);
		assertEquals(javax.xml.bind.DatatypeConverter.printHexBinary(hash1),
					 javax.xml.bind.DatatypeConverter.printHexBinary(hash2));
		String plainText2 = "This is second plain text to be digested";
		byte [] hash3 = HashUtils.createSHA2Hash(plainText2, salt);
		assertNotEquals(javax.xml.bind.DatatypeConverter.printHexBinary(hash1),
				        javax.xml.bind.DatatypeConverter.printHexBinary(hash3));
	}
	
	@Test
	public void testPasswordUtility() throws Exception {
		String plainPassword = "p@ssword";
		String hashedPassword = HashUtils.hashPasword(plainPassword);
		assertTrue("Error... correct passwprd is denied",HashUtils.checkPassword(plainPassword, hashedPassword));
		String plainPassword2 = "passworrd";
		assertFalse("Wrong password matched different password's hash", HashUtils.checkPassword(plainPassword2, hashedPassword));
		System.out.println(hashedPassword);
	}
	
	
}
