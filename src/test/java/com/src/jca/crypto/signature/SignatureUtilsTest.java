package com.src.jca.crypto.signature;

import static org.junit.Assert.*;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;

import org.junit.Test;

import com.src.jca.crypto.asymmetric.AsymmetricEncryptionUtils;

public class SignatureUtilsTest {
	
	@Test
	public void testSignature() throws Exception {
		URL url = this.getClass().getClassLoader().getResource("random.txt");
		byte[] inputData = Files.readAllBytes(Paths.get(url.toURI()));
		System.out.println("Length of input data:"+inputData.length);
		KeyPair keyPair = AsymmetricEncryptionUtils.createKeyPairForRSA();
		
		byte[] signature = SignatureUtils.digitalSignContent(inputData, keyPair.getPrivate());
		assertNotNull("Signature is null!!",signature);
		
		assertTrue("Siganture invalid", SignatureUtils.verifySignature(inputData, signature, keyPair.getPublic()));
	}
}
