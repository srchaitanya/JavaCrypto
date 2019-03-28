package com.src.jca.crypto.signature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SignatureUtils {
	
	private static String SIGNATURE_ALGORITHM = "SHA256WithRSA";
	
	public static byte[] digitalSignContent(byte[] input, PrivateKey privateKey) throws Exception {
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(privateKey);
		signature.update(input);
		return signature.sign();
	}
	
	public static boolean verifySignature(byte[] input, byte[] signatureData, PublicKey publicKey) throws Exception {
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(publicKey);
		signature.update(input);
		return signature.verify(signatureData);
	}

}
