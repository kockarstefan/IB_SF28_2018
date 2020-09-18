package util;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class MenageSignatures {
	public static byte[] sign(byte[] data, PrivateKey privateKey) {
		try {
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(privateKey);
			signature.update(data);
			return signature.sign();
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	public static boolean verify(byte[] data, byte[] digitalSignature, PublicKey publicKey) {
		Signature signature;
		try {
			signature = Signature.getInstance("SHA1withRSA");
			signature.initVerify(publicKey);
			signature.update(data);
			return signature.verify(digitalSignature);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
		
		return false;
	}
}
