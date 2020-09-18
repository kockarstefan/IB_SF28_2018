	package app;


import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.internet.MimeMessage;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.varia.NullAppender;
import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.api.services.gmail.Gmail;

import model.mailclient.MailBody;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import util.KeyStoreReader;
import util.MenageSignatures;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {

	private static final String USERA_FILE = "./data/usera.jks";
	private static final String USERB_FILE = "./data/userb.jks";
	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	
	private static String userAPassword = "usera";
	
	public static void main(String[] args) {
		
        try {
        	BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        	System.out.println("Insert your email:");
            String sender = reader.readLine();
        	
            
            Gmail service = getGmailService();
        	

        	System.out.println("Insert a reciever:");
            String reciever = reader.readLine();
        	
            System.out.println("Insert a subject:");
            String subject = reader.readLine();
            
            
            System.out.println("Insert body:");
            String body = reader.readLine();
            
            //Preuzimanje privatnog kljuca korisnka A iz njegovog keystora
    		char[] pass = userAPassword.toCharArray();
    		KeyStore keystore = KeyStoreReader.readKeyStore(USERA_FILE, pass);			
    		PrivateKey senderPrivateKey = KeyStoreReader.getPrivateKeyFromKeyStore(keystore, "usera", pass);
    		Certificate certificateSender = KeyStoreReader.getCertificateFromKeyStore(keystore, "usera");
    		PublicKey senderPublicKey = KeyStoreReader.getPublicKeyFromCertificate(certificateSender);
            
    		//Preuzimanje javnog kljuca korisnika B iz njegovog sertifikata koji se nalazi u keystoru korisnika A
    		Certificate certificateReceiver = KeyStoreReader.getCertificateFromKeyStore(keystore, "usera");
    		PublicKey recieverPublicKey = KeyStoreReader.getPublicKeyFromCertificate(certificateReceiver);
    		
            //Compression
            String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
            String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
            
            //Key generation
            KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 
			SecretKey secretKey = keyGen.generateKey();
			Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
		
			
			//sifrovanje body-a
			byte[] ciphertext = aesCipherEnc.doFinal(compressedBody.getBytes());
			String ciphertextStr = Base64.encodeToString(ciphertext);
			System.out.println("Kriptovan tekst: " + ciphertextStr);
			
			//potpisivanje
			byte[] signature = MenageSignatures.sign(ciphertext, senderPrivateKey);
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
			
			//sifrovanje subjecta
			byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
			System.out.println("Kriptovan subject: " + ciphersubjectStr);
			
			//kriptovanje tajnog kljuca
			Security.addProvider(new BouncyCastleProvider());
			Cipher rsaCipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
			rsaCipherEnc.init(Cipher.ENCRYPT_MODE, recieverPublicKey);
			byte[] cipherSecretKey = rsaCipherEnc.doFinal(secretKey.getEncoded());
//			String secretKeyEncString = Base64.encodeToString(secretKeyEnc);
			
			//kreiranje mail body-a
			MailBody mailBody = new MailBody(ciphertext, ivParameterSpec1.getIV(), ivParameterSpec2.getIV(), cipherSecretKey, signature);
			
			//snimaju se bajtovi kljuca i IV.
//			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
//			JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
//			JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());
			
        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, mailBody.toCSV());
        	MailWritter.sendMessage(service, "me", mimeMessage);
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	}
}
