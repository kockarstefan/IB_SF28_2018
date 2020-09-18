package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
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
import com.google.api.services.gmail.model.Message;

import model.mailclient.MailBody;
import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.GzipUtil;
import util.KeyStoreReader;
import util.MenageSignatures;

public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	
	private static final String USERB_FILE = "./data/userb.jks";
	private static String userBPassword = "userb";
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, MessagingException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException {
        // Build a new authorized API client service.
	
    		
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
        
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
        
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));  
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
		MimeMessage chosenMessage = mimeMessages.get(answer);
		

//		dobavljanje privatnog kljuca korisnika B
		char[] pass = userBPassword.toCharArray();
		KeyStore keystore = KeyStoreReader.readKeyStore(USERB_FILE, pass);
		PrivateKey recieverPrivateKey = KeyStoreReader.getPrivateKeyFromKeyStore(keystore, "userb", pass);
		
//		Preuzimanje javnog kljuca korisnika A iz njegovog sertifikata koji se nalazi u keystoru korisnika B
		Certificate certificateSender = KeyStoreReader.getCertificateFromKeyStore(keystore, "usera");
		PublicKey senderPublicKey = KeyStoreReader.getPublicKeyFromCertificate(certificateSender);
		
//		 Sifrovana poruka
		String textMail = MailHelper.getText(chosenMessage);
				
// 		izdvojeni delovi mailbody
		MailBody mailBody = new MailBody(textMail);		
		String textMessage = mailBody.getEncMessage();
				
		byte[] cipherText = mailBody.getEncMessageBytes();
		byte[] cipherSecretKey = mailBody.getEncKeyBytes();
		byte[] signature = mailBody.getSignatureBytes();
		IvParameterSpec iv1 = new IvParameterSpec(mailBody.getIV1Bytes());
		IvParameterSpec iv2 = new IvParameterSpec(mailBody.getIV2Bytes());

				
//		dekriptovanje tajnog kljuca
		Security.addProvider(new BouncyCastleProvider());
		Cipher rsaCipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");		
		rsaCipherEnc.init(Cipher.DECRYPT_MODE, recieverPrivateKey);
						
		byte [] sessionKey = rsaCipherEnc.doFinal(cipherSecretKey);
					
//		dekriptovanje i dekompresovanje poruke
		Cipher aesCipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKey secretKey = new SecretKeySpec(sessionKey, "AES");
				
		IvParameterSpec ivParameterSpec1 = iv1;
		aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec1);
					
		byte[] bodyEnc = Base64.decode(textMessage);
		String receivedBody = new String(aesCipherDec.doFinal(bodyEnc));
		String decompressedBody = GzipUtil.decompress(Base64.decode(receivedBody));
				
				
//		inicijalizacija za dekriptovanje
		IvParameterSpec ivParameterSpec2 = iv2;		
		aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec2);
				
//		dekompresovanje i dekriptovanje subject-a
		String decryptedSubject = new String(aesCipherDec.doFinal(Base64.decode(chosenMessage.getSubject())));
		String decompressedSubject = GzipUtil.decompress(Base64.decode(decryptedSubject));
												
		System.out.println("\nSubject text: \n" + new String(decompressedSubject) + "\n");
		System.out.println("Body text: \n" + decompressedBody);
				
//		Provera potpisa
				
		if(MenageSignatures.verify(mailBody.getEncMessageBytes(),mailBody.getSignatureBytes() , senderPublicKey)) {
			System.out.println("\nSignature is verified\n");
			}else {
				System.out.println("\nSignature is not verified\n");
			}
		
	}
}
