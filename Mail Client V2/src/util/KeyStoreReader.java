package util;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class KeyStoreReader {
	
	public static KeyStore readKeyStore(String keyStoreFilePath, char[] password) {
		KeyStore keyStore = null;
		try {
			// kreiramo instancu KeyStore objekta. 
			// prvi parametar getInstance metode je tip KeyStore-a, drugi parametar je provider
			// npr. ako zelimo da kreiramo PKCS12 KeyStore -> KeyStore.getInstance("PKCS12")
			keyStore = KeyStore.getInstance("JKS", "SUN");
			
			// VAZNO:
			// pre nego sto instanca keyStore moze da se koristi, mora da se ucita pozivom load() metode. KeyStore instance se uglavnom cuvaju
			// na disku. Zbog toga klasa KeyStore je definisano tako da se podaci sa diska prvo moraju procitati. Ukoliko ne zelimo da ucitamo
			// nikakve podatke u keyStore instancu, kao prvi parametar load() metode prosledjujemo null vrednost -> keyStore.load(null, password);
			// load() metoda se uvek mora pozvati! KeyStore instanca se mora inicijalizovati uvek, bilo sa nekim podacima ili sa null. Ukoliko se
			// ovaj korak preskoci i metoda load() ne pozove, imacemo neinicijalizovan KeyStore objekat, i svaki poziv bilo koje metode
			// nad ovim objektom ce izazvati Exception!
			
			// ucitavamo podatke
			BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyStoreFilePath));
			keyStore.load(in, password);
		} catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
			System.err.println("\n[KeyStoreReader - readKeyStore] Greska prilikom ucitavanja KeyStore-a. Proveriti da li je putanja ispravna i da li je prosledjen dobra sifra za otvaranje KeyStore-a!\n");			
		}
		
		return keyStore;
	}
	
	/**
	 * Metoda sluzi za citanje sertifikata iz KeyStore-a
	 * 
	 * @param keyStore - referenca na KeyStore
	 * @param alias - kljuc pod kojim se sertifikat koji zelimo da preuzmemo cuva u KeyStore-u
	 * 
	 * @return Sertifikat
	 */
	public static Certificate getCertificateFromKeyStore(KeyStore keyStore, String alias) {
		Certificate certificate = null;
		try {
			certificate = keyStore.getCertificate(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		if (certificate == null) {
			System.err.println("\n[KeyStoreReader - getCertificateFromKeyStore] Sertifikat je null. Proveriti da li je alias ispravan!\n");
		}
		
		return certificate;
	}
	
	/**
	 * Metoda sluzi za citanje privatnog kljuca iz KeyStore-a
	 * 
	 * @param keyStore - referenca na KeyStore
	 * @param alias - kljuc pod kojim se privatni kljuc koji zelimo da preuzmemo cuva u KeyStore-u
	 * @param keyPass - sifra za pristup privatnom kljucu u okviru KeyStore-a
	 *  
	 * @return Privatni kljuc
	 */
	public static PrivateKey getPrivateKeyFromKeyStore(KeyStore keyStore, String alias, char[] keyPass) {
		PrivateKey privateKey = null;
		try {
			privateKey = (PrivateKey) keyStore.getKey(alias, keyPass);
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		if (privateKey == null) {
			System.err.println("\n[KeyStoreReader - getPrivateKeyFromKeyStore] Privatni kljuc je null. Proveriti da li su ispravni alias i sifra za privatni kljuc!\n");
		}
		
		return privateKey;
	}
	
	/**
	 * Metoda sluzi za citanje javnog kljuca iz sertifikata
	 * 
	 * @param certificate - sertifikat iz kojeg zelimo da procitamo javni kljuc
	 * @return Javni kljuc
	 */
	public static PublicKey getPublicKeyFromCertificate(Certificate certificate) {
		return certificate.getPublicKey();
	}
}
