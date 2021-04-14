package MySignatures;

/*
 * MD5withRSA
 * SHA1withRSA
 * SHA256withRSA
 * SHA512withRSA
 * 
 * @author Sergio Gustavo Mendonça Pyrrho Moreira e Alex Nascimento Rodrigues
 */


import java.security.*;
import java.util.Arrays;
import javax.crypto.*;

public class MySignature {
	
	private MessageDigest message_digest;
	private Cipher cipher;
	private KeyPairGenerator KGen;
	private KeyPair key;
	private PublicKey publiKey;
	private PrivateKey privKey;
	private byte[] decryptMessageDigest;
	
	
	protected MySignature (String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException {
		String[] algorithms = algorithm.toLowerCase().split("with");
		
		String dgstAlg = algorithms[0];
		
		if(dgstAlg.equals("sha256")) {
			dgstAlg = "sha256"; 
		}
		else if(dgstAlg.equals("sha512")) {
			dgstAlg = "sha512";
		}
		else {
			System.out.println("Padrão de Assinatura Não Reconhecido.\n");
		}
		
		this.message_digest = MessageDigest.getInstance(dgstAlg);
		this.cipher = Cipher.getInstance(algorithms[1]);
		
	}
	
	public static MySignature getInstance(String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException {
		MySignature mysignature;
		String lowAlg = algorithm.toLowerCase();
		if(lowAlg.equals("md5withrsa") || lowAlg.equals("sha1withrsa") || lowAlg.equals("sha1withrsa") || lowAlg.equals("sha256withrsa") || lowAlg.equals("sha512withrsa")) {
			try {
				mysignature = new MySignature(algorithm);
			}
			catch (NoSuchAlgorithmException | NoSuchPaddingException e){
				throw new NoSuchAlgorithmException("Implementação Não Disponível Para Algoritmo.\n");
			}
		}
		else {
			throw new NoSuchAlgorithmException("Assinatura Não Suporta Algoritmo.\n");
		}
		
		return mysignature;
	}
	
	private void generatePairOfKey() throws Exception {
		System.out.println("Gerando chave RSA");
	}
	
	public void initSign() throws Exception {
		System.out.println("Gerando Par de Chave .\n");
		this.generatePairOfKey();
		this.cipher = Cipher.getInstance("RSA/ECB/PKCBS1Padding");
		this.cipher.init(Cipher.ENCRYPT_MODE, this.getPrivateKey());
		System.out.println("Par de Chave gerada.\n");
	}
	
	public void update() throws Exception {
		System.out.println("Elaborando MDigest.\n");
		this.message_digest.generateMessageDigest();
	}
	
	public void sign() throws Exception {
		System.out.println("Assinando MDigest - [Chave Privada]\n");
		this.setCipherText(cipher.doFinal(this.message_digest.getDigest()));
		System.out.println("Assinatura Concluída - [Chave Privada]\n");
	}
	
	public void initVerify() throws Exception {
		System.out.println("Inicializando Verificação do Cipher.\n");
		this.cipher.init(Cipher.DECRYPT_MODE, this.getPublicKey());
		System.out.println("Verificação do Cipher em andamento.\n");
	}
	
	public boolean verify(byte[] assinatura) throws Exception {
		
		byte[] tc1 = message_digest.digest();
		
		byte[] digestFromSign = cipher.doFinal(assinatura);
		
		System.out.println("\nDigest gerado:");
		
		for (int i=0; i != tc1.length; i++) {
			System.out.println(String.format("%02X", tc1[i]));
		}
		
		if (Arrays.equals(tc1, digestFromSign)) {
			return true; // Válido
		}		
		
		return false; // Inválido
		
	}
	
	private void setKeyPar(KeyPair newKeyPair) {
		this.key = newKeyPair;
	}
	
	private KeyPair getKeyPair() {
		return this.key;	
	}
	
	private void setPublicKey(PublicKey newPublicKey) {
		this.publiKey = newPublicKey;
	}
	
	private PublicKey getPublicKey() {
		return this.publiKey;
	}
	
	private void setPrivateKey(PrivateKey newPrivateKey) {
		this.privKey = newPrivateKey;
	}
	
	private PrivateKey getPrivateKey() {
		return this.privKey;
	}
	
	private void setMessage(byte[] msg) {
		this.message_digest.setMessage(msg);
	}
	
	private byte[] getMessage() {
		return this.message_digest.getMessage();
	}
	
	private void setDecryptMessageDigest(byte[] newDecryptMessageDigest) {
		this.decryptMessageDigest = newDecryptMessageDigest;
	}
	
	private byte[] getDecryptMessageDigest() {
		return this.decryptMessageDigest;
	}
}




