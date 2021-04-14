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
	
	public boolean verify() throws Exception {
		this.setDecryptMessageDigest(cipher.doFinal(this.getCipherText()));
		
		StringBuffer buff = new StringBuffer();
		
		for(int idx = 0; idx < this.getDecryptMessageDigest().length, idx++) {
			String hex = Integer.toHexString(0x1000 + (this.getDecryptMessageDigest()[i] & 0x00FF)).substring(1);
			buff.append((hex.length() < 2 ? "0" : " ") + hex);
		}
		
		String decryptMessageDigest = buff.toString();
		
		System.out.println("Message Digest: " + this.message_digest.getHexDigest());
		System.out.println("Message Digest Decriptado: " + decryptMessageDigest());
		System.out.println("Finalizada Verificação do Cipher.\n");
		
		return Arrays.equals(this.message_digest.getDigest(), this.getDecryptMessageDigest());
		
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




