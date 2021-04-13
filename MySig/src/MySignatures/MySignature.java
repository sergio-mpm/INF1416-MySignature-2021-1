package MySignatures;

/*
 * MD5withRSA
 * SHA1withRSA
 * SHA256withRSA
 * SHA512withRSA
 * 
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
	
	
	protected MySignature (String algorithm, String sign ) throws Exception {
		String[] algorithms = algorithm.toLowerCase().split("with");
		
		
	}
	
	public static MySignature GetInstance(String algorithm, String sign) throws Exception {
		MySignature mysignature = new MySignature(algorithm, sign);
		
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
		System.out.println("Assinatura Conclu�da - [Chave Privada]\n");
	}
	
	public void initVerify() throws Exception {
		System.out.println("Inicializando Verifica��o do Cipher.\n");
		this.cipher.init(Cipher.DECRYPT_MODE, this.getPublicKey());
		System.out.println("Verifica��o do Cipher em andamento.\n");
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
		System.out.println("Finalizada Verifica��o do Cipher.\n");
		
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




