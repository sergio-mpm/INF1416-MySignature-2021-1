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
	private boolean signatureState;
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
		this.decryptMessageDigest = null;
		this.cipher = Cipher.getInstance(algorithms[1]);
		this.signatureState = false;
		
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
	
	private void generatePairOfKey(PrivateKey newPrivateKey, PublicKey newPublicKey) throws Exception {
		System.out.println("Gerando chave RSA");
		this.setPrivateKey(newPrivateKey);
		this.setPublicKey(newPublicKey);
	}
	
	public void initSign() throws InvalidKeyException {
		this.cipher.init(Cipher.ENCRYPT_MODE, this.getPrivateKey());
		this.signatureState = true;
		System.out.println("Assinatura Com Chave Privada Gerada.\n");
	}
	
	public void update(byte[] data) throws SignatureException {
		if (this.signatureState == true) {
			this.message_digest.update(data);
		}
		else {
			System.out.println("Erro ao atualizar.\n");
			throw new SignatureException("Erro ao atualizar assinatura.\n");
		}
	}
	
	public void sign() throws SignatureException {
		System.out.println("Assinando MDigest - [Chave Privada]\n");
		if(this.signatureState == true) {
			this.decryptMessageDigest = message_digest.digest();
			try {
				this.cipher.doFinal(this.decryptMessageDigest);
			}
			catch (Exception e) {
				throw new SignatureException("Algoritmo de assinatura não consegue processar os dados.\n");
			}
		}
		System.out.println("Assinatura Concluída - [Chave Privada]\n");
	}
	
	public void initVerify() throws Exception {
		System.out.println("Inicializando Verificação do Cipher.\n");
		this.cipher.init(Cipher.DECRYPT_MODE, this.getPublicKey());
		System.out.println("Verificação do Cipher em andamento.\n");
	}
	
	public boolean verify(byte[] signature) throws Exception {
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
	
	private void setDecryptMessageDigest(byte[] newDecryptMessageDigest) {
		this.decryptMessageDigest = newDecryptMessageDigest;
	}
	
	private byte[] getDecryptMessageDigest() {
		return this.decryptMessageDigest;
	}
}




