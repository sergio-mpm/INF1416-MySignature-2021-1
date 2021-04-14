package MySignatures;

/*
 * MD5withRSA
 * SHA1withRSA
 * SHA256withRSA
 * SHA512withRSA
 * 
 * @author Sergio Gustavo Mendon�a Pyrrho Moreira e Alex Nascimento Rodrigues
 */


import java.security.*;
import java.util.Arrays;
import javax.crypto.*;

public class MySignature {
	
	private MessageDigest message_digest;
	private Cipher cipher;
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
			System.out.println("Padr�o de Assinatura N�o Reconhecido.\n");
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
				throw new NoSuchAlgorithmException("Implementa��o N�o Dispon�vel Para Algoritmo.\n");
			}
		}
		else {
			throw new NoSuchAlgorithmException("Assinatura N�o Suporta Algoritmo.\n");
		}
		
		return mysignature;
	}
	
	public void generatePairOfKey(PrivateKey newPrivateKey, PublicKey newPublicKey) throws Exception {
		System.out.println("Gerando chave RSA");
		this.setPrivateKey(newPrivateKey);
		this.setPublicKey(newPublicKey);
	}
	
	public void initSign(PrivateKey newPrivateKey) throws InvalidKeyException {
		this.cipher.init(Cipher.ENCRYPT_MODE, newPrivateKey);
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
	
	public byte[] sign() throws SignatureException {
		System.out.println("Assinando MDigest - [Chave Privada]\n");
		byte[] cipherDigest = null;
		if(this.signatureState == true) {
			this.decryptMessageDigest = message_digest.digest();
			try {
				cipherDigest = this.cipher.doFinal(this.decryptMessageDigest);
			}
			catch (Exception e) {
				throw new SignatureException("Algoritmo de assinatura n�o consegue processar os dados.\n");
			}
		}
		System.out.println("Assinatura Conclu�da - [Chave Privada]\n");
		return cipherDigest;
	}
	
	public void initVerify() throws Exception {
		System.out.println("Inicializando Verifica��o do Cipher.\n");
		this.cipher.init(Cipher.DECRYPT_MODE, this.getPublicKey());
		System.out.println("Verifica��o do Cipher em andamento.\n");
	}
	
	public boolean verify(byte[] assinatura) throws Exception {
				
		byte[] tc1 = message_digest.digest();
		byte[] digestFromSign = cipher.doFinal(assinatura);
		
		System.out.println("\nDigest gerado:");
		
		for (int i=0; i != tc1.length; i++) {
			System.out.println(String.format("%02X", tc1[i]));
		}

		if (Arrays.equals(tc1, digestFromSign)) {
			return true; //Valido
		}		
		
		return false; //Invalido
		
	}

	public void setPublicKey(PublicKey newPublicKey) {
		this.publiKey = newPublicKey;
	}
	
	public PublicKey getPublicKey() {
		return this.publiKey;
	}
	
	public void setPrivateKey(PrivateKey newPrivateKey) {
		this.privKey = newPrivateKey;
	}
	
	public PrivateKey getPrivateKey() {
		return this.privKey;
	}
	
	public void setDecryptMessageDigest(byte[] newDecryptMessageDigest) {
		this.decryptMessageDigest = newDecryptMessageDigest;
	}
	
	public byte[] getDecryptMessageDigest() {
		return this.decryptMessageDigest;
	}
}




