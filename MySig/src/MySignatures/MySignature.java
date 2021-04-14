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
	private boolean signatureState;
	private byte[] decryptMessageDigest;
	
	
	protected MySignature (String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException {
		
		
		String[] algorithms = algorithm.toUpperCase().split("WITH");
		
		String dgstAlg = algorithms[0];
		
		System.out.println("\nTESTE dgstAlg: " + dgstAlg);
				
		if(dgstAlg.equals("SHA256")) {
			dgstAlg = "SHA-256"; 
		}
		else if(dgstAlg.equals("SHA512")) {
			dgstAlg = "SHA-512";
		}		
				
		this.message_digest = MessageDigest.getInstance(dgstAlg);
		this.decryptMessageDigest = null;
		this.cipher = Cipher.getInstance(algorithms[1]);
		this.signatureState = false;
		
	}
	
	public static MySignature getInstance(String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException {
		MySignature mysignature;
		String lowAlg = algorithm.toLowerCase();
		if(lowAlg.equals("md5withrsa") || lowAlg.equals("sha1withrsa") || lowAlg.equals("sha256withrsa") || lowAlg.equals("sha512withrsa")) {
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
				throw new SignatureException("Erro durante a assinatura.\n");
			}
		}
		System.out.println("Assinatura Concluída - [Chave Privada]\n");
		return cipherDigest;
	}
	
	public void initVerify(PublicKey pbKey) throws Exception {
		System.out.println("Verificação do cipher.\n");
		cipher.init(Cipher.DECRYPT_MODE, pbKey);
	}
	
	public boolean verify(byte[] assinatura) throws Exception {
				
		byte[] tc1 = message_digest.digest();
		byte[] digestFromSign = cipher.doFinal(assinatura);
		
		System.out.println("\nResultado do Digest:");
		
		for (int i=0; i != tc1.length; i++) {
			System.out.println(String.format("%02X", tc1[i]));
		}

		if (Arrays.equals(tc1, digestFromSign)) {
			return true; //Valido
		}		
		
		return false; //Invalido
		
	}




}
