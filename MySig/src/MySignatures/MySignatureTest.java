package MySignatures;

import java.security.KeyPair;
import java.security.KeyPairGenerator;



public class MySignatureTest {
	public MySignatureTest(String[] args) throws Exception {
			
			if(args.length != 1) {
				System.err.println("Excesso de argumentos!");
				System.exit(1);
			}
			System.out.println("Padrao de Assinatura: " + args[0]);
	
			byte[] padraoAsgn = args[0].getBytes("UTF8"); 
			System.out.print("Padrao de Assinatura em Hexadecimal: ");
			for(int i = 0; i < padraoAsgn.length; i++)
				System.out.print(String.format("%02X", padraoAsgn[i]));
			
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair key = keyGen.generateKeyPair();
			
			MySignature mySignature = MySignature.getInstance("SHA512withRSA");
			mySignature.initSign(key.getPrivate());
			mySignature.update(padraoAsgn);
	
			byte[] signature = mySignature.sign();
			System.out.print("\nSignature: ");
			for(int i = 0; i != signature.length; i++)
				System.out.print(String.format("%02x", signature[i]));
						
			mySignature.initVerify(key.getPublic());
			mySignature.update(padraoAsgn);
			
			if(mySignature.verify(signature))
				System.out.println("\nAssinatura válida");
			else
				System.err.println("\nAssinatura inválida");
		}

}