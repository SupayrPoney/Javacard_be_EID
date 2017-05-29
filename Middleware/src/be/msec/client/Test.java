package be.msec.client;

import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import helpers.HomeMadeCertificate;

import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.awt.event.ActionEvent;

public class Test {

	public static HomeMadeCertificate restoreCert(String name) {

        HomeMadeCertificate deserializedCert = null;
        FileInputStream inputFileStream;
		try {
			inputFileStream = new FileInputStream("certs/" + name + ".crt");
	        ObjectInputStream objectInputStream = new ObjectInputStream(inputFileStream);
	        deserializedCert= (HomeMadeCertificate)objectInputStream.readObject();
	        //System.out.println(new String(deserializedCert.getIssuer()));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return deserializedCert;
	}

	/**
	 * Launch the application.
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		String fileName = "/home/supayrponey/Cours/2016-2017/SecurityInComputing/Project/project.jks";
		FileInputStream fis = new FileInputStream(fileName);
		keyStore.load(fis, "ThisIs4V3ryS4f3Pa$$w0rd".toCharArray());
		fis.close();

		String subject = "default1";
		String issuer = "default";
		
		Certificate selfSignedCert = keyStore.getCertificate(subject);
		RSAPublicKey pubKey = (RSAPublicKey) selfSignedCert.getPublicKey();
		
		byte[] modulus = pubKey.getModulus().toByteArray();
		byte[] exponent = pubKey.getPublicExponent().toByteArray();
		
		
		
		byte[] sign = null;
		byte[] validFromBytes = {0,0,1,89,-44,-53,-64,-128};
		byte[] validUntilBytes = {0,0,1,97,44,124,-20,-128};
		
		byte[] subjectBytes = subject.getBytes();
		byte[] issuerBytes = issuer.getBytes();
		
		HomeMadeCertificate cert = new HomeMadeCertificate(issuerBytes, subjectBytes, exponent, modulus, sign, validFromBytes, validUntilBytes);

		signCertificate(cert);
		
		
		cert.save();
		
//		
//		HomeMadeCertificate deserCert = restoreCert(subject);
//		
//		System.out.println(Arrays.equals(deserCert.getSignature(),data));

	      
	}
	public static void byteArrayToPrintable(byte[] input){
		System.out.print("{");
		for (byte b : input) {
			System.out.print(b + ",");
		}

		System.out.println("}");
	}

	private static void signCertificate(HomeMadeCertificate cert) {
		String name = "main_ca";
		
		try {
			KeyStore keyStore = KeyStore.getInstance("JKS");
			String fileName = "/home/supayrponey/Cours/2016-2017/SecurityInComputing/Project/project.jks";
			FileInputStream fis = new FileInputStream(fileName);
			keyStore.load(fis, "ThisIs4V3ryS4f3Pa$$w0rd".toCharArray());
			fis.close();
			
			PrivateKey caPrivKey = (PrivateKey) keyStore.getKey(name, "test".toCharArray());
			Signature signEngine = Signature.getInstance("SHA1withRSA");
			signEngine.initSign(caPrivKey);
			signEngine.update(cert.getAsBytesWithoutSign());
			byte[] signature = signEngine.sign();
			cert.setSignature(signature);
			System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(signature));
			//byteArrayToPrintable(cert.getAsBytesWithSign());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
