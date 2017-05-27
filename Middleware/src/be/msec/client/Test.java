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

		String subject = "javacard";
		
		Certificate selfSignedCert = keyStore.getCertificate(subject);
		RSAPublicKey pubKey = (RSAPublicKey) selfSignedCert.getPublicKey();
		
		byte[] modulus = pubKey.getModulus().toByteArray();
		byte[] exponent = pubKey.getPublicExponent().toByteArray();
		
		
		
		byte[] sign = null;
		int[] fromDate = {2017, 01, 25, 9, 44};
		int[] toDate = {2018, 01, 25, 9, 44};

		byte[] validFromBytes = new byte[8];
		byte[] yearBytes = ByteBuffer.allocate(4).putInt(new Integer(fromDate[0])).array();
		System.arraycopy(yearBytes, 0, validFromBytes, 0, yearBytes.length);
		validFromBytes[yearBytes.length] = (byte) (int) new Integer(fromDate[1]);
		validFromBytes[yearBytes.length + 1] = (byte) fromDate[2];
		validFromBytes[yearBytes.length + 2] = (byte) fromDate[3];
		validFromBytes[yearBytes.length + 3] = (byte) fromDate[4];
		

		byte[] validUntilBytes = new byte[8];
		byte[] yearTillBytes = ByteBuffer.allocate(4).putInt(new Integer(toDate[0])).array();
		System.arraycopy(yearTillBytes, 0, validUntilBytes, 0, yearTillBytes.length);
		validUntilBytes[yearTillBytes.length] = (byte) (int) new Integer(toDate[1]);
		validUntilBytes[yearTillBytes.length + 1] = (byte) toDate[2];
		validUntilBytes[yearTillBytes.length + 2] = (byte) toDate[3];
		validUntilBytes[yearTillBytes.length + 3] = (byte) toDate[4];
		
		byte[] subjectBytes = subject.getBytes();
		
		HomeMadeCertificate cert = new HomeMadeCertificate(subjectBytes, subjectBytes, exponent, modulus, sign, validFromBytes, validUntilBytes);

		signCertificate(cert);
		
		
		//cert.save();
		
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
