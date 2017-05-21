package be.msec.server;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;

public class TimeService {
	public final static byte REVALIDATION_REQUEST = 1;

	public static void main(String[] args) throws Exception {
		// TODO Reconstruct key
        ServerSocket welcomeSocket = new ServerSocket(8000);
		KeyStore keyStore = KeyStore.getInstance("JKS");
		FileInputStream fis = new FileInputStream(new File("project.jks").getAbsolutePath());
		keyStore.load(fis, "ThisIs4V3ryS4f3Pa$$w0rd".toCharArray());
		fis.close();

		RSAPrivateKey timestampPrivateKey = (RSAPrivateKey) keyStore.getKey("timestamp", "test".toCharArray());

		Certificate cert = keyStore.getCertificate("timestamp");
		RSAPublicKey pubKey = (RSAPublicKey) cert.getPublicKey();

        while(true) {
        	System.out.println("Waiting");
            Socket connectionSocket = welcomeSocket.accept();
        	System.out.println("Accept");
        	DataInputStream inFromClient = new DataInputStream(connectionSocket.getInputStream());
            DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
            byte clientRequest = inFromClient.readByte();
            System.out.println(clientRequest);
            switch (clientRequest) {
				case REVALIDATION_REQUEST:
	            	System.out.println("Answering to client");
	            	DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd-HH-mm");
	            	LocalDateTime now = LocalDateTime.now();
					String outputTime = dtf.format(now);
					String[] time = outputTime.split("-");
					int[] intTime = new int[time.length];
					for (int i = 0; i < intTime.length; i++) {
						intTime[i] = Integer.parseInt(time[i]);
					}
					byte[] yearBytes = ByteBuffer.allocate(4).putInt(intTime[0]).array();
					byte[] timeBytes = new byte[8];
					System.arraycopy(yearBytes, 0, timeBytes, 0, 4);
					for (int i = 4; i < timeBytes.length; i++) {
						timeBytes[i] = (byte) intTime[i-4];
					}

					MessageDigest md = MessageDigest.getInstance("SHA-256");

					byte[] hashedTime = md.digest(timeBytes);

					Signature signEngine = Signature.getInstance("SHA256withRSA");
					signEngine.initSign(timestampPrivateKey);
					signEngine.update(hashedTime);
					System.out.println("MODULUS:" + pubKey.getModulus());
					System.out.println("EXPONENT:" + pubKey.getPublicExponent());
//					System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(timeBytes));

					byte[] signature = signEngine.sign();
//					System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(signature));
					int length = signature.length + timeBytes.length + 4;
					byte[] lenBytes = ByteBuffer.allocate(4).putInt(length).array();
					byte[] output = new byte[length];
					System.out.println(length);
					System.arraycopy(lenBytes, 0, output, 0, lenBytes.length);
					System.arraycopy(timeBytes, 0, output, lenBytes.length, timeBytes.length);
					System.arraycopy(signature, 0, output, timeBytes.length + lenBytes.length, signature.length);
					
		            outToClient.write(output);
					
					break;
	
				default:
					break;
			}
            if (clientRequest == REVALIDATION_REQUEST) {
			}
        }
	}

}
