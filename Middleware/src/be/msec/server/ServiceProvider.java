package be.msec.server;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class ServiceProvider extends Thread{
	public final static byte REVALIDATION_REQUEST = 1;
	private static final short SIZE_OF_CHALLENGE = 2;
	private static final short SIZE_OF_SUBJECT = 16;
	String SPName;
	
	public ServiceProvider(String name) throws Exception {
		SPName = name;
	}

	private PrivateKey getPrivateKey() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException{
		KeyStore keyStore = KeyStore.getInstance("JKS");
		String fileName = "/home/supayrponey/Cours/2016-2017/SecurityInComputing/Project/project.jks";
		FileInputStream fis = new FileInputStream(fileName);
		keyStore.load(fis, "ThisIs4V3ryS4f3Pa$$w0rd".toCharArray());
		fis.close();

		return (PrivateKey) keyStore.getKey(SPName, "test".toCharArray());
	}
	
	private static int bytesToInt(byte[] bytes, int offset){
		return bytes[offset] << 24 | (bytes[offset+1] & 0xFF) << 16 | (bytes[offset+2] & 0xFF) << 8 | (bytes[offset+3] & 0xFF);

	}
	
	public void run() {
		ServerSocket welcomeSocket = null;
		File file = new File("certs/" + SPName + ".crt");
		FileInputStream fin = null;
		byte[] certificatebytes = null;
		try {
			// create FileInputStream object
			fin = new FileInputStream(file);

			 certificatebytes = new byte[(int)file.length()];
			
			// Reads up to certain bytes of data from this input stream into an array of bytes.
			fin.read(certificatebytes);
		}
		catch (FileNotFoundException e) {
			System.out.println("File not found" + e);
		}
		catch (IOException ioe) {
			System.out.println("Exception while reading file " + ioe);
		}
		finally {
			// close the streams using close method
			try {
				if (fin != null) {
					fin.close();
				}
			}
			catch (IOException ioe) {
				System.out.println("Error while closing stream: " + ioe);
			}
		}
		
		try {
			welcomeSocket = new ServerSocket(9999);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		

			//connection made with the Middleware
			System.out.println("Waiting");
			Socket connectionSocket = null;
			try {
				connectionSocket = welcomeSocket.accept();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			System.out.println("Accept");
			
			DataInputStream inFromClient = null;
			try {
				inFromClient = new DataInputStream(connectionSocket.getInputStream());
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			DataOutputStream outToClient = null;
			try {
				outToClient = new DataOutputStream(connectionSocket.getOutputStream());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			//we convert "AuthenticateSp + cetSP to bytes in order to sent them
			byte[] command = {0x01};
			int lengthToSend = 1 + certificatebytes.length + 4;
			byte[] lenBytes = ByteBuffer.allocate(4).putInt(lengthToSend).array();
			byte[] output = new byte[lengthToSend];
			System.arraycopy(lenBytes, 0, output, 0, lenBytes.length);
			System.arraycopy(command, 0, output, lenBytes.length, 1);
			System.arraycopy(certificatebytes, 0, output, 1 + lenBytes.length, certificatebytes.length);
			System.out.println(output.length);
			try {
				outToClient.write(output);
				System.out.println("Sent to client!");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			// Step 2.8
	        byte[] lengthToReceive = new byte[4];
	        try {
				lengthToReceive[0] = (byte) inFromClient.read();
		        lengthToReceive[1] = (byte) inFromClient.read();
		        lengthToReceive[2] = (byte) inFromClient.read();
		        lengthToReceive[3] = (byte) inFromClient.read();
		        int encryptedKeyLen = bytesToInt(lengthToReceive, 0);
		        lengthToReceive[0] = (byte) inFromClient.read(); 
		        lengthToReceive[1] = (byte) inFromClient.read();
		        lengthToReceive[2] = (byte) inFromClient.read();
		        lengthToReceive[3] = (byte) inFromClient.read();
		        int encryptedChallengeLen = bytesToInt(lengthToReceive, 0);
		        
		        byte[] data = new byte[encryptedKeyLen+encryptedChallengeLen];
				inFromClient.readFully(data);
				byte[] encryptedKey = new byte[encryptedKeyLen];
				System.arraycopy(data, 0, encryptedKey, 0, encryptedKeyLen);
				byte[] encryptedChallenge = new byte[encryptedChallengeLen];
				System.arraycopy(data, encryptedKeyLen, encryptedChallenge, 0, encryptedChallengeLen);
				
			//Step 2.9
				Cipher rsadec = Cipher.getInstance("RSA");
				rsadec.init(Cipher.DECRYPT_MODE, getPrivateKey());
				byte[] symKeyByte = rsadec.doFinal(encryptedKey);
				SecretKey symKey = new SecretKeySpec(symKeyByte, "AES");
				
			//Step 2.10
	            IvParameterSpec iv = new IvParameterSpec("0000111122223333".getBytes("UTF-8"));
				Cipher aesdec = Cipher.getInstance("AES/CBC/NOPADDING");
				aesdec.init(Cipher.DECRYPT_MODE, symKey, iv);
				byte[] challengeAndSubjectPadded = aesdec.doFinal(encryptedChallenge);
				byte[] challengeAndSubject = new byte[SIZE_OF_CHALLENGE+SIZE_OF_SUBJECT];
				System.arraycopy(challengeAndSubjectPadded, 0, challengeAndSubject, 0, challengeAndSubject.length);
				byte[] challengeBytes = Arrays.copyOfRange(challengeAndSubject, 0, SIZE_OF_CHALLENGE);
				byte[] certSubjectBytes = Arrays.copyOfRange(challengeAndSubject, SIZE_OF_CHALLENGE, SIZE_OF_CHALLENGE + SIZE_OF_SUBJECT);
				String certSubject = new String(certSubjectBytes, "UTF-8");
				
				
			// Step 2.11
				System.out.println("HERE SP LEN");
				System.out.println(this.SPName.length() + "-" + certSubject.length());
				byte[] spNameBuffer = new byte[SIZE_OF_SUBJECT];
				System.arraycopy(SPName.getBytes(), 0, spNameBuffer, 0, SPName.getBytes().length);
				String paddedSPName = new String(spNameBuffer);
				if (!paddedSPName.equals(certSubject)) {
					System.out.println("Test");
					return;
				}
				
			// Step 2.12
		        short challenge = (short) (challengeBytes[0] << 8 | (challengeBytes[1] & 0xFF));
		        short newChallenge = (short) (challenge + 1);
				Cipher aesenc = Cipher.getInstance("AES/CBC/NOPADDING");
				aesenc.init(Cipher.ENCRYPT_MODE, symKey, iv);
				byte[] newChallengeBytes = ByteBuffer.allocate(2).putShort(newChallenge).array();
				System.out.println(newChallengeBytes.length);
				byte[] paddedNewChallenge = new byte[16];
				Arrays.fill(paddedNewChallenge, (byte) 0);
				System.arraycopy(newChallengeBytes, 0, paddedNewChallenge, 0, newChallengeBytes.length);
				
				byte[] encryptedResponse = aesenc.doFinal(paddedNewChallenge);

				command[0] = (byte) 2;
				lengthToSend = 1 + 4 + encryptedResponse.length;
				lenBytes = ByteBuffer.allocate(4).putInt(lengthToSend).array();
				byte[] dataToSend = new byte[lengthToSend] ;
				System.arraycopy(lenBytes, 0, dataToSend, 0, lenBytes.length);
				System.arraycopy(command, 0, dataToSend, lenBytes.length, 1);
				System.arraycopy(encryptedResponse, 0, dataToSend, 1 + lenBytes.length, encryptedResponse.length);
				System.out.println(dataToSend.length);
				System.out.println(symKey.getEncoded());
				outToClient.write(dataToSend);
				connectionSocket.close();
		        
			//step 3
				step3(welcomeSocket, symKey);
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (UnrecoverableKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 
    }
	
	private void step3( ServerSocket welcomeSocket, SecretKey symKey){
		Socket connectionSocket = null;
		try {
			connectionSocket = welcomeSocket.accept();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Accept Step 3");
		
		DataInputStream inFromClient = null;
		try {
			inFromClient = new DataInputStream(connectionSocket.getInputStream());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		DataOutputStream outToClient = null;
		try {
			outToClient = new DataOutputStream(connectionSocket.getOutputStream());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		SecureRandom random = new SecureRandom();
		byte[] challenge= new byte[SIZE_OF_CHALLENGE];
		random.nextBytes(challenge);

	    System.out.println("Challenge: " + javax.xml.bind.DatatypeConverter.printHexBinary(challenge));
		Cipher aesenc;
		byte[] encryptedChallenge = null;
		try {
			aesenc = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	        IvParameterSpec iv = new IvParameterSpec("0000111122223333".getBytes("UTF-8"));
			aesenc.init(Cipher.ENCRYPT_MODE, symKey, iv);
			encryptedChallenge = aesenc.doFinal(challenge);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		try {
			outToClient.write(encryptedChallenge);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
			
			
//		      byte[] key = null;
//	            byte[] message = null;
//	            SecretKey symkey = null; 
//	            RSAPrivateKey SPPrivateKey= null;
//	            Cipher rsadec;
//				try {
//					rsadec = Cipher.getInstance("RSA");
//					rsadec.init(Cipher.DECRYPT_MODE, SPPrivateKey);
//		            byte[] encodedKey =rsadec.doFinal(key);
//		            symkey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "RSA");
//		            Cipher rsasymdec = Cipher.getInstance("RSA");
//		            rsasymdec.init(Cipher.DECRYPT_MODE, symkey);
//		            byte[] decriptedmessage = rsasymdec.doFinal(message);
//		            byte[] challenge = Arrays.copyOfRange(decriptedmessage, 0, 20);
//		            String subject = new String(Arrays.copyOfRange(decriptedmessage, 21,decriptedmessage.length));
//		            if (!(subject.equals(SPName))){
		            	//here we have to abort
		            	
		           //we create the challenge + 1 
		            // i'm doing weird things here.. what if the original challenge + 1 is no longer 20 bytes? etc
		            
//		            ByteBuffer wrapped = ByteBuffer.wrap(challenge); // big-endian by default
//		            short num = wrapped.getShort();
//		            short newnum = (short) (num + 1); 
//		            ByteBuffer dbuf = ByteBuffer.allocate(20);
//		            dbuf.putShort(newnum);
//		            byte[] responseChalleng = dbuf.array(); 
		            
		            
		            
		            
		            
		            
		            
//				} catch (NoSuchAlgorithmException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (NoSuchPaddingException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (InvalidKeyException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (IllegalBlockSizeException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				} catch (BadPaddingException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
	            
			
			
			
	
	
	public void counter(){
		int i= 1 ; 
		switch(i){
		case 1:
			i++; 
			break;
		}
		
	}
}



