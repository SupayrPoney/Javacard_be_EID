package be.msec.server;

import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;






public class ServiceProvider {
	public final static byte REVALIDATION_REQUEST = 1;
	private static final short SIZE_OF_CHALLENGE = 2;
	private static final short ISSUER_LEN = 16; 
	private static final short SUBJECT_LEN = 16;
	private static final short DATE_LEN = 8; 
	private static final short SIZE_OF_AUTH = 4;

	private static final short EXPONENT_LEN = 3; 
	private static final short MODULUS_LEN = 64; 
	
	private byte[] nym = new byte[32];
	private byte[] name = new byte[32];
	private byte[] address = new byte[48];
	private byte[] country = new byte[2];
	private byte[] birthDate = new byte[6];
	private byte donor;
	private byte age;
	private byte gender;
	byte[] picture = new byte[]{0x30, 0x35, 0x37, 0x36, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};

	private final byte NYM_INDEX = 9;
	private final byte NAME_INDEX = 1;
	private final byte ADDRESS_INDEX = 2;
	private final byte COUNTRY_INDEX = 3;
	private final byte BIRTHDATE_INDEX = 4;
	private final byte DONOR_INDEX = 5;
	private final byte AGE_INDEX = 6;
	private final byte GENDER_INDEX = 7;
	private final byte PICTURE_INDEX = 8;
	
	
	private byte[] authText = {65,117,116,104};

	private byte[] mainCAPublicExponent = {1,0,1};
	private byte[] mainCAPublicModulus = {0,-111,103,-6,88,-39,13,27,-42,85,-123,-123,-92,101,-57,-34,83,42,-118,-101,115,38,22,-113,-108,-21,97,-21,99,-18,-77,54,58,32,115,-47,-80,-71,53,43,-3,81,88,114,-25,-114,125,-12,-53,108,25,-49,37,15,66,20,8,52,-99,-49,-79,23,81,50,23};


	private static final short SIGN_LEN = 64; 
	private static final short SIZE_OF_CERT = ISSUER_LEN + SUBJECT_LEN + 2*DATE_LEN + EXPONENT_LEN + MODULUS_LEN + SIGN_LEN;
	
	String SPName;
	private ServerSocket clientComSocket;
	private SecretKey symmetricKey;
	
	public ServiceProvider() {
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
	
	public void start(String name) {
		SPName = name;
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
				byte[] challengeAndSubject = new byte[SIZE_OF_CHALLENGE+SUBJECT_LEN];
				System.arraycopy(challengeAndSubjectPadded, 0, challengeAndSubject, 0, challengeAndSubject.length);
				byte[] challengeBytes = Arrays.copyOfRange(challengeAndSubject, 0, SIZE_OF_CHALLENGE);
				byte[] certSubjectBytes = Arrays.copyOfRange(challengeAndSubject, SIZE_OF_CHALLENGE, SIZE_OF_CHALLENGE + SUBJECT_LEN);
				String certSubject = new String(certSubjectBytes, "UTF-8");
				
				
			// Step 2.11
				System.out.println("HERE SP LEN");
				System.out.println(this.SPName.length() + "-" + certSubject.length());
				byte[] spNameBuffer = new byte[SUBJECT_LEN];
				System.arraycopy(SPName.getBytes(), 0, spNameBuffer, 0, SPName.getBytes().length);
				String paddedSPName = new String(spNameBuffer);
				if (!paddedSPName.equals(certSubject)) {
					JOptionPane.showMessageDialog(null, "The subject does not correspond to the certificate.");
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
				outToClient.write(dataToSend);
				connectionSocket.close();
		        
			//step 3
				step3(welcomeSocket, symKey);
				
			} catch (IOException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (UnrecoverableKeyException e) {
				e.printStackTrace();
			} catch (KeyStoreException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			}
			return ; 
    }
	
	private String step3( ServerSocket welcomeSocket, SecretKey symKey){
		clientComSocket = welcomeSocket;
		symmetricKey = symKey;
		Socket connectionSocket = null;
		try {
			connectionSocket = welcomeSocket.accept();
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("Accept Step 3\n");
		
		DataInputStream inFromClient = null;
		try {
			inFromClient = new DataInputStream(connectionSocket.getInputStream());
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		DataOutputStream outToClient = null;
		try {
			outToClient = new DataOutputStream(connectionSocket.getOutputStream());
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
		SecureRandom random = new SecureRandom();
		byte[] challenge= new byte[SIZE_OF_CHALLENGE];
		random.nextBytes(challenge);

	    System.out.println("Challenge: " + javax.xml.bind.DatatypeConverter.printHexBinary(challenge));
		Cipher aesenc;
		byte[] encryptedChallenge = null;
		IvParameterSpec iv = null;
		try {
			aesenc = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			iv = new IvParameterSpec("0000111122223333".getBytes("UTF-8"));
			aesenc.init(Cipher.ENCRYPT_MODE, symKey, iv);
			encryptedChallenge = aesenc.doFinal(challenge);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
		
		try {
			outToClient.write(encryptedChallenge);
		} catch (IOException e) {
			e.printStackTrace();
		}
	// step 3.8
		byte[] length = new byte[4];
		byte[] paddingLength = new byte[4];
		try {
			length[0] = (byte) inFromClient.read();
			length[1] = (byte) inFromClient.read();
			length[2] = (byte) inFromClient.read();
			length[3] = (byte) inFromClient.read();
			paddingLength[0] = (byte) inFromClient.read();
			paddingLength[1] = (byte) inFromClient.read();
			paddingLength[2] = (byte) inFromClient.read();
			paddingLength[3] = (byte) inFromClient.read();
		} catch (IOException e) {
			e.printStackTrace();
		}
		//from four bytes to an int
		int msgLen = length[0] << 24 | (length[1] & 0xFF) << 16 | (length[2] & 0xFF) << 8 | (length[3] & 0xFF);
		int paddingLen = paddingLength[0] << 24 | (paddingLength[1] & 0xFF) << 16 | (paddingLength[2] & 0xFF) << 8 | (paddingLength[3] & 0xFF);
		System.out.println("TOTAL LEN: "+ msgLen);
		System.out.println("PADDING LEN: "+ paddingLen);
		byte[] paddedEncryptedData = null;
		if (msgLen > 0) {
			try {
				paddedEncryptedData = new byte[msgLen];
				inFromClient.readFully(paddedEncryptedData);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		try {
			connectionSocket.close();
		} catch (IOException e2) {
			e2.printStackTrace();
		}
	// step 3.9
		Cipher aesdecCipher = null;
		byte[] certAndSignPadded = null;
		try {
			aesdecCipher = Cipher.getInstance("AES/CBC/NOPADDING");
			aesdecCipher.init(Cipher.DECRYPT_MODE, symKey, iv);
			certAndSignPadded = aesdecCipher.doFinal(paddedEncryptedData);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	// step 3.10
		byte[] certificate = new byte[SIZE_OF_CERT];
		byte[] signedHashedChallenge = new byte[SIGN_LEN];
		
		System.arraycopy(certAndSignPadded, 0, certificate, 0, SIZE_OF_CERT);
		System.arraycopy(certAndSignPadded, SIZE_OF_CERT, signedHashedChallenge, 0, SIGN_LEN);
		
		byte[] certificateSignature = new byte[SIGN_LEN];
		byte[] dataToCheck = new byte[SUBJECT_LEN + ISSUER_LEN + MODULUS_LEN + EXPONENT_LEN + DATE_LEN + DATE_LEN];
		byte[] javacardPublicKeyModulus = new byte[MODULUS_LEN];
		byte[] javacardPublicKeyExponent = new byte[EXPONENT_LEN];
		

		System.arraycopy(certificate, 0, dataToCheck, 0, SUBJECT_LEN + ISSUER_LEN + MODULUS_LEN + EXPONENT_LEN + DATE_LEN + DATE_LEN);
		System.arraycopy(dataToCheck, SUBJECT_LEN + ISSUER_LEN, javacardPublicKeyModulus, 0, MODULUS_LEN);
		System.arraycopy(dataToCheck, SUBJECT_LEN + ISSUER_LEN + MODULUS_LEN, javacardPublicKeyExponent, 0, EXPONENT_LEN);
		
		System.arraycopy(certificate, (SUBJECT_LEN + ISSUER_LEN + MODULUS_LEN + EXPONENT_LEN + DATE_LEN + DATE_LEN), certificateSignature, 0, SIGN_LEN);
		
		System.out.println("CERTIFICATE:\n" + javax.xml.bind.DatatypeConverter.printHexBinary(certificate));
		System.out.println("SIGNATURE:\n" + javax.xml.bind.DatatypeConverter.printHexBinary(certificateSignature));
		
		RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(mainCAPublicModulus), new BigInteger(mainCAPublicExponent));
		KeyFactory factory;
		Signature signEngine = null;
		try {
			factory = KeyFactory.getInstance("RSA");
			RSAPublicKey mainCAPubKey =  (RSAPublicKey) factory.generatePublic(spec);
			signEngine = Signature.getInstance("SHA1withRSA");
			signEngine.initVerify(mainCAPubKey);
			signEngine.update(dataToCheck);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		boolean verifies = false;
		try {
			verifies = signEngine.verify(certificateSignature);
		} catch (SignatureException e) {
			// 
			e.printStackTrace();
		}
		if (verifies) {
	// step 3.11
			byte[] uncroppedJavacardPublicKeyModulus = new byte[javacardPublicKeyModulus.length+1];
			uncroppedJavacardPublicKeyModulus[0] = 0;
			System.arraycopy(javacardPublicKeyModulus, 0, uncroppedJavacardPublicKeyModulus, 1, javacardPublicKeyModulus.length);
			
			
			RSAPublicKeySpec javacardSpec = new RSAPublicKeySpec(new BigInteger(uncroppedJavacardPublicKeyModulus), new BigInteger(javacardPublicKeyExponent));
			KeyFactory javacardFactory;
			Signature javacardSignEngine = null;
			

			byte[] concatChallengeAuth = new byte[SIZE_OF_CHALLENGE + SIZE_OF_AUTH];
			System.arraycopy(challenge, (short) 0, concatChallengeAuth, (short) 0, SIZE_OF_CHALLENGE);
			System.arraycopy(authText, (short) 0, concatChallengeAuth, SIZE_OF_CHALLENGE, SIZE_OF_AUTH);
			System.out.println("BEFORE HASHING: " + javax.xml.bind.DatatypeConverter.printHexBinary(concatChallengeAuth));
			MessageDigest md = null;
			try {
				md = MessageDigest.getInstance("SHA-256");
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
			}
			byte[] hashedConcatChallengeAuth =  md.digest(concatChallengeAuth);
			System.out.println("AFTER HASHING: " + javax.xml.bind.DatatypeConverter.printHexBinary(hashedConcatChallengeAuth));
			
			try {
				javacardFactory = KeyFactory.getInstance("RSA");
				RSAPublicKey javacardPubKey =  (RSAPublicKey) javacardFactory.generatePublic(javacardSpec);
				javacardSignEngine = Signature.getInstance("SHA1withRSA");
				javacardSignEngine.initVerify(javacardPubKey);
				javacardSignEngine.update(hashedConcatChallengeAuth);
				boolean javacardSignVerfies = javacardSignEngine.verify(signedHashedChallenge);
				if (! javacardSignVerfies) {
					JOptionPane.showMessageDialog(null, "The javacard signing verification failed.");
					return "";
				}
				
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				e.printStackTrace();
			} catch (SignatureException e) {
				e.printStackTrace();
			}
			
		}else{

			JOptionPane.showMessageDialog(null, "The javacard certificate verification failed.");
		}
		return "";
		


		//System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(certAndSignPadded));
		
	}
	

	public void step4(byte[] query){

		Socket clientSocketSP;
		DataOutputStream outToClient = null;
		DataInputStream inFromClient  = null;
		try {
			clientSocketSP = new Socket("localhost", 9988);
			outToClient = new DataOutputStream(clientSocketSP.getOutputStream());
			inFromClient = new DataInputStream(clientSocketSP.getInputStream());
			byte[] queryWithLen = new byte[1 + query.length];
			queryWithLen[0] = (byte) query.length;
			System.arraycopy(query, 0, queryWithLen, 1, query.length);
			outToClient.write(queryWithLen);
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	// step 4.10
		byte[] queryResponse = null;
		try {
			byte[] length = new byte[4];
			length[0] = (byte) inFromClient.read();
			length[1] = (byte) inFromClient.read();
			length[2] = (byte) inFromClient.read();
			length[3] = (byte) inFromClient.read();
			int len = bytesToInt(length, 0);
			System.out.println(len);
			queryResponse = new byte[len];
			inFromClient.readFully(queryResponse);
			System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(queryResponse));
		} catch (IOException e) {
			e.printStackTrace();
		}

		Cipher aesdecCipher = null;
		byte[] paddedQueryResult = null;
		try {
			aesdecCipher = Cipher.getInstance("AES/CBC/NOPADDING");
			IvParameterSpec iv = new IvParameterSpec("0000111122223333".getBytes("UTF-8"));
			aesdecCipher.init(Cipher.DECRYPT_MODE, symmetricKey, iv);
			paddedQueryResult = aesdecCipher.doFinal(queryResponse);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		String display = "";
		int offset = 0;
		System.out.println(query.length);
		for (int i = 0; i < query.length; i++) {
			System.out.println(query[i]);
			byte requestedData = query[i];
			System.out.println(requestedData);
			display += "\n";
			switch (requestedData) {
		// step 4.9
			case NYM_INDEX:
				System.arraycopy(paddedQueryResult, offset, nym, 0, (short) nym.length);
				display += ("NYM: " + javax.xml.bind.DatatypeConverter.printHexBinary(nym));
				offset += nym.length;
				break;
			case NAME_INDEX:
				System.arraycopy(paddedQueryResult, offset, name, 0, (short) name.length);
				display += ("NAME: " + new String(name));
				offset += name.length;
				
				break;
			case ADDRESS_INDEX:
				System.arraycopy(paddedQueryResult, offset, address, 0, (short) address.length);
				display += ("ADDRESS: " + new String(address));
				offset += address.length;
				
				break;
			case COUNTRY_INDEX:
				System.arraycopy(paddedQueryResult, offset, country, 0, (short) country.length);
				display += ("COUNTRY: " + new String(country));
				offset += country.length;
				
				break;
			case BIRTHDATE_INDEX:
				System.arraycopy(paddedQueryResult, offset, birthDate, 0, (short) birthDate.length);
				int year = bytesToInt(birthDate, 0);
				int month = birthDate[4];
				int day = birthDate[5];
				display += ("BIRTH DATE: " + day + "/" + month +"/" + year);
				
				offset += birthDate.length;
				
				break;
			case DONOR_INDEX:
				donor = paddedQueryResult[offset];
				display += ("DONOR: " + donor);
				offset += 1;
				break;
			case AGE_INDEX:
				age = paddedQueryResult[offset];
				display += ("AGE: " + age);
				offset += 1;
				
				break;
			case GENDER_INDEX:
				gender = paddedQueryResult[offset];
				display += ("GENDER: " + gender);
				offset += 1;
				
				break;
			case PICTURE_INDEX:
				System.arraycopy(paddedQueryResult, offset, picture, 0, (short) picture.length);
				offset += picture.length;
				
				break;

			default:
				break;
			}
			System.out.println(display);
			JFrame frame = new JFrame("JOptionPane showMessageDialog example");
	        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

	        final JPanel panel = new JPanel();
	        JTextArea textArea = new JTextArea(
	                display, 
	                6, 
	                20);
	        textArea.setLineWrap(true);
	        textArea.setWrapStyleWord(true);
	        textArea.setOpaque(false);
	        textArea.setEditable(false);

	        panel.add(textArea);
	        frame.add(panel);
	        frame.pack();
	        frame.setVisible(true);
//		    System.exit(0);
		}
		

		//TODO
		
		
	}
}



