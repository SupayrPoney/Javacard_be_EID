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
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;



public class ServiceProvider extends Thread{
	public final static byte REVALIDATION_REQUEST = 1;
	String SPName;
	public ServiceProvider(String name) throws Exception {
		SPName = name;
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
			

			try {
				DataInputStream inFromClient = new DataInputStream(connectionSocket.getInputStream());
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
			int length = 1 + certificatebytes.length + 4;
			byte[] lenBytes = ByteBuffer.allocate(4).putInt(length).array();
			byte[] output = new byte[length];
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
			
			
		      byte[] key = null;
	            byte[] message = null;
	            SecretKey symkey = null; 
	            RSAPrivateKey SPPrivateKey= null;
	            Cipher rsadec;
				try {
					rsadec = Cipher.getInstance("RSA");
					rsadec.init(Cipher.DECRYPT_MODE, SPPrivateKey);
		            byte[] encodedKey =rsadec.doFinal(key);
		            symkey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "RSA");
		            Cipher rsasymdec = Cipher.getInstance("RSA");
		            rsasymdec.init(Cipher.DECRYPT_MODE, symkey);
		            byte[] decriptedmessage = rsasymdec.doFinal(message);
		            byte[] challenge = Arrays.copyOfRange(decriptedmessage, 0, 20);
		            String subject = new String(Arrays.copyOfRange(decriptedmessage, 21,decriptedmessage.length));
		            if (!(subject.equals(SPName))){
		            	//here we have to abort
		            	
		            }
		           //we create the challenge + 1 
		            // i'm doing weird things here.. what if the original challenge + 1 is no longer 20 bytes? etc
		            
		            ByteBuffer wrapped = ByteBuffer.wrap(challenge); // big-endian by default
		            short num = wrapped.getShort();
		            short newnum = (short) (num + 1); 
		            ByteBuffer dbuf = ByteBuffer.allocate(20);
		            dbuf.putShort(newnum);
		            byte[] responseChalleng = dbuf.array(); 
		            
		            
		            
		            
		            
		            
		            
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IllegalBlockSizeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
	            
			
			
			
		}
	
	
	public void counter(){
		int i= 1 ; 
		switch(i){
		case 1:
			i++; 
			break;
		}
		
	}
}



