package be.msec.server;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
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


class ServiceProvider {
	public final static byte REVALIDATION_REQUEST = 1;

	public static void main(String[] args) throws Exception {
		final String[] egov1certificate  = {"eGov1","eGov1","8662876358682453906927923349999167622172319988418205169974414540143951423443047315769941049654770380940343634155986149960332903653123348482986444976584947","65537","Apr 25 2017 9:44:25 AM CEST","Apr 25 2018 9:44:25 AM CEST","29CA0FD68FB3979FBDEEEA86CC01DEB56CFDF1E94235D637975DA63E4DE58A759F7A4DC94D0BD919E186FD37BE5D4278A409AF265B4414240904B00FAEEABFB0"};
		ServerSocket welcomeSocket = new ServerSocket(8080);
		

			//connection made with the Middleware
			System.out.println("Waiting");
			Socket connectionSocket = welcomeSocket.accept();
			System.out.println("Accept");
			

			DataInputStream inFromClient = new DataInputStream(connectionSocket.getInputStream());
			DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
			
			//we convert "AuthenticateSp + cetSP to bytes in order to sent them
			byte command = (byte) 1;
			byte[] certificatebytes = String.join(",", egov1certificate).getBytes(); 
			int length = 1 + certificatebytes.length + 4;
			byte[] lenBytes = ByteBuffer.allocate(4).putInt(length).array();
			byte[] output = new byte[length];
			System.arraycopy(lenBytes, 0, output, 0, lenBytes.length);
			System.arraycopy(command, 0, output, lenBytes.length, 1);
			System.arraycopy(certificatebytes, 0, output, 1 + lenBytes.length, certificatebytes.length);
			outToClient.write(output);
			
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



