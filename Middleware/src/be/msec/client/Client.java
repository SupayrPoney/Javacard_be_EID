package be.msec.client;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;
import helpers.HomeMadeCertificate;

import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
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
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;

import javax.smartcardio.*;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.border.EmptyBorder;


public class Client {

	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GET_SERIAL_INS = 0x24;
	private static final byte SIGN_DATA = 0x26;
	private static final byte ECHO = 0x28;
	private static final byte VALIDATE_TIME = 0x30;
	private static final byte VERIFY_TIME_SIG = 0x32;
	private static final byte AUTHENTICATE_SP = 0x34;
	private static final byte AUTHENTICATE_SP_STEP = 0x36;
	private static final byte END_AUTH = 0x38;
	private static final byte AUTHENTICATE_CARD = 0x40;
	private static final byte QUERY_ATTRIBUTES = 0x42;

	private static final short ISSUER_LEN = 16; 
	private static final short SUBJECT_LEN = 16;
	private static final short DATE_LEN = 8; 

	private static final short EXPONENT_LEN = 3; 
	private static final short MODULUS_LEN = 64; 

	private static final short SIGN_LEN = 64; 
	private static final short SIZE_OF_CERT = ISSUER_LEN + SUBJECT_LEN + 2*DATE_LEN + EXPONENT_LEN + MODULUS_LEN + SIGN_LEN;

	private static final short SIZE_OF_AES = 16;
	private static final short SIZE_OF_PIN = 4;


	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private final static short SW_TIME_UPDATE_FAILED = 0x6302;
	private final static short SW_SP_NOT_AUTH = 0x6303;
	private final static short SW_TIME_SIGNATURE_VERIFICATION_FAILED = 0x6304;
	private final static short SW_CERT_VERIFICATIONR_OR_VALIDATION_FAILED = 0x6305;
	private final static short SW_WRONG_CHALLENGE = 0x6306;
	private final static short SW_WRONG_REQUEST = 0x6307;
	private final static short SW_WRONG_PIN = 0x6308;

	private final static short SIZE_OF_INT_IN_BYTES = 4;
	static boolean simulation = true;
	private static IConnection connectionWithJavacard;

	



	private static void authenticate(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception{
		int response = 0;
		System.out.println("AUTHENTICATE");
		if (!validate_Time(a, r, c)){
			System.out.println("NEED VALIDATION");
			BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));

			Socket clientSocket = new Socket("localhost", 8000);
			DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
			DataInputStream dIn = new DataInputStream(clientSocket.getInputStream());
			outToServer.writeByte(1);

			byte[] message = null;// read length of incoming message
			//4 bytes for len, 8 for date, rest for sign
			byte[] length = new byte[4];
			length[0] = (byte) dIn.read(); 
			length[1] = (byte) dIn.read();
			length[2] = (byte) dIn.read();
			length[3] = (byte) dIn.read();
			//from four bytes to an int
			int len = length[0] << 24 | (length[1] & 0xFF) << 16 | (length[2] & 0xFF) << 8 | (length[3] & 0xFF);
			if(len>0) {
				message = new byte[len - SIZE_OF_INT_IN_BYTES];
				dIn.readFully(message); // read the message
			}
			String year = Integer.toString(message[0] << 24 | (message[1] & 0xFF) << 16 | (message[2] & 0xFF) << 8 | (message[3] & 0xFF));
			String month = Integer.toString((int)message[4]);
			String day = Integer.toString((int)message[5]);
			String hour = Integer.toString((int)message[6]);
			String min = Integer.toString((int)message[7]);

			byte[] toSend = new byte[len];
			System.arraycopy(length, 0, toSend, 0, SIZE_OF_INT_IN_BYTES);
			System.arraycopy(message, 0, toSend, SIZE_OF_INT_IN_BYTES, len - SIZE_OF_INT_IN_BYTES);
			System.out.println(message.length + " bytes read.");

			clientSocket.close();
			System.out.println("Sending to card");
			a = new CommandAPDU(IDENTITY_CARD_CLA, VERIFY_TIME_SIG, 0x00, 0x00,toSend);
			r = c.transmit(a);
			System.out.println(r);
			byte[] dataOut = Arrays.copyOfRange(r.getData(),(short) 5 + len, 5 + len+1); 
			response = dataOut[0];			
		}
		boolean shouldContinue = true;
		if (r == null || r.getSW() == 0x9000) {
			// authenticateSP
			Socket clientSocketSP = new Socket("localhost", 9999);
			DataOutputStream outToServer = new DataOutputStream(clientSocketSP.getOutputStream());
			DataInputStream dIn = new DataInputStream(clientSocketSP.getInputStream());

			byte[] length = new byte[4];
			length[0] = (byte) dIn.read(); 
			length[1] = (byte) dIn.read();
			length[2] = (byte) dIn.read();
			length[3] = (byte) dIn.read();
			//from four bytes to an int
			int len = length[0] << 24 | (length[1] & 0xFF) << 16 | (length[2] & 0xFF) << 8 | (length[3] & 0xFF);
			byte[] message = null;// read length of incoming message
			int command = (int) dIn.read();

			if((len - 1)>0) {
				message = new byte[len - 5];
				dIn.readFully(message); // read the message
			}
			byte[] dataToSendToSP = verify_certificate(message, a, r, c);
			if (dataToSendToSP.length != 0) {
				outToServer.write(dataToSendToSP);

				length[0] = (byte) dIn.read();
				length[1] = (byte) dIn.read();
				length[2] = (byte) dIn.read();
				length[3] = (byte) dIn.read();
				//from four bytes to an int
				int msgLen = length[0] << 24 | (length[1] & 0xFF) << 16 | (length[2] & 0xFF) << 8 | (length[3] & 0xFF);
				System.out.println(msgLen);
				int newMsgLen = msgLen -1;
				command = (int) dIn.read();
				if((msgLen - 1)>0) {
					message = new byte[msgLen - 5];
					dIn.readFully(message); // read the message
				}
				byte[] dataToSend = new byte[newMsgLen];
				System.arraycopy(ByteBuffer.allocate(4).putInt(newMsgLen).array(), 0, dataToSend, 0, 4);
				System.arraycopy(message, 0, dataToSend, 4, message.length);
				r = end_of_auth(dataToSend, a, r, c);
				clientSocketSP.close();

			}
			else{
				shouldContinue = false;
				JOptionPane.showMessageDialog(null, "The certificate could not be verified.");
				
			}
		}
		else{
			JOptionPane.showMessageDialog(null, "The time verification failed.");
		}
		if (r == null || (r.getSW() == 0x9000 && shouldContinue)) {
			//Step 3
			Socket clientSocketSP = new Socket("localhost", 9999);
			DataOutputStream outToServer = new DataOutputStream(clientSocketSP.getOutputStream());
			DataInputStream dIn = new DataInputStream(clientSocketSP.getInputStream());
			System.out.println("WORKED");
			byte[] encryptedChallenge = new byte[SIZE_OF_AES];
			dIn.readFully(encryptedChallenge);

			a = new CommandAPDU(IDENTITY_CARD_CLA, AUTHENTICATE_CARD, 0x00, 0x00, encryptedChallenge);
			r = c.transmit(a);
			if (r.getSW() == 0x9000) {
				short padding = (short) (16 - ((SIGN_LEN + SIZE_OF_CERT)%16));
				byte[] paddedResponse = Arrays.copyOfRange(r.getData(),(short) 6+encryptedChallenge.length, r.getData().length);
				byte[] len =  intToBytes(SIGN_LEN + SIZE_OF_CERT + padding);
				byte[] paddingLen = intToBytes(padding);
				byte[] paddedResponseWithLength = new byte[paddedResponse.length + len.length + paddingLen.length];
				System.arraycopy(len, 0, paddedResponseWithLength, 0, 4);
				System.arraycopy(paddingLen, 0, paddedResponseWithLength, 4, 4);
				System.arraycopy(paddedResponse, 0, paddedResponseWithLength, 8, paddedResponse.length);
				outToServer.write(paddedResponseWithLength);
				step4();	
			}
			else if (r.getSW() == SW_SP_NOT_AUTH){
				JOptionPane.showMessageDialog(null, "The SP is not authenticated.");
				
			}
		}
		else if (r.getSW() == SW_WRONG_CHALLENGE){
			JOptionPane.showMessageDialog(null, "The challenge is incorrect.");
		}
		else{
			JOptionPane.showMessageDialog(null, "Unknown error occured");
		}






		// authenticateCard
		// releaseAttributes
	}
	private static void step4() {
		System.out.println("STEP4");
		ServerSocket welcomeSocket = null;
				
		try {
			welcomeSocket = new ServerSocket(9988);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		Socket connectionSocket = null;
		try {
			connectionSocket = welcomeSocket.accept();
		} catch( Exception e){
			e.printStackTrace();
		}

		System.out.println("Client side accept");
		DataInputStream inFromServer = null;
		DataOutputStream outToServer = null;
		byte len = 0;
		try {
			inFromServer = new DataInputStream(connectionSocket.getInputStream());
			outToServer = new DataOutputStream(connectionSocket.getOutputStream());
			len = inFromServer.readByte();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		byte[] query = new byte[len];
		try {
			inFromServer.readFully(query);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		JPanel panel = new JPanel();
		JLabel label = new JLabel("Enter a password:");
		JPasswordField pass = new JPasswordField(4);
		panel.add(label);
		panel.add(pass);
		String[] options = new String[]{"OK"};
		int option = JOptionPane.showOptionDialog(null, panel, "Insert PIN code",
		                         JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
		                         null, options, options[0]);
		
		char[] passwordChar = pass.getPassword();
		byte[] password = new byte[passwordChar.length];
		for (int i = 0; i < passwordChar.length; i++) {
			password[i] = (byte) Character.getNumericValue(passwordChar[i]);
			
		}
		
		byte[] queryForCard = new byte[2 + SIZE_OF_PIN + len];
		queryForCard[0] = len;
		System.out.println("QUERY LEN : " + query.length);
		System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(query));
		System.arraycopy(query, 0, queryForCard, 1, len);
		System.arraycopy(password, 0, queryForCard, 1 + len, password.length);
		
		
		CommandAPDU a = new CommandAPDU(IDENTITY_CARD_CLA, QUERY_ATTRIBUTES, 0x00, 0x00, queryForCard);
		ResponseAPDU r = null;
		try {
			r = connectionWithJavacard.transmit(a);
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println(r);
	//4.10
		if (r.getSW() == 0x9000) {
			byte[] response = Arrays.copyOfRange(r.getData(),(short) (6+ queryForCard.length), r.getData().length);
		    System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(response));
		    int responseLen = response.length;
		    byte[] toSendToServer = new byte[responseLen + 4];
		    System.arraycopy(intToBytes(responseLen), 0, toSendToServer, 0, 4);
		    System.arraycopy(response, 0, toSendToServer, 4, responseLen);
		    
		    try {
				outToServer.write(toSendToServer);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

            int dialogButton = JOptionPane.YES_NO_OPTION;
		    int dialogResult = JOptionPane.showConfirmDialog (null, "Would You Like to Logout","Warning",dialogButton);
		    try {
				connectionSocket.close();
				welcomeSocket.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		    if(dialogResult == JOptionPane.NO_OPTION){
		    	step4();
		    }
			
		}else{
			try {
				connectionSocket.close();
				welcomeSocket.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if (r.getSW() == SW_WRONG_PIN) {
				JOptionPane.showMessageDialog(null, "Wrong pin code.");
				
			}
			else if(r.getSW() == SW_SP_NOT_AUTH){
				JOptionPane.showMessageDialog(null, "The SP is not authenticated.");
				
			}
			else if(r.getSW() == SW_WRONG_REQUEST){
				JOptionPane.showMessageDialog(null, "The requested fields are not all accessible.");
				
			}
		}
		
		
	}
	private static void logout() {
		// TODO Auto-generated method stub
		
	}
	private static ResponseAPDU end_of_auth(byte[] message, CommandAPDU a, ResponseAPDU r, IConnection c) {

		//Divide in chunks of 250 bytes
		a = new CommandAPDU(IDENTITY_CARD_CLA, END_AUTH, 0x00, 0x00, message);
		try {
			r = c.transmit(a);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return r;

	}
	private static byte[] intToBytes(int input){
		return ByteBuffer.allocate(4).putInt(input).array();
		
	}
	
	private static int bytesToInt(byte[] bytes, int offset){
		return bytes[offset] << 24 | (bytes[offset+1] & 0xFF) << 16 | (bytes[offset+2] & 0xFF) << 8 | (bytes[offset+3] & 0xFF);
	}

	private static byte[] verify_certificate(byte[] message,CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception{
		System.out.println("Sending Certificate Verification Request");
		System.out.println("AUTH1");
		ByteArrayInputStream in = new ByteArrayInputStream(message);
		ObjectInputStream is;
		HomeMadeCertificate certificate = null;
		try {
			is = new ObjectInputStream(in);
			certificate = (HomeMadeCertificate) is.readObject();
		} catch (IOException e) {
			System.out.println("IOException");
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		byte[] bigBuffer = certificate.getAsBytesWithSign();

		System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(bigBuffer));
		System.out.println("Sending a message of " + bigBuffer.length + " bytes");
		byte[] buffer = new byte[250];
		//Divide in chunks of 250 bytes
		for (int i = 0; i < Math.ceil((double)bigBuffer.length/250); i++) {
			System.arraycopy(bigBuffer, 250*i, buffer, 0, Math.min(250, bigBuffer.length - 250*i));
			a = new CommandAPDU(IDENTITY_CARD_CLA, AUTHENTICATE_SP_STEP, 0x00, 0x00, buffer);
			r = c.transmit(a);
			System.out.println(r);
		}
		a = new CommandAPDU(IDENTITY_CARD_CLA, AUTHENTICATE_SP, 0x00, 0x00, new byte[1]);
		r = c.transmit(a);
		if(r.getSW() == 0x9000){
			System.out.println(r);
			byte[] response = Arrays.copyOfRange(r.getData(),(short) (6 + 1), r.getData().length);
			return response;
		}
		else{
			return new byte[0];
		}
	}

	private static boolean validate_Time(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception {
		int dataLen = 8;
		long currentTimeInMillis = System.currentTimeMillis();
		byte[] currentTimeInMillisBytes = ByteBuffer.allocate(8).putLong(currentTimeInMillis).array();
		a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_TIME, 0x00, 0x00,currentTimeInMillisBytes);
		byte[] dataIn = Arrays.copyOfRange(a.getBytes(), 0x05, 5 + 100); 
		r = c.transmit(a);
		System.out.println(r);
		System.out.println(r.getData().length);
		byte[] dataOut = null;
		if (simulation) {
			dataOut = Arrays.copyOfRange(r.getData(),(short) 5 + dataLen, 5 + dataLen+1); 
		}
		else{
			dataOut = Arrays.copyOfRange(r.getData(),(short) 0, (short) 1); 
		}
		int response = dataOut[0];
		System.out.println("RESPONSE: " + response);
		if (response == 1) {
			return false;
		} else {
			return true;
		}

		//		byte[] dateAfter = Arrays.copyOfRange(dataOut, (short)0x00, (short)4);
		//		int d = dateAfter[0] << 24 | (dateAfter[1] & 0xFF) << 16 | (dateAfter[2] & 0xFF) << 8 | (dateAfter[3] & 0xFF);
		//		System.out.println(d);

	}
	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		IConnection c;		// Choose simulation vs real card here

		if (simulation) {
			//Simulation:
			c = new SimulatedConnection();
		} else {
			//Real Card:
			c = new Connection();
			((Connection)c).setTerminal(0); //depending on which cardreader you use
		}

		c.connect(); 
		connectionWithJavacard = c;

		try {

			/*
			 * For more info on the use of CommandAPDU and ResponseAPDU:
			 * See http://java.sun.com/javase/6/docs/jre/api/security/smartcardio/spec/index.html
			 */

			CommandAPDU a = null;
			ResponseAPDU r = null;
			//CommandAPDU(int class,int instruction,bytes param1,bytes param2,int data)

			//getSW: 0x9000 correct, 0x9001 incorrect

			if (simulation) {
				//0. create applet (only for simulator!!!)
				a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,new byte[]{(byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01}, 0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW()!=0x9000) throw new Exception("select installer applet failed");

				a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,new byte[]{0xb, 0x01,0x02,0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x00, 0x00, 0x00}, 0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW()!=0x9000) throw new Exception("Applet creation failed");

				//1. Select applet  (not required on a real card, applet is selected by default)
				a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,new byte[]{0x01,0x02,0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x00, 0x00}, 0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW()!=0x9000) throw new Exception("Applet selection failed");
			}
			
			//2. Send PIN
			authenticate(a,r,c);
			//			if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("PIN INVALID");
			//			else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
			//			System.out.println("PIN Verified");

		} catch (Exception e) {
			throw e;
		}
		finally {
			c.close();  // close the connection with the card
		}


	}

}
