package be.msec.client;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
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

import javax.smartcardio.*;


public class Client {

	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GET_SERIAL_INS = 0x24;
	private static final byte SIGN_DATA = 0x26;
	private static final byte ECHO = 0x28;
	private static final byte VALIDATE_TIME = 0x30;
	private static final byte AUTHENTICATE_SP = 0x34;
	private static final byte VERIFY_TIME_SIG = 0x32;

	
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	
	private final static short SIZE_OF_INT_IN_BYTES = 4;
	

	
	private static void authenticate(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception{
		int response = 0;
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
	        	System.out.println(len);
	            message = new byte[len - SIZE_OF_INT_IN_BYTES];
	        	System.out.println(message.length);
	            dIn.readFully(message, 0, message.length); // read the message
	        	System.out.println(len);
	        }
	        byte[] toSend = new byte[len];
	        System.arraycopy(length, 0, toSend, 0, SIZE_OF_INT_IN_BYTES);
	        System.arraycopy(message, 0, toSend, SIZE_OF_INT_IN_BYTES, len - SIZE_OF_INT_IN_BYTES);
	        System.out.println(message.length + " bytes read.");
	        
	        clientSocket.close();
	        System.out.println("Sending to card");
			a = new CommandAPDU(IDENTITY_CARD_CLA, VERIFY_TIME_SIG, 0x00, 0x00,toSend);
			r = c.transmit(a);
			byte[] dataOut = Arrays.copyOfRange(r.getData(),(short) 5 + len, 5 + len+1); 
			response = dataOut[0];			
		}
		if (response == 1) {
		}
		
		// authenticateSP
		 Socket clientSocketSP = new Socket("localhost", 8080);
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
	        int command = (int)((byte) dIn.read());

	        if((len - 1)>0) {
	        	System.out.println(len);
	            message = new byte[(len -1)];
	            dIn.readFully(message, 0, message.length); // read the message
	        }
	        
	        switch(command){
	        case 1: 
	        	verify_certificate(message, c);
	        
	        }
		 
		
		

		// authenticateCard
		// releaseAttributes
	}
	
	private static void verify_certificate(byte[] message, IConnection c) throws Exception{
		CommandAPDU a = new CommandAPDU(IDENTITY_CARD_CLA, AUTHENTICATE_SP, 0x00, 0x00, message);
		ResponseAPDU r= c.transmit(a);
		
		
	}
	
	private static boolean validate_Time(CommandAPDU a, ResponseAPDU r, IConnection c) throws Exception {
		// TODO Auto-generated method stub
		int dataLen = 8;
		Date currentTime = new Date();
		LocalDateTime currentTimeDate = currentTime.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
		byte[] yearBytes = ByteBuffer.allocate(4).putInt(currentTimeDate.getYear()).array();
		byte[] dateBytes = new byte[8];
		System.arraycopy(yearBytes, 0, dateBytes, 0, 4);
		dateBytes[4] = (byte) currentTimeDate.getMonthValue();
		dateBytes[5] = (byte) currentTimeDate.getDayOfMonth();
		dateBytes[6] = (byte) currentTimeDate.getHour();
		dateBytes[7] = (byte) currentTimeDate.getMinute();
		a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_TIME, 0x00, 0x00,dateBytes);
		byte[] dataIn = Arrays.copyOfRange(a.getBytes(), 0x05, 5 + 100); 
	//	System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(dataIn));
		r = c.transmit(a);
	//	byte[] date = Arrays.copyOfRange(dataIn, (short)0x00, (short)4);
	//	int b = date[0] << 24 | (date[1] & 0xFF) << 16 | (date[2] & 0xFF) << 8 | (date[3] & 0xFF);
	//	System.out.println(b);
		
		byte[] dataOut = Arrays.copyOfRange(r.getData(),(short) 5 + dataLen, 5 + dataLen+1); 
		int response = dataOut[0];
		System.out.println(response);
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
		IConnection c;
		boolean simulation = true;		// Choose simulation vs real card here

		if (simulation) {
			//Simulation:
			c = new SimulatedConnection();
		} else {
			//Real Card:
			c = new Connection();
			((Connection)c).setTerminal(0); //depending on which cardreader you use
		}
		
		c.connect(); 
		
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
