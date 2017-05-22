package be.msec.smartcard;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

public class IdentityCard extends Applet {
	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	
	private final int SUBJECT = 0;
	private final int ISSUER = 1;
	private final int PUBLIC_KEY_MODULUS = 2;
	private final int PUBLIC_KEY_EXPONENT = 3;
	private final int START_DATE = 4;
	private final int END_DATE = 5;
	private final int SIGNATURE = 6;
	
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GET_SERIAL_INS = 0x24;
	private static final byte SIGN_DATA = 0x26;
	private static final byte ECHO = 0x28;
	private static final byte VALIDATE_TIME = 0x30;
	private static final byte VERIFY_TIME_SIG = 0x32;
	
	private final static byte PIN_TRY_LIMIT =(byte)0x03;
	private final static byte PIN_SIZE =(byte)0x04;
	
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private final static short SW_TIME_UPDATE_FAILED = 0x6302;

	
	private byte[] serial = new byte[]{0x30, 0x35, 0x37, 0x36, 0x39, 0x30, 0x31, 0x05};
	private String javacardPrivateExponent = "4019248479486344703173865994833247965130855891297001843442511551221472431764138438478319727380832243535639804382400663422189381536828238855709495144508993";
	private String javacardModulus = "7225408371738440114436736221839657995687428751040476459668967509666492175788144159467939803507838616521107657543265826137267809302826074208901286160547939";
	
	private String[] javacardCert = {"Javacard","Javacard","7225408371738440114436736221839657995687428751040476459668967509666492175788144159467939803507838616521107657543265826137267809302826074208901286160547939","65537","Apr 25 2017 9:44:25 PM CEST","Apr 25 2018 9:44:25 PM CEST","8DB055AED73FE6206C2233F9735F71C9FDEC54CD9AE1A33375D8D706C9EFB1EC3572D40CF8842096F32544DD8D17414998052EE1C08628C6232A39474E5424FF"};
	
	private String mainCAPublicExponent= "65537";
	private String mainCaPublicModulus = "7615538731625267295662549109333519945267947283726396806643436348704388298950354538429913118402429549367126946884389145577506962581434883709177615141122583";

	
	
	private String govTimePublicExponent = "65537";
	private String govTimePublicModulus = "7069442399809149374049602182035905118617463308097239483861495753479385489754469537665461584246377137057227306597598925117748461915260386529575906451435569";
	//CHECK HERE IF IT'S CORRECT
	int[] timeRatios = {525600, 1440, };
	
	private String[] lastValidationTime = {"2017","05","01","15","06"};
	
	private String[] deltaValidation = {"0","0","1","0","0"};
	
	
	private OwnerPIN pin;
	private byte[] storage = new byte[]{0x30, 0x35, 0x37, 0x36, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
	private byte[] bigStorage = new byte[512];
	private byte[] byteToInt = new byte[]{0x00,0x00,0x00,0x00, 0x04, 0x04};
	
	//TODO nymu,SP - hash(UserID ++ hash(cerificate_SP))
	private String name;
	private String address;
	private String country;
	private String birthDate;
	private short age;
	private char gender;
	byte[] picture;
	
	
	private IdentityCard() {
		/*
		 * During instantiation of the applet, all objects are created.
		 * In this example, this is the 'pin' object.
		 */
		pin = new OwnerPIN(PIN_TRY_LIMIT,PIN_SIZE);
		pin.update(new byte[]{0x01,0x02,0x03,0x04},(short) 0, PIN_SIZE);
		name = "Jean Dupont";
		address = "23 Roadlane Texas";
		country = "Belgium";
		birthDate = "23/04/1965";
		gender = 'M';
		//TODO PICTURE
		//TODO NEW ATTRIBUTES
		
		/*
		 * This method registers the applet with the JCRE on the card.
		 */
		register();
	}

	/*
	 * This method is called by the JCRE when installing the applet on the card.
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new IdentityCard();
	}
	
	private void validate_time(APDU apdu){
		System.out.println("Validate");
		byte[] buffer = apdu.getBuffer();
		short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		short START = 0;
		Util.arrayCopy(buffer, START, storage, START, (short)8);
		short readCount = apdu.setIncomingAndReceive();
		short i = 0;
		while ( bytesLeft > 0){
			
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storage, i, readCount);
			bytesLeft -= readCount;
			i+=readCount;
			readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
		}
		
		Util.arrayCopy(storage, (short)0x00, byteToInt,(short) 0x00, (short)4);
		String year = Integer.toString(byteToInt[0] << 24 | (byteToInt[1] & 0xFF) << 16 | (byteToInt[2] & 0xFF) << 8 | (byteToInt[3] & 0xFF));
		String month = Integer.toString((int)storage[4]);
		String day = Integer.toString((int)storage[5]);
		String hour = Integer.toString((int)storage[6]);
		String min = Integer.toString((int)storage[7]);
		String currentTimeString = String.join("-", new String[]{year,month,day,hour, min});
		
		String lastValidationString = String.join("-", lastValidationTime);
		
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd-HH-mm");
		
		try {
			Date currentDate = format.parse(currentTimeString);
			Date lastValidationDate = format.parse(lastValidationString);
			if((currentDate.getTime() - lastValidationDate.getTime())/(1000*60*60*24) > 1){
				apdu.setOutgoing();
				apdu.setOutgoingLength((short)1);
				Util.setShort(buffer,(short) 0, (short) 1);
				apdu.sendBytes((short) 0x00,(short)1);
				
			}
			else {
				
			}
		} catch (ParseException e) {
			// TODO Auto-generated catch block
		}
	}
	
	
	private void verify_time_signature(APDU apdu) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException{
		//4 bytes for len, 8 for date, rest for sign
		byte[] buffer = apdu.getBuffer();
		short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		short START = 0;
		Util.arrayCopy(buffer, START, bigStorage, START, (short)8);
		short readCount = apdu.setIncomingAndReceive();
		short i = 0;
		while ( bytesLeft > 0){
			
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, bigStorage, i, readCount);
			bytesLeft -= readCount;
			i+=readCount;
			readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
		}
        int len = bigStorage[0] << 24 | (bigStorage[1] & 0xFF) << 16 | (bigStorage[2] & 0xFF) << 8 | (bigStorage[3] & 0xFF);
 
        short sizeOfLen = 4;
        short sizeOfTime = 8;
        byte[] sigToVerify = new byte[len - sizeOfLen - sizeOfTime];
        byte[] timeToVerify = new byte[8];
        
        Util.arrayCopy(bigStorage, (short) sizeOfLen, timeToVerify, (short) 0, (short)(sizeOfTime));
        Util.arrayCopy(bigStorage, (short) (sizeOfLen + sizeOfTime), sigToVerify, (short) 0, (short)(len - sizeOfLen - sizeOfTime));

		RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(govTimePublicModulus), new BigInteger(govTimePublicExponent));
//		System.out.println(new BigInteger(govTimePublicModulus));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKey timestampPubKey =  (RSAPublicKey) factory.generatePublic(spec);
//		System.out.println("MODULUS:" + timestampPubKey.getModulus());
//		System.out.println("EXPONENT:" + timestampPubKey.getPublicExponent());

		Signature signEngine = Signature.getInstance("SHA256withRSA");
		signEngine.initVerify(timestampPubKey);
		MessageDigest md = MessageDigest.getInstance("SHA-256");

		byte[] hashedTime = md.digest(timeToVerify);
		signEngine.update(hashedTime, 0, hashedTime.length);
		
		boolean verifies = signEngine.verify(sigToVerify);
		
		String year = Integer.toString(timeToVerify[0] << 24 | (timeToVerify[1] & 0xFF) << 16 | (timeToVerify[2] & 0xFF) << 8 | (timeToVerify[3] & 0xFF));
		String month = Integer.toString((int)timeToVerify[4]);
		String day = Integer.toString((int)timeToVerify[5]);
		String hour = Integer.toString((int)timeToVerify[6]);
		String min = Integer.toString((int)timeToVerify[7]);
		String timeString = String.join("-", new String[]{year,month,day,hour, min});
		
		String lastValidationString = String.join("-", lastValidationTime);

		try {
			SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd-HH-mm");
			Date timeDate = format.parse(timeString);
			Date lastValidationDate = format.parse(lastValidationString);
			short response = 1;
			if(verifies || (timeDate.getTime() > lastValidationDate.getTime())){
				response = 0;
			}
			else{
				lastValidationTime = new String[]{year,month,day,hour, min};
			}
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)1);
			apdu.sendBytesLong(new byte[]{(byte)response},(short)0,(short)1);
			
		} catch (ParseException e) {
			// TODO Auto-generated catch block
		}


		
	}
	/*
	 * If no tries are remaining, the applet refuses selection.
	 * The card can, therefore, no longer be used for identification.
	 */
	public boolean select() {
		if (pin.getTriesRemaining()==0)
			return false;
		
		return true;
	}

	/*
	 * This method is called when the applet is selected and an APDU arrives.
	 */
	public void process(APDU apdu) throws ISOException {
		//A reference to the buffer, where the APDU data is stored, is retrieved.
		byte[] buffer = apdu.getBuffer();
		
		//If the APDU selects the applet, no further processing is required.
		if(this.selectingApplet())
			return;
		
		//Check whether the indicated class of instructions is compatible with this applet.
		if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA)ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		//A switch statement is used to select a method depending on the instruction
		switch(buffer[ISO7816.OFFSET_INS]){
		case VALIDATE_PIN_INS:
			validatePIN(apdu);
			break;
		case GET_SERIAL_INS:
			getSerial(apdu);
			break;
		case SIGN_DATA:
			sign_data(apdu);
			break;
		case ECHO:
			echo(apdu);
			break;
		case VALIDATE_TIME:
			validate_time(apdu);
			break;
		case VERIFY_TIME_SIG:
			try {
				verify_time_signature(apdu);
			} catch (Exception e) {}
			break;
			
		//If no matching instructions are found it is indicated in the status word of the response.
		//This can be done by using this method. As an argument a short is given that indicates
		//the type of warning. There are several predefined warnings in the 'ISO7816' class.
		default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	
	
	private void echo(APDU apdu){
		System.out.println("Echo");
		byte[] buffer = apdu.getBuffer();
		short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		short START = 0;
		Util.arrayCopy(buffer, START, storage, START, (short)8);
		short readCount = apdu.setIncomingAndReceive();
		short i = ISO7816.OFFSET_CDATA;
		while ( bytesLeft > 0){
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storage, i, readCount);
			bytesLeft -= readCount;
			i+=readCount;
			readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
		}
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)storage.length);
		apdu.sendBytesLong(storage,(short)0,(short)storage.length);
		
		 
	}
	

	
	private void sign_data(APDU apdu) {
		if(!pin.isValidated()){
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}
		else{
			//TODO SIGN
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)serial.length);
			apdu.sendBytesLong(serial,(short)0,(short)serial.length);
			
		}
		
	}

	/*
	 * This method is used to authenticate the owner of the card using a PIN code.
	 */
	private void validatePIN(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		//The input data needs to be of length 'PIN_SIZE'.
		//Note that the byte values in the Lc and Le fields represent values between
		//0 and 255. Therefore, if a short representation is required, the following
		//code needs to be used: short Lc = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		if(buffer[ISO7816.OFFSET_LC]==PIN_SIZE){
			//This method is used to copy the incoming data in the APDU buffer.
			apdu.setIncomingAndReceive();
			//Note that the incoming APDU data size may be bigger than the APDU buffer 
			//size and may, therefore, need to be read in portions by the applet. 
			//Most recent smart cards, however, have buffers that can contain the maximum
			//data size. This can be found in the smart card specifications.
			//If the buffer is not large enough, the following method can be used:
			//
			//byte[] buffer = apdu.getBuffer();
			//short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
			//Util.arrayCopy(buffer, START, storage, START, (short)5);
			//short readCount = apdu.setIncomingAndReceive();
			//short i = ISO7816.OFFSET_CDATA;
			//while ( bytesLeft > 0){
			//	Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storage, i, readCount);
			//	bytesLeft -= readCount;
			//	i+=readCount;
			//	readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
			//}
			if (pin.check(buffer, ISO7816.OFFSET_CDATA,PIN_SIZE)==false)
				ISOException.throwIt(SW_VERIFICATION_FAILED);
		}else ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}
	
	/*
	 * This method checks whether the user is authenticated and sends
	 * the identity file.
	 */
	private void getSerial(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'identityFile' with offset '0' and length 'identityFile.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)serial.length);
			apdu.sendBytesLong(serial,(short)0,(short)serial.length);
		}
	}
}
