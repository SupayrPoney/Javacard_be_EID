package be.msec.smartcard;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import helpers.HomeMadeCertificate;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
//import javacard.security.Signature;



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
	private static final byte AUTHENTICATE_SP = 0x34;
	private static final byte AUTHENTICATE_SP_STEP = 0x36;
	private static final byte END_AUTH = 0x38;
	
	private static final short ISSUER_LEN = 16; 
	private static final short SUBJECT_LEN = 16;
	private static final short DATE_LEN = 8; 

	private static final short EXPONENT_LEN = 3; 
	private static final short MODULUS_LEN = 64; 

	private static final short SIGN_LEN = 64; 
	
	private static boolean auth = false;

	private static final short SIZE_OF_CHALLENGE = 2;
	
	private final static byte PIN_TRY_LIMIT =(byte)0x03;
	private final static byte PIN_SIZE =(byte)0x04;
	
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private final static short SW_TIME_UPDATE_FAILED = 0x6302;

	private byte[] symKey = new byte[32];
	private byte[] aesEncryptBytes = new byte[16];
	private byte[] challenge = new byte[SIZE_OF_CHALLENGE];
	
	private byte[] serial = new byte[]{0x30, 0x35, 0x37, 0x36, 0x39, 0x30, 0x31, 0x05};
	private String javacardPrivateExponent = "4019248479486344703173865994833247965130855891297001843442511551221472431764138438478319727380832243535639804382400663422189381536828238855709495144508993";
	private String javacardModulus = "7225408371738440114436736221839657995687428751040476459668967509666492175788144159467939803507838616521107657543265826137267809302826074208901286160547939";
	
	//will need to be changed to the new kind of certificate
	private String[] javacardCert = {"Javacard","Javacard","7225408371738440114436736221839657995687428751040476459668967509666492175788144159467939803507838616521107657543265826137267809302826074208901286160547939","65537","Apr 25 2017 9:44:25 PM CEST","Apr 25 2018 9:44:25 PM CEST","8DB055AED73FE6206C2233F9735F71C9FDEC54CD9AE1A33375D8D706C9EFB1EC3572D40CF8842096F32544DD8D17414998052EE1C08628C6232A39474E5424FF"};
	
	private byte[] mainCAPublicExponent = {1,0,1};
	private byte[] mainCAPublicModulus = {0, -111,103,-6,88,-39,13,27,-42,85,-123,-123,-92,101,-57,-34,83,42,-118,-101,115,38,22,-113,-108,-21,97,-21,99,-18,-77,54,58,32,115,-47,-80,-71,53,43,-3,81,88,114,-25,-114,125,-12,-53,108,25,-49,37,15,66,20,8,52,-99,-49,-79,23,81,50,23};

	
	private byte[] govTimePublicExponent = {1,0,1};
	private byte[] govTimePublicModulus = {-122,-6,-74,-13,93,84,85,-61,-39,4,-102,-7,82,43,-67,-2,-63,-65,-69,100,51,-106,4,94,63,7,-67,61,127,-16,-59,-95,34,-49,14,14,94,44,81,-36,94,26,-45,46,-100,-40,-30,-55,-69,40,124,-3,0,-2,-84,-97,0,-87,77,44,-29,-20,-80,49};
	//CHECK HERE IF IT'S CORRECT
	
	private String[] lastValidationTime = {"2014","05","01","15","06"};
	
	private String[] deltaValidation = {"0","0","1","0","0"};
	
	
	private OwnerPIN pin;
	private byte[] storage = new byte[]{0x30, 0x35, 0x37, 0x36, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
	private byte[] bigStorage = new byte[1024];
	private byte[] byteToInt = new byte[]{0x00,0x00,0x00,0x00, 0x04, 0x04};
	private byte[] fourBytes = new byte[4];
	
	private short authStep = 0;
	
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
//		short i = 0;
//		while ( bytesLeft > 0){
//			
//			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storage, i, readCount);
//			bytesLeft -= readCount;
//			i+=readCount;
//			readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
//		}
		
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
				System.out.println("DELTA: "+(currentDate.getTime() - lastValidationDate.getTime())/(1000*60*60*24));
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
		System.out.println("VERIF");
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
		
		byte[] uncroppedGovTimePublicModulus = new byte[govTimePublicModulus.length + 1];
		Util.arrayCopy(govTimePublicModulus, (short)0, uncroppedGovTimePublicModulus, (short)1, (short)govTimePublicModulus.length);
		uncroppedGovTimePublicModulus[0] = (short) 0;
//		RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(uncroppedGovTimePublicModulus), new BigInteger(govTimePublicExponent));
////		System.out.println(new BigInteger(govTimePublicModulus));
//		KeyFactory factory = KeyFactory.getInstance("RSA");
//        RSAPublicKey timestampPubKey =  (RSAPublicKey) factory.generatePublic(spec);
//
//		Signature signEngine = Signature.getInstance("SHA256withRSA");
//		signEngine.initVerify(timestampPubKey);
//		MessageDigest md = MessageDigest.getInstance("SHA-256");
//
//		byte[] hashedTime = md.digest(timeToVerify);
//		signEngine.update(hashedTime, 0, hashedTime.length);
//		
//		boolean verifies = signEngine.verify(sigToVerify);
//		System.out.println(new BigInteger(govTimePublicModulus));
		javacard.security.RSAPublicKey timestampPubKey = (javacard.security.RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);

        timestampPubKey.setExponent(govTimePublicExponent, (short) 0, (short) govTimePublicExponent.length);
        timestampPubKey.setModulus(govTimePublicModulus, (short) 0, (short) govTimePublicModulus.length);
 		//System.out.println("MODULUS:" + timestampPubKey.getModulus());
		//System.out.println("EXPONENT:" + timestampPubKey.getPublicExponent());
		
        javacard.security.Signature signEngine = javacard.security.Signature.getInstance(javacard.security.Signature.ALG_RSA_SHA_PKCS1, false);
		System.out.println("VERIF2TER");
		signEngine.init( timestampPubKey, javacard.security.Signature.MODE_VERIFY);
        System.out.println("VERIF2QUAT");
		
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		System.out.println("VERIF3");

		byte[] hashedTime = md.digest(timeToVerify);
		//signEngine.update(hashedTime, (short) 0, (short) hashedTime.length);
		boolean verifies = signEngine.verify(hashedTime, (short) 0, (short) hashedTime.length, sigToVerify, (short) 0, (short)sigToVerify.length);
		System.out.println("VERIFIES:" + verifies);
		
		String year = Integer.toString(timeToVerify[0] << 24 | (timeToVerify[1] & 0xFF) << 16 | (timeToVerify[2] & 0xFF) << 8 | (timeToVerify[3] & 0xFF));
		String month = Integer.toString((int)(timeToVerify[4]& 0xFF));
		String day = Integer.toString((int)(timeToVerify[5]& 0xFF));
		String hour = Integer.toString((int)(timeToVerify[6]& 0xFF));
		String min = Integer.toString((int)(timeToVerify[7]& 0xFF));
		String timeString = String.join("-", new String[]{year,month,day,hour, min});
		
		String lastValidationString = String.join("-", lastValidationTime);

		try {
			SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd-HH-mm");
			Date timeDate = format.parse(timeString);
			Date lastValidationDate = format.parse(lastValidationString);
			short response = 1;
			if(!verifies || !(timeDate.getTime() > lastValidationDate.getTime())){
				response = 0;
			}
			else{
				lastValidationTime = new String[]{year,month,day,hour, min};
				for (int j = 0; j < lastValidationTime.length; j++) {
					System.out.println(j+","+lastValidationTime[j]);
				}
				System.out.println("UPDATINGTIME WITH: "+ String.join("-",lastValidationTime));
			}
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)1);
			apdu.sendBytesLong(new byte[]{(byte)response},(short)0,(short)1);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
		}


		
	}

	
	private void auth_step(APDU apdu) {
		if (authStep == 0) {
			Arrays.fill(bigStorage, (byte) 0);
		}
		byte[] buffer = apdu.getBuffer();
		short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		short START = 0;
		Util.arrayCopy(buffer, START, storage, START, (short)8);
		short readCount = apdu.setIncomingAndReceive();
		short i = (short) (250*authStep);
		while ( bytesLeft > 0){
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, bigStorage, i, readCount);
			bytesLeft -= readCount;
			i+=readCount;
			readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
		}
		
		
		authStep += 1;
		apdu.setOutgoing();
		System.out.println((short)buffer.length);
		apdu.setOutgoingLength((short)buffer.length);
		apdu.sendBytesLong(buffer,(short)0,(short)buffer.length);    
		
	}
	private byte[] intToByte(int integer){
		return ByteBuffer.allocate(4).putInt(integer).array();
	}
	
	private void authenticate_sp(APDU apdu){
		authStep = 0;
		byte[] buffer = apdu.getBuffer();
		short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		short START = 0;
		Util.arrayCopy(buffer, START, storage, START, (short)8);
		short readCount = apdu.setIncomingAndReceive();
		short i = (short) (250*authStep);
		while ( bytesLeft > 0){
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storage, i, readCount);
			bytesLeft -= readCount;
			i+=readCount;
			readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
		}
		
		byte[] response = null;
		System.out.println("AUTH_SP");
		byte[] issuer = new byte[ISSUER_LEN];
		byte[] subject = new byte[SUBJECT_LEN];
		byte[] modulus = new byte[MODULUS_LEN+1];
		modulus[0] = 0;
		byte[] exponent = new byte[EXPONENT_LEN];
		byte[] validFrom = new byte[DATE_LEN];
		byte[] validUntil = new byte[DATE_LEN];
		byte[] signature = new byte[SIGN_LEN];

		Util.arrayCopy(bigStorage, (short) 0x00, issuer,(short) 0x00, ISSUER_LEN);
		Util.arrayCopy(bigStorage, (short) ISSUER_LEN, subject,(short) 0x00, SUBJECT_LEN);
		Util.arrayCopy(bigStorage, (short) (SUBJECT_LEN + ISSUER_LEN), modulus,(short) 0x01, MODULUS_LEN);
		Util.arrayCopy(bigStorage, (short) (SUBJECT_LEN + ISSUER_LEN + MODULUS_LEN), exponent,(short) 0x00, EXPONENT_LEN);
		Util.arrayCopy(bigStorage, (short) (SUBJECT_LEN + ISSUER_LEN + MODULUS_LEN + EXPONENT_LEN), validFrom,(short) 0x00, DATE_LEN);
		Util.arrayCopy(bigStorage, (short) (SUBJECT_LEN + ISSUER_LEN + MODULUS_LEN + EXPONENT_LEN + DATE_LEN), validUntil,(short) 0x00, DATE_LEN);
		Util.arrayCopy(bigStorage, (short) (SUBJECT_LEN + ISSUER_LEN + MODULUS_LEN + EXPONENT_LEN + DATE_LEN + DATE_LEN), signature,(short) 0x00, SIGN_LEN);
		
		byte[] dataToCheck = new byte[SUBJECT_LEN + ISSUER_LEN + MODULUS_LEN + EXPONENT_LEN + DATE_LEN + DATE_LEN];
		Arrays.fill(dataToCheck, (byte) 0);
		Util.arrayCopy(bigStorage, (short) 0, dataToCheck, (short)0,(short) (SUBJECT_LEN + ISSUER_LEN + MODULUS_LEN + EXPONENT_LEN + DATE_LEN + DATE_LEN));
		System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(signature));
		
		
		boolean verified = false;
		boolean valid = false;
		RSAPublicKey mainCaPublicKey = null;
		try {
			// now we need to verify if the certificate is correct
			Signature SPcheck = Signature.getInstance("SHA1withRSA");	
//			SPPublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
//			SPPublicKey.setModulus(modulus,(short) 0, (short) modulus.length);
//			SPPublicKey.setExponent(exponent,(short) 0,(short) exponent.length);

			RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(mainCAPublicModulus), new BigInteger(mainCAPublicExponent));
			KeyFactory factory = KeyFactory.getInstance("RSA");
			mainCaPublicKey = (RSAPublicKey) factory.generatePublic(spec);
			SPcheck.initVerify((PublicKey) mainCaPublicKey);
			
			SPcheck.update(dataToCheck, 0, dataToCheck.length);
			System.out.println(dataToCheck.length);
			
		    verified = SPcheck.verify(signature);
		    System.out.println(verified);
			
			
			//we need to check if the current date is in between the validity period;
			String[] validStart = getDateAsString(validFrom);
			String[] validTo = getDateAsString(validUntil);
			SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd-HH-mm");
			String lastValidationString = String.join("-", lastValidationTime);
			String validFromString = String.join("-", validStart);
			String validToString = String.join("-", validTo);
			Date lastValidationDate = format.parse(lastValidationString);
			Date validFromDate = format.parse(validFromString); 
			Date validToDate = format.parse(validToString);
			
			if(lastValidationDate.after(validFromDate) && lastValidationDate.before(validToDate)) {
			   valid = true;
			}
			System.out.println(valid);

		} catch (NoSuchAlgorithmException e) {
			System.out.println("NoSuchAlgorithmException");
		} catch (InvalidKeyException e) {
			System.out.println("InvalidKeyException");
		} catch (SignatureException e) {
			System.out.println("SignatureException");
		} catch (ParseException e) {
			System.out.println("ParseException");
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			System.out.println("InvalidKeySpecException");
		}

		if (!(verified && valid)){
		//here the ABORT should happen
			
		}
		System.out.println("HERE");
		//otherwise we generate a new symmetric key
		 KeyGenerator kgen;
		 SecretKey key = null;
		try {
			//make sure this works on the card..
			kgen = KeyGenerator.getInstance("AES");
			//should this be 256 since the size of the keys we use are 256?
	        kgen.init(256);
	        key = (SecretKey) kgen.generateKey();
	        symKey = key.getEncoded();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("NoSuchAlgorithmException");
		}
		
		try {
			Cipher rsaenc = Cipher.getInstance("RSA");
			RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(exponent));
			KeyFactory factory = KeyFactory.getInstance("RSA");
			RSAPublicKey spPublicKey = (RSAPublicKey) factory.generatePublic(spec);
			rsaenc.init(Cipher.ENCRYPT_MODE, spPublicKey);
			byte[] encryptedKey = rsaenc.doFinal(key.getEncoded());
			
			//we have to generate a challenge 
			SecureRandom random = new SecureRandom();
			random.nextBytes(challenge);

			IvParameterSpec iv = new IvParameterSpec("0000111122223333".getBytes("UTF-8"));
			Cipher aesenc = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			byte[] dataToEncrypt = new byte[SIZE_OF_CHALLENGE + SUBJECT_LEN]; 
			Util.arrayCopy(challenge,(short) 0, dataToEncrypt,(short) 0, SIZE_OF_CHALLENGE);
			Util.arrayCopy(subject,(short)0, dataToEncrypt, SIZE_OF_CHALLENGE, SUBJECT_LEN);
			aesenc.init(Cipher.ENCRYPT_MODE, key, iv);
			byte[] encryptedChallenge = aesenc.doFinal(dataToEncrypt);
			response = new byte[4 + 4 + encryptedKey.length +  encryptedChallenge.length];
			Util.arrayCopy(intToByte(encryptedKey.length), (short) 0, response, (short) 0, (short) 4);
			Util.arrayCopy(intToByte(encryptedChallenge.length), (short) 0, response, (short) 4, (short) 4);
			Util.arrayCopy(encryptedKey, (short) 0, response, (short) 8,(short) encryptedKey.length);
			Util.arrayCopy(encryptedChallenge, (short) 0, response, (short) (encryptedKey.length +8),(short) encryptedChallenge.length);
			System.out.println(encryptedChallenge.length);
			System.out.println("END OF AUTH 1");
			
		} catch (NoSuchAlgorithmException e) {
			System.out.println("NoSuchAlgorithmException");
		} catch (NoSuchPaddingException e) {
			System.out.println("NoSuchPaddingException");
		} catch (InvalidKeyException e) {
			System.out.println("InvalidKeyException");
		} catch (IllegalBlockSizeException e) {
			System.out.println("IllegalBlockSizeException");
		} catch (BadPaddingException e) {
			System.out.println("BadPaddingException");
		} catch (InvalidAlgorithmParameterException e) {
			System.out.println("InvalidAlgorithmParameterException");
		} catch (UnsupportedEncodingException e) {
			System.out.println("UnsupportedEncodingException");
		} catch (InvalidKeySpecException e) {
			System.out.println("InvalidKeySpecException");

		}
		System.out.println("RESPONSE LENGTH: "+response.length);
		System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(response));
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)response.length);
		apdu.sendBytesLong(response,(short)0,(short)response.length);    
		
	}
	
	private String[] getDateAsString(byte[] dateAsByte){
		String year = Integer.toString(dateAsByte[0] << 24 | (dateAsByte[1] & 0xFF) << 16 | (dateAsByte[2] & 0xFF) << 8 | (dateAsByte[3] & 0xFF));
		String month = Integer.toString((int)dateAsByte[4]);
		String day = Integer.toString((int)dateAsByte[5]);
		String hour = Integer.toString((int)dateAsByte[6]);
		String min = Integer.toString((int)dateAsByte[7]);
		String[] timeString = {year,month,day,hour, min}; //THIS IS LIKE A NEW
		
		return timeString;
		
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
		if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA){System.out.println("huh?");ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);};
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
		case AUTHENTICATE_SP: 
			authenticate_sp(apdu);
			break;
		case AUTHENTICATE_SP_STEP:
			auth_step(apdu);
			break;
		case END_AUTH:
			end_auth(apdu);
			break;
			
		//If no matching instructions are found it is indicated in the status word of the response.
		//This can be done by using this method. As an argument a short is given that indicates
		//the type of warning. There are several predefined warnings in the 'ISO7816' class.
		default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	

	private void end_auth(APDU apdu) {
		System.out.println("AUTH");
		byte[] buffer = apdu.getBuffer();
		System.out.println("AUTH1");
		System.out.println(symKey.length);
		SecretKey symetricKey = new SecretKeySpec(symKey, "AES");
		Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA, fourBytes, (short)0, (short)4);
		short size = (short) bytesToInt(fourBytes, 0);
		System.out.println(size);
		byte[] encryptedResponse = new byte[size];
		Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + 4), encryptedResponse,(short) 0, size);

        IvParameterSpec iv = null;
		System.out.println("AUTH2");
		try {
			iv = new IvParameterSpec("0000111122223333".getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			System.out.println("UnsupportedEncodingException");
		}
		Cipher aesdec = null;
		try {
			aesdec = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("NoSuchAlgorithmException");
		} catch (NoSuchPaddingException e) {
			System.out.println("NoSuchPaddingException");
		}
		System.out.println("AUTH3");
		System.out.println(symetricKey.getEncoded());
		try {
			aesdec.init(Cipher.DECRYPT_MODE, symetricKey, iv);
		} catch (InvalidKeyException e) {
			System.out.println("InvalidKeyException");
		} catch (InvalidAlgorithmParameterException e) {
			System.out.println("InvalidAlgorithmParameterException");
		}
		byte[] response = null;
		System.out.println(encryptedResponse.length);
		Util.arrayCopy(encryptedResponse, (short) 0, aesEncryptBytes, (short) 0, (short)aesEncryptBytes.length);
		System.out.println(aesEncryptBytes.length);
		try {
			response = aesdec.doFinal(aesEncryptBytes);
		} catch (IllegalBlockSizeException e) {
			System.out.println("IllegalBlockSizeException");
		} catch (BadPaddingException e) {
			System.out.println("BadPaddingException");
		}
		System.out.println("AUTH4");
		System.out.println(response.length);
		int responseShort =  (response[0] << 8 | (response[1] & 0xFF));
		System.out.println("AUTH4.5:"+ responseShort);
		short previousChallenge = (short)  (challenge[0] << 8 | (challenge[1] & 0xFF));
		System.out.println(responseShort + "-" + previousChallenge);
		if (responseShort != previousChallenge+1) {
			return;
		}
		System.out.println("AUTH5");
		auth = true;
		System.out.println("AUTH: " + auth);
		
	}
	
	private static int bytesToInt(byte[] bytes, int offset){
		return bytes[offset] << 24 | (bytes[offset+1] & 0xFF) << 16 | (bytes[offset+2] & 0xFF) << 8 | (bytes[offset+3] & 0xFF);
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
		}else{ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);}
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
