package helpers;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class HomeMadeCertificate implements java.io.Serializable{
	/**
	 * 
	 */
	byte[] subject;
	byte[] issuer;
	byte[] publicKeyExponent;
	byte[] publicKeyModulus;
	byte[] signature;
	byte[] validFrom;
	byte[] validTo;
	
	private static final short ISSUER_LEN = 16; 
	private static final short SUBJECT_LEN = 16;
	private static final short DATE_LEN = 8; 

	private static final short EXPONENT_LEN = 3; 
	private static final short MODULUS_LEN = 64; 
	
	private static final short SIGN_LEN = 64; 
	
	private static final short SIZE_OF_INT_IN_BYTES = 4;
	
	
	public HomeMadeCertificate(byte[] issuer, byte[] subject, byte[] publicKeyExponent, byte[] publicKeyModulus,
			byte[] signature, byte[] validFrom, byte[] validTo) {
		super();
		this.subject = subject;
		this.issuer = issuer;
		this.publicKeyExponent = publicKeyExponent;
		this.publicKeyModulus = publicKeyModulus;
		this.signature = signature;
		this.validFrom = validFrom;
		this.validTo = validTo;
	}
	public byte[] getAsBytesWithSign(){
		byte[] res = new byte[SUBJECT_LEN + ISSUER_LEN + 2*DATE_LEN + EXPONENT_LEN + MODULUS_LEN + SIGN_LEN];
		Arrays.fill(res, (byte) 0); 
		//System.out.println(res.length);

		byte[] issuerBytes = new byte[ISSUER_LEN];
		System.arraycopy(this.issuer, 0, issuerBytes, 0, this.issuer.length);
		System.arraycopy(issuerBytes, 0, res, 0, ISSUER_LEN);

		byte[] subjectBytes = new byte[SUBJECT_LEN];
		System.arraycopy(this.subject, 0, subjectBytes, 0, this.subject.length);
		System.arraycopy(subjectBytes, 0, res, ISSUER_LEN, SUBJECT_LEN);
		
		byte[] modulus = new byte[MODULUS_LEN];
		byte[] shrinkedModulus = Arrays.copyOfRange(this.publicKeyModulus, 1, this.publicKeyModulus.length);
		System.arraycopy(shrinkedModulus, 0, modulus, 0, shrinkedModulus.length);
		System.arraycopy(modulus, 0, res, ISSUER_LEN + SUBJECT_LEN, MODULUS_LEN);
		
		byte[] exponent = new byte[EXPONENT_LEN];
		System.arraycopy(this.publicKeyExponent, 0, exponent, 0, this.publicKeyExponent.length);
		System.arraycopy(exponent, 0, res, ISSUER_LEN + SUBJECT_LEN + MODULUS_LEN, EXPONENT_LEN);
		
		byte[] validFrom = new byte[DATE_LEN];
		System.arraycopy(this.validFrom, 0, validFrom, 0, DATE_LEN);
		System.arraycopy(validFrom, 0, res, ISSUER_LEN + SUBJECT_LEN + MODULUS_LEN + EXPONENT_LEN, DATE_LEN);
		
		byte[] validUntil = new byte[DATE_LEN];
		System.arraycopy(this.validTo, 0, validUntil, 0, DATE_LEN);
		System.arraycopy(validUntil, 0, res, ISSUER_LEN + SUBJECT_LEN + MODULUS_LEN + EXPONENT_LEN + DATE_LEN, DATE_LEN);
		
		System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(res));
		System.out.println("DATA LEN: " + res.length);
		
		System.arraycopy(this.signature, 0, res, ISSUER_LEN + SUBJECT_LEN + MODULUS_LEN + EXPONENT_LEN + DATE_LEN + DATE_LEN, SIGN_LEN);
		
		
		return res;
	}
	
	public byte[] getAsBytesWithoutSign(){
		byte[] res = new byte[SUBJECT_LEN + ISSUER_LEN + 2*DATE_LEN + EXPONENT_LEN + MODULUS_LEN];
		Arrays.fill(res, (byte) 0); 
		//System.out.println(res.length);
		byte[] issuerBytes = new byte[ISSUER_LEN];
		System.arraycopy(this.issuer, 0, issuerBytes, 0, this.issuer.length);
		System.arraycopy(issuerBytes, 0, res, 0, ISSUER_LEN);

		byte[] subjectBytes = new byte[SUBJECT_LEN];
		System.arraycopy(this.subject, 0, subjectBytes, 0, this.subject.length);
		System.arraycopy(subjectBytes, 0, res, ISSUER_LEN, SUBJECT_LEN);
		
		byte[] modulus = new byte[MODULUS_LEN];
		byte[] shrinkedModulus = Arrays.copyOfRange(this.publicKeyModulus, 1, this.publicKeyModulus.length);
		System.arraycopy(shrinkedModulus, 0, modulus, 0, shrinkedModulus.length);
		System.arraycopy(modulus, 0, res, ISSUER_LEN + SUBJECT_LEN, MODULUS_LEN);
		
		byte[] exponent = new byte[EXPONENT_LEN];
		System.arraycopy(this.publicKeyExponent, 0, exponent, 0, this.publicKeyExponent.length);
		System.arraycopy(exponent, 0, res, ISSUER_LEN + SUBJECT_LEN + MODULUS_LEN, EXPONENT_LEN);
		
		byte[] validFrom = new byte[DATE_LEN];
		System.arraycopy(this.validFrom, 0, validFrom, 0, DATE_LEN);
		System.arraycopy(validFrom, 0, res, ISSUER_LEN + SUBJECT_LEN + MODULUS_LEN + EXPONENT_LEN, DATE_LEN);
		
		byte[] validUntil = new byte[DATE_LEN];
		System.arraycopy(this.validTo, 0, validUntil, 0, DATE_LEN);
		System.arraycopy(validUntil, 0, res, ISSUER_LEN + SUBJECT_LEN + MODULUS_LEN + EXPONENT_LEN + DATE_LEN, DATE_LEN);
		
		System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(res));
		System.out.println("DATA LEN: " + res.length);
		
		
		return res;
	}
	
	public void save(){
		try {
				String subjectString = new String(this.subject);
	          FileOutputStream fileOut = new FileOutputStream("certs/" + subjectString + ".crt");
	          ObjectOutputStream out = new ObjectOutputStream(fileOut);
	          out.writeObject(this);
	          out.close();
	          fileOut.close();
	       }catch(IOException i) {
	          i.printStackTrace();
	       }
	}


	public byte[] getSubject() {
		return subject;
	}

	public void setSubject(byte[] subject) {
		this.subject = subject;
	}

	public byte[] getIssuer() {
		return issuer;
	}

	public void setIssuer(byte[] issuer) {
		this.issuer = issuer;
	}

	public byte[] getValidFrom() {
		return validFrom;
	}

	public void setValidFrom(byte[] validFrom) {
		this.validFrom = validFrom;
	}

	public byte[] getValidTo() {
		return validTo;
	}

	public void setValidTo(byte[] validTo) {
		this.validTo = validTo;
	}

	public byte[] getPublicKeyExponent() {
		return publicKeyExponent;
	}

	public void setPublicKeyExponent(byte[] publicKeyExponent) {
		this.publicKeyExponent = publicKeyExponent;
	}

	public byte[] getPublicKeyModulus() {
		return publicKeyModulus;
	}

	public void setPublicKeyModulus(byte[] publicKeyModulus) {
		this.publicKeyModulus = publicKeyModulus;
	}

	public byte[] getSignature() {
		return signature;
	}


	public void setSignature(byte[] signature) {
		this.signature = signature;
	}

}
