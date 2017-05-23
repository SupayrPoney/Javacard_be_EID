package helpers;

import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

public class HomeMadeCertificate implements java.io.Serializable{
	String subject;
	String issuer;
	BigInteger publicKeyExponent;
	BigInteger publicKeyModulus;
	byte[] signature;
	String[] validFrom;
	String[] validTo;
	
	
	public HomeMadeCertificate(String issuer, String subject, BigInteger publicKeyExponent, BigInteger publicKeyModulus,
			byte[] signature, String[] validFrom, String[] validTo) {
		super();
		this.subject = subject;
		this.issuer = issuer;
		this.publicKeyExponent = publicKeyExponent;
		this.publicKeyModulus = publicKeyModulus;
		this.signature = signature;
		this.validFrom = validFrom;
		this.validTo = validTo;
	}
	
	public void save(){
		try {
	          FileOutputStream fileOut =
	          new FileOutputStream("certs/" + subject + ".crt");
	          ObjectOutputStream out = new ObjectOutputStream(fileOut);
	          out.writeObject(this);
	          out.close();
	          fileOut.close();
	       }catch(IOException i) {
	          i.printStackTrace();
	       }
	}
	
	
	public String getIssuer() {
		return issuer;
	}


	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}


	public String getSubject() {
		return subject;
	}


	public void setSubject(String subject) {
		this.subject = subject;
	}


	public BigInteger getPublicKeyExponent() {
		return publicKeyExponent;
	}


	public void setPublicKeyExponent(BigInteger publicKeyExponent) {
		this.publicKeyExponent = publicKeyExponent;
	}


	public BigInteger getPublicKeyModulus() {
		return publicKeyModulus;
	}


	public void setPublicKeyModulus(BigInteger publicKeyModulus) {
		this.publicKeyModulus = publicKeyModulus;
	}


	public byte[] getSignature() {
		return signature;
	}


	public void setSignature(byte[] signature) {
		this.signature = signature;
	}


	public String[] getValidFrom() {
		return validFrom;
	}


	public void setValidFrom(String[] validFrom) {
		this.validFrom = validFrom;
	}


	public String[] getValidTo() {
		return validTo;
	}


	public void setValidTo(String[] validTo) {
		this.validTo = validTo;
	}
	
	
}
