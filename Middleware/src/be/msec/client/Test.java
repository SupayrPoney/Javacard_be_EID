package be.msec.client;

import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import helpers.HomeMadeCertificate;

import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.awt.event.ActionEvent;

public class Test {

	public static HomeMadeCertificate restoreCert(String name) {

        HomeMadeCertificate deserializedCert = null;
        FileInputStream inputFileStream;
		try {
			inputFileStream = new FileInputStream("certs/" + name + ".crt");
	        ObjectInputStream objectInputStream = new ObjectInputStream(inputFileStream);
	        deserializedCert= (HomeMadeCertificate)objectInputStream.readObject();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return deserializedCert;
	}

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		byte[] sign = new byte[8];
		String[] fromDate = {"2017", "05", "25", "09", "44"};
		String[] toDate = {"2018", "05", "25", "09", "44"};
		String subject = "egov2";
		HomeMadeCertificate cert= new HomeMadeCertificate(subject, subject, new BigInteger("10554386398715009799383770668844394385077749890982339064701937475083362987983834269156144949025011552047026073019318971307070997094912766506017370126042689"), 
				new BigInteger("65537"), sign, fromDate, toDate);

		
		
		
        Path path = Paths.get("signatures/" + subject + ".sig");
        byte[] data = null;
        try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
        cert.setSignature(data);
		cert.save();
//		
//		HomeMadeCertificate deserCert = restoreCert(subject);
//		
//		System.out.println(Arrays.equals(deserCert.getSignature(),data));

	      
	}

}
