package ui;

import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import java.awt.GridLayout;
import javax.swing.JTextField;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.SwingConstants;
import java.awt.FlowLayout;
import java.awt.CardLayout;
import javax.swing.JLabel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.Color;
import java.awt.Font;

public class Login extends JFrame {

	private JPanel contentPane;
	private JTextField txtLogin;
	private JTextField txtPassword;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Login frame = new Login();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public Login() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 300);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(new GridLayout(3, 0, 0, 0));
		
		JPanel panel_1 = new JPanel();
		contentPane.add(panel_1);
		
		JLabel lblLoginRequired = new JLabel("Login required");
		lblLoginRequired.setFont(new Font("Dialog", Font.BOLD, 24));
		panel_1.add(lblLoginRequired);
		
		JPanel panel_2 = new JPanel();
		contentPane.add(panel_2);
		panel_2.setLayout(new GridLayout(0, 3, 0, 0));
		
		JPanel panel_3 = new JPanel();
		panel_3.setForeground(Color.WHITE);
		FlowLayout flowLayout = (FlowLayout) panel_3.getLayout();
		panel_2.add(panel_3);
		
		JPanel panel_4 = new JPanel();
		panel_2.add(panel_4);
		panel_4.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 15));
		
		txtLogin = new JTextField();
		txtLogin.setHorizontalAlignment(SwingConstants.LEFT);
		txtLogin.setToolTipText("Login");
		txtLogin.setText("Login");
		txtLogin.setColumns(10);
		panel_4.add(txtLogin);
		
		txtPassword = new JTextField();
		txtPassword.setText("Password");
		txtPassword.setColumns(10);
		panel_4.add(txtPassword);
		
		JPanel panel_5 = new JPanel();
		panel_2.add(panel_5);
		
		JPanel panel = new JPanel();
		contentPane.add(panel);
		
		JButton btnNewButton = new JButton("Login");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			}
		});
		panel.add(btnNewButton);
		
		JButton btnNewButton_1 = new JButton("Cancel");
		panel.add(btnNewButton_1);
	}

}
