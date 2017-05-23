package ui;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import be.msec.server.ServiceProvider;

import java.awt.GridLayout;
import javax.swing.JLabel;
import javax.swing.SwingConstants;
import javax.swing.JButton;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashMap;
import java.util.Set;
import javax.swing.JComboBox;
import javax.swing.DefaultComboBoxModel;
import javax.swing.AbstractAction;
import javax.swing.Action;

public class SPSelection extends JFrame {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private JPanel contentPane;
	JLabel lblDomain = new JLabel("Domain");
	JButton btnNewButton = new JButton("Select Service");
	final JComboBox<String> comboBox_1 = new JComboBox<String>();

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					HashMap<String, String[]> allServices = new HashMap<String, String[]>();
					allServices.put("eGov", new String[]{"eGov1","eGov2"});
					allServices.put("SocNet", new String[]{"serviceSocNet1","serviceSocNet2"});
					allServices.put("default", new String[]{"serviceDefault1","serviceDefault2"});
					allServices.put("health", new String[]{"healthService1","healthService2"});
					SPSelection frame = new SPSelection(allServices);
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
	public SPSelection(final HashMap<String,String[]> services) {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 300);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		GridBagLayout gbl_contentPane = new GridBagLayout();
		gbl_contentPane.columnWidths = new int[]{219, 219, 0};
		gbl_contentPane.rowHeights = new int[]{132, 132, 0, 0, 0};
		gbl_contentPane.columnWeights = new double[]{1.0, 0.0, Double.MIN_VALUE};
		gbl_contentPane.rowWeights = new double[]{0.0, 1.0, 0.0, 0.0, Double.MIN_VALUE};
		contentPane.setLayout(gbl_contentPane);
		
		JPanel panel = new JPanel();
		GridBagConstraints gbc_panel = new GridBagConstraints();
		gbc_panel.gridwidth = 2;
		gbc_panel.fill = GridBagConstraints.BOTH;
		gbc_panel.insets = new Insets(0, 0, 5, 0);
		gbc_panel.gridx = 0;
		gbc_panel.gridy = 0;
		contentPane.add(panel, gbc_panel);
		panel.setLayout(new GridLayout(0, 1, 0, 0));
		
		JLabel lblNewLabel = new JLabel("Select a Service Provider");
		panel.add(lblNewLabel);
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		
		JPanel panel_2 = new JPanel();
		GridBagConstraints gbc_panel_2 = new GridBagConstraints();
		gbc_panel_2.insets = new Insets(0, 0, 5, 5);
		gbc_panel_2.fill = GridBagConstraints.BOTH;
		gbc_panel_2.gridx = 0;
		gbc_panel_2.gridy = 1;
		contentPane.add(panel_2, gbc_panel_2);
		panel_2.setLayout(new GridLayout(0, 2, 0, 0));
		
		panel_2.add(lblDomain);
		
		final JComboBox<String> comboBox = new JComboBox<String>();
		Set<String> keys = services.keySet();
		comboBox.setModel(new DefaultComboBoxModel<String>(keys.toArray(new String[keys.size()])));
		comboBox.setSelectedIndex(0);
		JLabel lblService = new JLabel("Service");
		String selectedDomain = (String) comboBox.getSelectedItem();
		String[] selectedServices = services.get(selectedDomain);
		comboBox_1.setModel(new DefaultComboBoxModel<String>(selectedServices));
		comboBox.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent arg0) {
				String selectedDomain = (String) comboBox.getSelectedItem();
				String[] selectedServices = services.get(selectedDomain);
				comboBox_1.setModel(new DefaultComboBoxModel<String>(selectedServices));
				
				
			}
		});
		panel_2.add(comboBox);
		
		panel_2.add(lblService);
		
		panel_2.add(comboBox_1);
		
		JPanel panel_1 = new JPanel();
		GridBagConstraints gbc_panel_1 = new GridBagConstraints();
		gbc_panel_1.insets = new Insets(0, 0, 5, 0);
		gbc_panel_1.gridx = 1;
		gbc_panel_1.gridy = 1;
		contentPane.add(panel_1, gbc_panel_1);
		panel_1.setLayout(new GridLayout(0, 1, 0, 0));
		
		btnNewButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					System.out.println((String) comboBox_1.getSelectedItem());
					ServiceProvider SP = new ServiceProvider((String) comboBox_1.getSelectedItem());
					btnNewButton.setEnabled(false);
					SP.start();
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				
			}
		});
		panel_1.add(btnNewButton);
		
	}
}
