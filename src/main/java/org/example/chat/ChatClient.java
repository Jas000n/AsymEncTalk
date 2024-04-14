package org.example.chat;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

import org.example.encryption.Encryption;


public class ChatClient extends JFrame {

	private static final String RSA = "RSA";
	private static final String SERVER_PUBLIC_KEY = "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGk9wUQ4G9PChyL5SUkCyuHjTNOglEy5h4KEi0xpgjxi/UbIH27NXLXOr94JP1N5pa1BbaVSxlvpuCDF0jF9jlZw5IbBg1OW2R1zUACK+NrUIAYHWtagG7KB/YcyNXHOZ6Icv2lXXd7MbIao3ShrUVXo3u+5BJFCEibd8a/JD/KpAgMBAAE=";
	private PublicKey serverPublicKey;
	private Key communicationKey;
	private JTextArea displayField;
	private JTextField inputField;
	private Socket socket;
	private JMenuItem connectItem;


	public ChatClient() {
		super("Chat Client");
		createAndShowGUI();
		try {
			serverPublicKey = Encryption.readPublicKey(SERVER_PUBLIC_KEY);			
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("error getting server public key: " + e.getMessage());
		}
		
	}
	private void createAndShowGUI() {
		setSize(400, 200);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setLayout(new BorderLayout());

		// create menu
		JMenuBar menuBar = new JMenuBar();
		JMenu menu = new JMenu("Menu");
		JMenuItem connectItem = new JMenuItem("Connect");
		this.connectItem = connectItem;
		JMenuItem exitItem = new JMenuItem("Exit");

		// add event listener
		connectItem.addActionListener(e -> connect());
		exitItem.addActionListener(e -> System.exit(0));

		// construct menu bar item
		menu.add(connectItem);
		menu.add(exitItem);
		menuBar.add(menu);
		setJMenuBar(menuBar);

		displayField = new JTextArea();
		displayField.setEditable(false);
		JScrollPane scrollPane = new JScrollPane(displayField);
		scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
		scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		add(scrollPane);

		inputField = new JTextField();
		add(inputField, BorderLayout.SOUTH);

		inputField.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
                try {
                    onEnterPressed(inputField.getText());
                } catch (IOException | InvalidAlgorithmParameterException | NoSuchPaddingException |
                         IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException |
                         InvalidKeyException ex) {
                    throw new RuntimeException(ex);
                }
                inputField.setText("");
			}
		});

		setVisible(true);
	}

	private void connect() {
		connectItem.setEnabled(false);
		new Thread(()->{
			try (Socket socket = new Socket("127.0.0.1", 9898)) {
				this.socket = socket;
				shakeHande(socket);
				byte[] buffer = new byte[1024];
				int read;
				DataInputStream fromServer = new DataInputStream(socket.getInputStream());
				while (true) {
					String clientData = fromServer.readUTF();
					clientData = Encryption.decrypt(this.communicationKey,clientData);
					this.displayField.append(clientData+"\n");
				}

			} catch (IOException e) {
				displayField.append("Connection failed: " + e.getMessage());
			} catch (InvalidAlgorithmParameterException e) {
                throw new RuntimeException(e);
            } catch (NoSuchPaddingException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (BadPaddingException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        }).start();

	}

	private void onEnterPressed(String text) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
		displayField.append(text+"\n");
		OutputStream outputStream = this.socket.getOutputStream();
		text = Encryption.encrypt(this.communicationKey,text);
		DataOutputStream toServer = new DataOutputStream(socket.getOutputStream());
		toServer.writeUTF((text));
		outputStream.flush();

	}
	private void shakeHande(Socket socket) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
		byte[] buffer = new byte[1024];
		int read;
		OutputStream outputStream = socket.getOutputStream();
		outputStream.write("HELLO".getBytes());
		read = socket.getInputStream().read(buffer);
		String clientData = new String(buffer, 0, read);
		byte[] seed = Encryption.generateSeed();
		System.out.println(seed.length);
		this.communicationKey = Encryption.generateAESKey(seed);
		if(clientData.equals("CONNECTED")){
			byte[] encryptedSeed = Encryption.pkEncrypt(this.serverPublicKey, seed);
			System.out.println(encryptedSeed.length);
			outputStream.write(encryptedSeed);

		}
	}

	
	public static void main(String[] args) {
		ChatClient chatClient = new ChatClient();
	}
}
