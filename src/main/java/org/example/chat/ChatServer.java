package org.example.chat;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;

import org.example.encryption.Encryption;

import java.security.*;


public class ChatServer extends JFrame {

	private static final String  RSA = "RSA";
	private Key privateKey;
	private ArrayList<String> messages;
	private HashMap<Socket,info> clients;
	private int clientCount = 0;

	public ChatServer() {


		super("Chat Server");
		setSize(400, 300);
		setLocationRelativeTo(null);
		setDefaultCloseOperation(EXIT_ON_CLOSE);

		//init arraylist for clients and message
		this.messages = new ArrayList<>();
		this.clients = new HashMap<>();




		// create menu bar
		JMenuBar menuBar = new JMenuBar();
		setJMenuBar(menuBar);

		// create menu
		JMenu fileMenu = new JMenu("File");
		menuBar.add(fileMenu);

		// create menu item
		JMenuItem exitItem = new JMenuItem("Exit");
		exitItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent event) {
				System.exit(0);
			}
		});
		fileMenu.add(exitItem);



		// create textarea
		JTextArea textArea = new JTextArea();
		JScrollPane scrollPane = new JScrollPane(textArea);
		textArea.setLineWrap(true);
		textArea.setWrapStyleWord(true);
		textArea.setEditable(false);
		textArea.append("Server created on "+System.currentTimeMillis()+"\n");

		// add elements
		add(scrollPane, BorderLayout.CENTER);
		this.setVisible(true);

		try {
			privateKey = Encryption.readPrivateKey("src/main/java/org/example/keypairs/pkcs8_key");
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("problem loading private key: " + e.getMessage());
			System.exit(1);
		}
		int port = 9898;
		try (ServerSocket serverSocket = new ServerSocket(port)) {
			System.out.println("Server is listening on port " + port);


			while (true) {
				Socket socket = serverSocket.accept();
				System.out.println("Connected to a client");

				new Thread(() -> {
                    try {
                        handleSocket(socket,textArea);
                    } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException |
                             NoSuchAlgorithmException | BadPaddingException | InvalidKeyException |
                             InvalidAlgorithmParameterException e) {
                        throw new RuntimeException(e);
                    }
                }).start();
			}
		} catch (IOException e) {
			System.out.println("Server exception: " + e.getMessage());
			e.printStackTrace();
		}

	}
	private void sendMessage(Socket socket) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
		if(!this.messages.isEmpty()){
			String tmp = messages.remove(0);
			Set<Socket> sockets = clients.keySet();
			for (Socket each : sockets) {
				if(socket.equals(each)){
					continue;
				}
				String tosend = this.clients.get(socket).id+":"+tmp;
				tosend = Encryption.encrypt(clients.get(each).communicationKey,tosend);
				OutputStream stream = each.getOutputStream();
				DataOutputStream toClient = new DataOutputStream(stream);
				toClient.writeUTF(tosend);
				stream.flush();
			}

		}
	}
	private synchronized int addOne(){
		return clientCount++;
	}
	private void handleSocket(Socket socket, JTextArea textArea) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

		handshake(socket,textArea);
		System.out.println(socket.getPort());
		byte[] buffer = new byte[1024];
		int read;
		DataInputStream fromClient = new DataInputStream(socket.getInputStream());
		while (true) {
			try {
				String clientData = fromClient.readUTF();
				clientData = Encryption.decrypt(clients.get(socket).communicationKey, clientData);
				String str = "on port: " + socket.getPort() + " client " + this.clients.get(socket).id + " said: " + clientData+"\n";
				System.out.println(str);
				textArea.append(str);

				this.messages.add(clientData);
				this.sendMessage(socket);
			} catch (EOFException e) {
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
//		String str = "client " + this.clients.get(socket) + " disconnected\n";
//		this.clients.remove(socket);
//		textArea.append(str);
	}
	private class info{
		int id;
		Key communicationKey;

		public int getId() {
			return id;
		}

		public void setId(int id) {
			this.id = id;
		}

		public Key getCommunicationKey() {
			return communicationKey;
		}

		public void setCommunicationKey(Key communicationKey) {
			this.communicationKey = communicationKey;
		}

		public info(Key communicationKey, int id) {
			this.communicationKey = communicationKey;
			this.id = id;
		}
	}


	private void handshake(Socket socket,JTextArea textArea) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
		byte[] buffer = new byte[1024];
		int read;
		OutputStream outputStream = socket.getOutputStream();
		read = socket.getInputStream().read(buffer);
		String clientData = new String(buffer, 0, read);
		if(clientData.equals("HELLO")){
			outputStream.write("CONNECTED".getBytes());
			buffer = new byte[128]; // Buffer to store bytes read from the InputStream
			int totalBytesRead = 0; // Total bytes read into the buffer

			try {
				while (totalBytesRead < buffer.length) {
					int bytesRemaining = buffer.length - totalBytesRead;
					// Read at most as many bytes as will fit in the buffer
					int bytesRead = socket.getInputStream().read(buffer, totalBytesRead, bytesRemaining);
					if (bytesRead == -1) {
						// End of stream is reached
						break;
					}
					totalBytesRead += bytesRead;
				}
			}catch (IOException e) {
				e.printStackTrace();
			}

//			String encryptedSeed = new String(buffer, 0, read);
//			System.out.println(encryptedSeed.getBytes().length);
			byte[] seed = Encryption.pkDecrypt(privateKey,buffer);
			Key communicationKey = Encryption.generateAESKey(seed);
			int size = addOne();
			info clientInfo = new info(communicationKey,size);
			this.clients.put(socket,clientInfo);
			textArea.append("on port:" + socket.getPort() + " client "+clients.get(socket).id +" connected!\n");
		}


	}

	public static void main(String[] args) {
		ChatServer chatServer = new ChatServer();
	}


}


