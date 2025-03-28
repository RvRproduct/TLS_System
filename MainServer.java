import java.io.*;
import java.net.*;

public class MainServer 
{
    public static final int PORT = 44444;

    public static void main(String[] args)
    {
        try (ServerSocket serverSocket = new ServerSocket(PORT))
        {
            System.out.println("[Server] Listening on port " + PORT);
            while (true)
            {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[Server] Connection accepted from " + clientSocket.getInetAddress());

                // Handle Client Connection
                handleClient(clientSocket);
            }
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket clientSocket)
    {
        try (
            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())
        )
        {
            System.out.println("[Server] Performing handshake...");
            HandshakeSession session = Handshake.performServerHandshake(in, out);

            SecureChannel channel = new SecureChannel(session, in, out, SecureChannel.Role.SERVER);

            System.out.println("[Server] Sending secure messages...");
            channel.send("Hello from Choom Server - message 1".getBytes());
            System.out.println("[Server] Sent message 1");
            channel.send("Hello Again from Choom Server - message 2".getBytes());
            System.out.println("[Server] Sent message 2");

            System.out.println("[Server] Waiting for client confirmation...");
            byte[] response = channel.receive();
            System.out.println("[Server] Received confirmation: " + new String(response));

            if (new String(response).contains("received both messages")) 
            {
                System.out.println("[Server] Client confirmed receipt of both messages.");
            }
            else 
            {
                System.out.println("[Server] Unexpected confirmation response.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
