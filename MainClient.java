import java.io.*;
import java.net.*;

public class MainClient 
{
    public static void main(String[] args) 
    {
        String serverHost = "localhost";
        int serverPort = MainServer.PORT;

        try (Socket socket = new Socket(serverHost, serverPort))
        {
            System.out.println("[Client] Connected to server at " + serverHost + ":" + serverPort);

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            System.out.println("[Client] Performing handshake...");
            HandshakeSession session = Handshake.performClientHandshake(in, out);

            SecureChannel channel = new SecureChannel(session, in, out, SecureChannel.Role.CLIENT);

            System.out.println("[Client] Receiving secure messages...");
            byte[] message1 = channel.receive();
            System.out.println("[Client] Received: " + new String(message1));
            byte[] message2 = channel.receive();
            System.out.println("[Client] Received: " + new String(message2));

            String confirmation = "Client received both messages successfully";
            System.out.println("[Client] Sending confirmation: " + confirmation);
            channel.send(confirmation.getBytes());

        } 
        catch (Exception e) 
        {
            e.printStackTrace();
        }
    }
}

