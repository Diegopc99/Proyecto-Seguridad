//package Ej;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class Servidor {

	public static String KeyStoreFile ="";
	public static String ContrasenhaKeyStore="servidor";
	public static String TrustStoreFile="";
	public static String ContrasenhaTrustStore= "servidor";
	public static String AlgoritmoCifrado="";
	public static int IDRegistro;
	public static String StorePath = "Almacen/";
	public static KeyStore KeyStore;
	public static KeyStore TrustStore;
	public static String path ="Servidor/";
	
	public static void main(String args[]) {
		
		SSLServerSocketFactory ServerSocketFactorySSL=null;
		ServerSocketFactory ServerFactory = null;
		SSLServerSocket ServerSocket;
		KeyManagerFactory KeyManagerFactory = null;
		//KeyStore KeyStore = null;
		//KeyStore TrustStore;
		SSLContext Context;
		
		if(args.length == 4) {
		
			KeyStoreFile=args[0].trim(); //Eliminamos los espacios 
			ContrasenhaKeyStore=args[1].trim();
			TrustStoreFile=args[2].trim();
			AlgoritmoCifrado=args[3].trim();
			
		}else {
			System.out.println("Faltan argumentos");
			System.exit(-1);
		}
		
		System.setProperty("javax.net.ssl.keyStore", StorePath + KeyStoreFile);
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", ContrasenhaKeyStore);
		
		System.setProperty("javax.net.ssl.trustStore", StorePath + TrustStoreFile);
        System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
        System.setProperty("javax.net.ssl.trustStorePassword", ContrasenhaTrustStore);
	
	//////////////////////////////////////////////////////////
	
	System.out.println("IniciandoServidor...");

        try {
        	
		Context = SSLContext.getInstance("TLS");
		KeyManagerFactory = KeyManagerFactory.getInstance("SunX509");
		
			KeyStore = KeyStore.getInstance("JCEKS");
			KeyStore.load(new FileInputStream(StorePath + KeyStoreFile), ContrasenhaKeyStore.toCharArray());
		
		KeyManagerFactory.init(KeyStore, ContrasenhaKeyStore.toCharArray());
		TrustManagerFactory TrustManFac = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			
			TrustStore=KeyStore.getInstance("JCEKS");
			TrustStore.load(new FileInputStream(StorePath + TrustStoreFile), ContrasenhaKeyStore.toCharArray());
			TrustManFac.init(TrustStore);
			
		Context.init(KeyManagerFactory.getKeyManagers(),null,null);
		
	//////////////////////Anadido//////////////
		ServerSocketFactorySSL = Context.getServerSocketFactory();
			
            ServerFactory = ServerSocketFactorySSL;
            
            ServerSocket = (SSLServerSocket) ServerFactory.createServerSocket(9000);
            ServerSocket.setNeedClientAuth(true);
		
	System.out.println("[OK]");
	int contador_hilos=0;
	int idSession=0; 
		
	while (true) {
            
		Socket cliente = ServerSocket.accept();
             SocketHilo thread = new SocketHilo(cliente,idSession);
             thread.setName("Hilo"+contador_hilos);
             thread.start();
	     contador_hilos++;
	     idSession++;
	}
///////////////////////////////////////////////////////
		} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
			e.printStackTrace();
		
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyManagementException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        /////////////////////Iniciamos la conexion con el Thread
        
        /*ServerSocket SS;
        System.out.print("Inicializando servidor... ");
        
        try {
            SS = new ServerSocket(9000);
            
            System.out.println("[OK]");
            int ContadorHilos = 0;
            int idSession = 1;
            
            while (true) {

                Socket socket = SS.accept();
                System.out.println("Nueva conexión entrante: ");
                SocketHilo Thread = new SocketHilo(socket,idSession);
                Thread.setName("Hilo" + ContadorHilos);
                Thread.start();
                idSession++;
                ContadorHilos++;
            }
        } catch (IOException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        }
    }*/
}
}

