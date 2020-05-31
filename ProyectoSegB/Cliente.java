//package Ej;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.util.Calendar;
import java.text.SimpleDateFormat;
import java.text.DateFormat;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.nio.ByteBuffer;
import java.util.Date;

public class Cliente extends Thread{
	
	protected Socket Socket;
    protected static DataOutputStream out;
    protected static DataInputStream in;
    private int id;
    private static Scanner teclado = new Scanner(new InputStreamReader(System.in));
    
    
    public Cliente(int id) {
        this.id = id;
    }
    
    //@Override
    
    /*public void run() {
        try {
            Socket = new Socket("localhost", 9000);
            out = new DataOutputStream(Socket.getOutputStream());
            in = new DataInputStream(Socket.getInputStream());
            System.out.println(id + " envía saludo");
            out.writeUTF("hola");
            String respuesta="";
            respuesta = in.readUTF();
            System.out.println(id + " Servidor devuelve saludo: " + respuesta);
            in.close();
            out.close();
            Socket.close();
        } catch (IOException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }*/
	
	/////////////////////////////////////////////////////
    
    public static String idUsuario = "";
	public static String KeyStoreFile = "";
	public static String TrustStoreFile = "";
	public static String contrasenhaKeyStore  = "cliente";
	public static String contrasenhaTrustStore = "cliente";
	public static final String algoritmoCifrado="RSA";
	public static SSLSocket socket;
    private static String Storepath =  "Almacen/";
    public static KeyStore KeyStore,TrustStore;
    //public static Principal idPropietario;
    
	public static void main(String[] args) {
		
		int seleccion = 0;
		int numero_suite = 0;
		boolean exit = false;
		
		SSLSocketFactory socket_factorySSL = null;
		SSLContext context;
		KeyManagerFactory keymanagerfactory;
		ServerSocketFactory ServerFactory = null;
		SSLServerSocket ServerSocket;
		//KeyStore KeyStore = null;
		//KeyStore TrustStore;
		SSLContext Context;
        String[] cipherSuites = null;
        String[] suitesValidas = null;
        HashMap <Integer,String> cipher_suites_map = new HashMap<Integer,String>();
		
		if (args.length == 3) {
			
			KeyStoreFile = args[0].trim();
			TrustStoreFile = args[1].trim();
			idUsuario = args[2].trim();
			
		} else {
			System.out.println("Argumentos incorrectos");
			System.exit(-1);
		}
		
		Scanner EntradaTeclado = new Scanner(System.in);
		System.setProperty("javax.net.ssl.keyStore", Storepath + KeyStoreFile);
		System.setProperty("javax.net.ssl.trustStore", Storepath + TrustStoreFile);
		System.out.print("Introduzca la pass del keystore:");
		contrasenhaKeyStore = EntradaTeclado.nextLine();
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", contrasenhaKeyStore);
		System.out.print("Introduzca la pass del truststore:");
		contrasenhaTrustStore = EntradaTeclado.nextLine();
		System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
      		System.setProperty("javax.net.ssl.trustStorePassword", contrasenhaTrustStore);

        
		try {
			
			context = SSLContext.getInstance("TLS");
			keymanagerfactory = KeyManagerFactory.getInstance("SunX509");
			KeyStore = KeyStore.getInstance("JCEKS");
			KeyStore.load(new FileInputStream(Storepath + KeyStoreFile), contrasenhaKeyStore.toCharArray());
			keymanagerfactory.init(KeyStore, contrasenhaKeyStore.toCharArray());
			
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			TrustStore = KeyStore.getInstance("JCEKS");
			TrustStore.load(new FileInputStream( Storepath + TrustStoreFile), contrasenhaTrustStore.toCharArray());
			tmf.init(TrustStore);
			context.init(keymanagerfactory.getKeyManagers(), tmf.getTrustManagers(), null); //Ponemos a null el trust y el secure porque no tenemos		
			socket_factorySSL = context.getSocketFactory();
	
			
			socket = (SSLSocket) socket_factorySSL.createSocket("localhost" , 9000);
			cipherSuites = socket_factorySSL.getDefaultCipherSuites();
			socket.setEnabledCipherSuites(cipherSuites);
			 for (int i=0; i<cipherSuites.length; i++) 
		     		System.out.println (cipherSuites[i]);

			try {
			System.out.println ("Comienzo SSL Handshake");
			socket.startHandshake();
			System.out.println ("Fin SSL Handshake");
			}catch (Exception ex) {
				ex.printStackTrace();
			}
			
			in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());
           
			
            while(!exit) {
            	
             System.out.println("Elija una de las opciones:\n");
             System.out.println("1.- Registrar documento");
             System.out.println("2.- Listar documentos");
             System.out.println("3.- Recuperar documento");
             System.out.println("4.- Salir");
             
             seleccion = EntradaTeclado.nextInt();
            // seleccion=1;
             
             
             switch (seleccion) {
             
             case 1:
            	 Registrar_Documento();
            	 break;
             case 2:
            	 Listar_Documento();
            	 break;
             case 3:
            	 Recuperar_Documento();
            	 break;
             case 4:
            	 out.writeUTF("4");
            	 //dataout.flush();
            	 System.out.println("Cerrado");
            	 exit = true;
            	 break;
             default:
            	 System.out.println("Opcion incorrecta");
            	 break;             
             }
           }
		}catch (Exception ex) {
			
			ex.printStackTrace();
			System.exit(-1);
			
		}
	}
	
	public static void Registrar_Documento() throws IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnrecoverableEntryException, CertificateEncodingException, NoSuchProviderException {
		
		String nombreDocumento;
		File Documento=null;
		byte[] byte_leidos= new byte[112]; //Mantener siempre a 112 para que al cifrarla llege a 128 por los 16 de mas
		Boolean Exit=false;
		int i,j;
		//byte[] timeStamp=new byte[128];
		//idPropietario=0;
		int IDRegistro=0;
		//byte[] SigRD=new byte[2048];
		//byte[] certificadoServ= new byte[2048];
		String Confidencialidad,tipoConfidencialidad;
		
		System.out.println("Llega a registrar documento");
		//out.flush();
		out.writeUTF("1");
		
		/*String confirmacion=in.readUTF();
		if(confirmacion=="Error"){
			System.out.print("Error");
			return;
		}*/
		//while(!Exit) {
		
		//System.out.println("Elige el documento: ");
		try {
			
			//cipher.init(Cipher.ENCRYPT_MODE, secKey);
			
			System.out.println("Nombre del documento sin cifrar: ");
			nombreDocumento=teclado.nextLine();
			//System.out.println("Nombre del documento cifrado:");
			//DocumentoCifrado=teclado.nextLine();
			
			//Documento=new File();
			//FileInputStream fis = new FileInputStream(DocumentoSinCifrar);
			//FileOutputStream fos = new FileOutputStream(DocumentoCifrado);
			//CipherOutputStream cos = new CipherOutputStream(fos, cipher);
			Documento= new File(nombreDocumento);
			
		}catch(Exception ex) {
			System.out.println("No se encuentra el archivo");
			return;
		}
		
		/////Pedimos el tipo de confidencialidad
		
		System.out.println("Introduzca tipo de confidencialidad: ");
		Confidencialidad=teclado.nextLine();
		
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(Documento));
		BufferedOutputStream bos = new BufferedOutputStream(socket.getOutputStream());
		
		if(Confidencialidad.equals("PUBLICO")) {
			//System.out.println("Llega a publico");	
			//BufferedInputStream bis = new BufferedInputStream(new FileInputStream(Documento));
			//BufferedOutputStream bos = new BufferedOutputStream(socket.getOutputStream());
			 //Enviamos el nombre del fichero
			 //DataOutputStream dos=new DataOutputStream(client.getOutputStream());
			 //dos.writeUTF(localFile.getName());
			 //Enviamos el fichero
			
			 out.writeUTF(nombreDocumento);
			 out.writeUTF(idUsuario);
			 out.writeUTF(Confidencialidad);
			 

			 int longitud_Doc=(int) Documento.length();
			 byte[] byteArray = new byte[longitud_Doc];
				out.writeLong(Documento.length());
				//bis.read(byteArray,0,byteArray.length);
			 while ((i = bis.read(byteArray)) != -1){
			 	//bos.write(byteArray,0,byteArray.length);
				out.write(byteArray,0,byteArray.length);
			 }
			 	bis.close();
			 	//bos.close();
		}
		
		if(Confidencialidad.equals("PRIVADO")) {
			
			out.writeUTF(nombreDocumento);
			out.writeUTF(idUsuario);
			out.writeUTF(Confidencialidad);
			
			//System.out.println("Llega a privado");
			//////////////////CIFRADO//////////////////
			
			KeyGenerator keyGen=null;
			try {
				
				keyGen = KeyGenerator.getInstance("AES");
			
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			keyGen.init(128);
			SecretKey sessionKey = keyGen.generateKey(); ///Clave k
			//System.out.println(sessionKey);
			
			X509Certificate certificado=(X509Certificate) TrustStore.getCertificate("Servidor");
			Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipher.init(Cipher.ENCRYPT_MODE, certificado.getPublicKey());
			byte[] kcifrada = rsaCipher.doFinal(sessionKey.getEncoded()); //CLave k cifrada
			
			out.writeLong(kcifrada.length);
			out.write(kcifrada,0,kcifrada.length);//Enviamos la clave cifrada
			
			//BufferedInputStream bis = new BufferedInputStream(new FileInputStream(Documento));
			
			Cipher AESCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			AESCipher.init(Cipher.ENCRYPT_MODE,sessionKey);
			byte[] Envio= new byte[128];
			long tamDoc=Documento.length();
			//System.out.println(tamDoc);
			out.writeLong(tamDoc);
			char espacio=' ';
			byte Espacio= (byte) espacio;
			int ultimotrozo= (int) tamDoc % 112;
			int numtrozos=(int) tamDoc/112; 
			int contador=1;
			//System.out.println(ultimotrozo);

			while((j =bis.read(byte_leidos,0,byte_leidos.length)) !=-1) {
							
				//if(byte_leidos.length<112){
				//	Arrays.fill(byte_leidos,j,112,Espacio);
				//}
				//System.out.println(new String (byte_leidos));
				Envio=AESCipher.doFinal(byte_leidos);
				//System.out.println("Contenido cifrado");
				out.write(Envio,0,Envio.length);//Enviamos el array de bytes por chachos de 128 bytes 
				out.flush();
				//System.out.println(numtrozos);
				//System.out.println(contador);
				
				//if(contador==numtrozos){		
					//byte_leidos=new byte[ultimotrozo];	
				//}else{
					byte_leidos=new byte[112];
				//}
				contador++;
					
			}
			bis.close();
			}
			//////////////////////FIN CIFRADO//////////////////////////////
			
			////////////////////////FIRMA/////////////////////////////////
			
			//System.out.println("Empezamos la firma");
			try {
				
			String Alias="Cliente";
			byte[] firma_byte=new byte[2048];
			PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) KeyStore.getEntry(Alias,new KeyStore.PasswordProtection(contrasenhaKeyStore.toCharArray()));
            		PrivateKey privateKey = privateKeyEntry.getPrivateKey();
            		Signature sig = Signature.getInstance("SHA1withRSA");
            		sig.initSign(privateKey);
            
			    BufferedInputStream fichero=new BufferedInputStream(new FileInputStream(Documento)); 
					
			    while(fichero.read(firma_byte) != -1) {
				sig.update(firma_byte,0,firma_byte.length);//Enviamos el array de bytes por cachos de 128 bytes 
			    }
			    fichero.close();
			    
			    byte[] FirmaDoc=sig.sign();
			    //System.out.println(FirmaDoc.length);

			    out.writeUTF(Integer.toString(FirmaDoc.length));//Enviamos la firma del documento
            			out.write(FirmaDoc);
				
			} catch (SignatureException e) {
				e.printStackTrace();
			}
			//System.out.println("Fin firma");
			
			/////////////////////////FIN FIRMA////////////////////////////
			
			//////////////////////CERTIFICADO/////////////////////////////
			try {
				String Alias="cliente";
				out.writeUTF(Integer.toString(KeyStore.getCertificate(Alias).getEncoded().length));
				out.write(KeyStore.getCertificate(Alias).getEncoded());
				
			
			} catch (CertificateEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			//System.out.println("Fin certificado");			

			String recepcion = in.readUTF();
	        
	        if (recepcion.equals("CERTIFICADO DE FIRMA INCORRECTO")) {
	        	System.out.println("Certificado de firma incorrecto.");
	        	return;
	        }
	        
	        if (recepcion.equals("FIRMA INCORRECTA")) {
	        	System.out.println("Firma incorrecta.");
	        	return;
	        }
		
			////////////////////////FIN CERTIFICADO//////////////////////////
	    
	        IDRegistro = Integer.parseInt(in.readUTF());

		int long_timeStamp=Integer.parseInt(in.readUTF());
		byte[] timeStamp=new byte[long_timeStamp];
	        in.read(timeStamp);

		//idPropietario=Integer.parseInt(in.readUTF());
		idUsuario=in.readUTF();		
		
		int long_SigRD=Integer.parseInt(in.readUTF());
		byte[] SigRD=new byte[long_SigRD];
	        in.read(SigRD);

		int long_certificadoServ=Integer.parseInt(in.readUTF());
		byte[] certificadoServ=new byte[long_certificadoServ];
	        in.read(certificadoServ);
	        
	        
	        if(!Arrays.equals(certificadoServ, TrustStore.getCertificate("Servidor").getEncoded())) {
	        	System.out.println("Certificado de registro incorrecto");
	        	return;
	        }
	        

	       		
		
            
       	 return;
		
	}

	public static long bytesalong(byte[] bytes) {
	    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	    buffer.put(bytes);
	    buffer.flip();
	    return buffer.getLong();
	}

	public static File descifrador(int idRegistro) throws NoSuchProviderException {
	try {

		byte[] array_bytes = new byte [128];
		//byte[] intermedio = new byte [128];
		//byte[] key_des_fich= new byte [256];			
		int bytes_leidos = 0,j=0;
		int bytes_recibidos = 0;
		byte[] byte_leidos=new byte[128];
		int long_key_des_fich=0;
		//int i = 0;
		String Alias = "cliente", contrasenha = "cliente";


		//KeyStore = KeyStore.getInstance("JCEKS");
		//KeyStore.load(new FileInputStream(Cliente.KeyStore), Servidor.ContrasenhaKeyStore.toCharArray());

		PrivateKeyEntry pke = (PrivateKeyEntry) KeyStore.getEntry(Alias, new KeyStore.PasswordProtection(contrasenhaKeyStore.toCharArray()));

		PrivateKey privatekey = pke.getPrivateKey();
		//System.out.println(privatekey);
		//SecretKey secret_key = new SecretKeySpec(privatekey, 0, "RSA");
		

		//Desciframos la clave
		Cipher descifradorkey = Cipher.getInstance("RSA/ECB/PKCS1Padding");//"RSA/ECB/PKCS1Padding"
		descifradorkey.init(Cipher.DECRYPT_MODE, privatekey);
		
		long_key_des_fich= (int) in.readLong();
		//System.out.println(long_key_des_fich);
		byte[] key_des_fich=new byte[long_key_des_fich];		
		
		in.read(key_des_fich);
		//System.out.println(key_des_fich);
		
		//decodedkey_des_fich=descifradorkey.update(key_des_fich,0,long_key_des_fich);
		//decodedkey_des_fich=descifradorkey.doFinal(key_des_fich);
		SecretKey key_des_doc = new SecretKeySpec(descifradorkey.doFinal(key_des_fich),  "AES");
		
		File archivo = new File("Cliente/Documento_pedido_cliente"+idRegistro+".txt"); //Introducir path del archivo a utilizar
		FileOutputStream Salida = new FileOutputStream(archivo);
		
		//Desciframos el documento
			//System.out.println("Desciframos el documento");
		Cipher  descifradordoc= Cipher.getInstance("AES/ECB/PKCS5Padding");
		//System.out.println(key_des_doc.size());
		descifradordoc.init(Cipher.DECRYPT_MODE, key_des_doc);
		
		byte[] Recibido=new byte[112];
		int tamDoc=0;
		tamDoc=(int) in.readLong();
		//System.out.println(tamDoc);
		//tamDoc=tamDoc-1;
		int ultimotrozo= (int) tamDoc % 112;
		int numtrozos=(int) tamDoc/112; 
		int contador=1;
		//System.out.println(ultimotrozo);
		byte[] otroarray=new byte[112];
		//try {
			//byte[] byte_leidos=new byte[128];
			//System.out.println(in.read(byte_leidos));
			while(/*(j =in.read(byte_leidos)) != -1 &&*/ tamDoc>0) {
				j =in.read(byte_leidos);
					//System.out.println(j);
				Recibido=descifradordoc.doFinal(byte_leidos);
					//System.out.println("Hola mundo");
				//Salida.flush();
				byte[] array = new String(Recibido).replaceAll("\00","").getBytes(); 
				Salida.write(array, 0, array.length);
				//Salida.flush();
				//System.out.println(new String (Recibido));
				//Salida.flush();
				tamDoc-=112;
				//System.out.println(tamDoc);
				//if(contador==numtrozos){	
					//Salida.write(Recibido, 0, ultimotrozo);	
					//otroarray=new byte[ultimotrozo];
					//otroarray=Arrays.copyOfRange(Recibido,0,ultimotrozo);
					//Salida.write(otroarray, 0, otroarray.length);
					//byte_leidos=new byte[ultimotrozo];	
					
				//}else{
					//Salida.write(Recibido, 0, Recibido.length);
					//otroarray=Arrays.copyOfRange(Recibido,0,112);
					//Salida.write(otroarray, 0, otroarray.length);
					//byte_leidos=new byte[112];
				//}
				contador++;
			}
		//}catch(BadPaddingException ex) {
			//System.out.println("Error en do Final");
		//}
		Salida.close();                    
		// fichero_out.close();


		return archivo ;
	} catch (Exception e) {
		e.printStackTrace();
	}
	System.out.println("Error al descifrar el archivo");
	return null;

	}
	public static void Listar_Documento() throws CertificateEncodingException, KeyStoreException, IOException {
		
		String Confidencialidad="";
		int long_certificado=KeyStore.getCertificate("Cliente").getEncoded().length;
		byte[] Certificado = new byte[long_certificado];
		String Confirmacion="",nombreDoc="";
		int Tamano_lista=0,long_selloTemporal=0,idRegistro=0,id_Propietario=0;	
	
		out.writeUTF("2");

		System.out.println("Listar documentos publicos o privados?");
		Confidencialidad=teclado.nextLine();
		
		switch(Confidencialidad){

			case "PUBLICO":
				out.writeUTF("PUBLICO");
				//System.out.println("PUBLICO");
				Certificado=(KeyStore.getCertificate("Cliente")).getEncoded();
				out.writeInt(long_certificado);
				//System.out.println(long_certificado);
				out.write(Certificado);
				//System.out.println(Certificado);
				Confirmacion=in.readUTF();
				//System.out.println(Confirmacion);

				if(Confirmacion.equals("CERTIFICADO INCORRECTO")){
					System.out.println("Certificado incorrecto");
					return;
				}else{
					System.out.println("CERTIFICADO CORRECTO");
					Tamano_lista=Integer.parseInt(in.readUTF());
					System.out.println();
					System.out.println("Lista de documentos privados:");
					for(int i=1;i<=Tamano_lista;i++){

						idRegistro=Integer.parseInt(in.readUTF());
						id_Propietario=Integer.parseInt(in.readUTF());
						nombreDoc=in.readUTF();
						long_selloTemporal=Integer.parseInt(in.readUTF());
						byte[] selloTemporal=new byte[long_selloTemporal];	
						in.read(selloTemporal);
						//String sello = new String((byte[]) selloTemporal);
						//Date Stamp = new SimpleDateFormat("yyyy-MM-dd").parse(sello);

						System.out.println("Documento numero "+i+" :");
						System.out.println("IDRegistro: "+idRegistro);
						System.out.println("IDPropietario: "+id_Propietario);
						System.out.println("NombreDocumento: "+nombreDoc);
						System.out.println("SelloTemporal: "+new Date(bytesalong(selloTemporal)).toString());
						System.out.println();
					}				
				}		
			break;
			
			case "PRIVADO":
				out.writeUTF("PRIVADO");
				//System.out.println("PRIVADO");
				Certificado=(KeyStore.getCertificate("Cliente")).getEncoded();
				out.writeInt(long_certificado);
				//System.out.println(long_certificado);
				out.write(Certificado);
				//System.out.println(Certificado);
				Confirmacion=in.readUTF();
				//System.out.println(Confirmacion);

				if(Confirmacion.equals("CERTIFICADO INCORRECTO")){
					System.out.println("Certificado incorrecto");
					return;
				}else{
					System.out.println("CERTIFICADO CORRECTO");
					Tamano_lista=Integer.parseInt(in.readUTF());
					System.out.println();
					System.out.println("Lista de documentos privados:");
					for(int i=1;i<=Tamano_lista;i++){

						idRegistro=Integer.parseInt(in.readUTF());
						id_Propietario=Integer.parseInt(in.readUTF());
						nombreDoc=in.readUTF();
						long_selloTemporal=Integer.parseInt(in.readUTF());
						byte[] selloTemporal=new byte[long_selloTemporal];	
						in.read(selloTemporal);
						//String sello = new String((byte[]) selloTemporal);
						//Date Stamp = new SimpleDateFormat("yyyy-MM-dd").parse(sello);

						System.out.println("Documento numero "+i+" :");
						System.out.println("IDRegistro: "+idRegistro);
						System.out.println("IDPropietario: "+id_Propietario);
						System.out.println("NombreDocumento: "+nombreDoc);
						System.out.println("SelloTemporal: "+new Date(bytesalong(selloTemporal)).toString());
						System.out.println();
					}				
				}		
			break;
		}

	}
	public static void Recuperar_Documento() throws CertificateEncodingException, KeyStoreException, IOException, NoSuchProviderException{
		
	int IDRegistro=0;
	String Confirmacion_ID="",Confirmacion_cert="";
	File file=null;

	out.writeUTF("3");

	System.out.println("Introduce ID de registro del documento:");
	IDRegistro=teclado.nextInt();
	
	out.writeInt(IDRegistro);
	
	Confirmacion_ID=in.readUTF();
	if(Confirmacion_ID.equals("DOCUMENTO NO EXISTE")){
		System.out.println("El documento no existe");
		return;
	}else{
		System.out.println("El documento existe");
	}

	int long_certificado=KeyStore.getCertificate("Cliente").getEncoded().length;
	byte[] Certificado = new byte[long_certificado];
	Certificado=(KeyStore.getCertificate("Cliente")).getEncoded();

	out.writeInt(long_certificado);
	out.write(Certificado);
	
	Confirmacion_cert=in.readUTF();

	if(Confirmacion_cert.equals("ACCESO NO PERMITIDO")){
		System.out.println("Usuario no identificado");
		return;
	}else{
		System.out.println("Usuario identificado");
	}
	//in.read();
	file=descifrador(IDRegistro);

	System.out.println("DOCUMENTO RECUPERADO CORRECTAMENTE");







	
    }
       
}
	

