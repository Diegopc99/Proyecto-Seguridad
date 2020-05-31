//package Ej;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.GregorianCalendar;
import java.nio.ByteBuffer;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class SocketHilo extends Thread{
	
	private Socket socket;
    private int idSessio;
    //private static Socket cliente;
	private static String idPropietario;
	private static String nombreDoc;
	private static String tipoConf;
	public static long longDoc = 0;
	private static SecretKey ClaveCifDocumentoServidor;
	public static KeyStore KeyStore, TrustStore;
	public static BufferedReader buffin;
	public static PrintWriter buffout;
	public static ArrayList<Documento> Documentos = new ArrayList<Documento>();
	public static BufferedReader lectura;
	public static PrintWriter Salida;
	public static DataInputStream in;
	public static DataOutputStream out;
    
    public SocketHilo(Socket socket, int id) {
        this.socket = socket;
        this.idSessio = id;
        try {
		//System.out.println("LLega a Socket hilo");
	    buffin = new BufferedReader(new InputStreamReader(socket.getInputStream()));
	    buffout = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));

            out = new DataOutputStream(socket.getOutputStream());
            in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        } catch (IOException ex) {
            Logger.getLogger(SocketHilo.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public void desconectar() {
        try {
            socket.close();
        } catch (IOException ex) {
            Logger.getLogger(SocketHilo.class.getName()).log(Level.SEVERE, null, ex);
        }
	return;
    }
    
    @Override
    public void run() {
        
    	boolean exit=false;
        try {
            
        while(!exit) {
        	
        	String seleccion=in.readUTF();

		//System.out.println("LLega a run");
        	
            switch(seleccion) {
            	case "1":
            		Registrar_Documento();
            		break;
            	case "2":
            		Listar_Documentos();
            		break;
            	case "3":
            		Recuperar_Documento();
            		break;
            	case "4":
            		System.out.println("Saliendo..");
            		exit=true;
            		desconectar();
            		break;
            	default:
            		out.writeUTF("Error");
            		break;
            }
        	}
        } catch (IOException ex) {
            Logger.getLogger(SocketHilo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NumberFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	return;
    }
    
    public void Registrar_Documento() throws NumberFormatException, IOException, NoSuchProviderException, KeyStoreException, CertificateEncodingException , Exception, NoSuchAlgorithmException{
    	
    	BufferedInputStream bis = new BufferedInputStream(socket.getInputStream());
    	String Nombre_Documento="",Confidencialidad="",idUsuario="";
    	int i=0,bytes_recibidos;
	long selloTemporal = 0;
	byte[] timeStamp, sigRD;
	File archivo = null;
	int IDRegistro=Servidor.IDRegistro;
	Servidor.IDRegistro+=1;
    	
	//System.out.println("Llega a registrar doc en servidor");
	
    	Nombre_Documento=in.readUTF();
		//System.out.println(Nombre_Documento);
    	idUsuario=in.readUTF();
		//System.out.println(idUsuario);
    	Confidencialidad=in.readUTF();
		//System.out.println(Confidencialidad);    	

    	if(Confidencialidad.equals("PUBLICO")) {
    		
	//System.out.println("Llega a publico");
    		
	//Servidor.IDRegistro+=1;
	
	archivo =new File(Servidor.path+"Documento"+Servidor.IDRegistro+".txt");
	FileOutputStream Salida =new FileOutputStream(/*Servidor.path+"Documento"+Servidor.IDRegistro+".txt"*/archivo);

	KeyStore = KeyStore.getInstance("JCEKS");
	KeyStore.load(new FileInputStream(Servidor.StorePath + Servidor.KeyStoreFile), Servidor.ContrasenhaKeyStore.toCharArray());

    		
		int longitud_Doc=0;
		longitud_Doc=(int) in.readLong();
		byte[] byteArray = new byte[longitud_Doc];

    		while (/*(i = in.read(byteArray))*/ longitud_Doc > 0){
			 //bytes_recibidos=in.read(byteArray);	
			 in.read(byteArray);
			 //System.out.println(byteArray.toString());
			// System.out.println("Bucle");
			// byte[] array = new String(byteArray).replaceAll("\00","").getBytes();
			 Salida.write(byteArray,0,byteArray.length);
			 longitud_Doc-=longitud_Doc;
		}
		//in.close();
		//out.close();
    		
    	}


				
    	
    	if(Confidencialidad.equals("PRIVADO")) {
    		
		/*Nombre_Documento=in.readUTF();
			System.out.println(Nombre_Documento);
    		idUsuario=Integer.parseInt(in.readUTF());
			System.out.println(idUsuario);
    		Confidencialidad=in.readUTF();
			System.out.println(Confidencialidad);  
    		*/
		archivo=descifrador();
    		//System.out.println("Acaba");
    	}

	//System.out.println("Comenzamos la firma y el cert");
	int longitud_firma = Integer.parseInt(in.readUTF());
	//System.out.println(longitud_firma);
	byte[] firmaCliente= new byte[longitud_firma];
	in.read(firmaCliente);

	int longitud_certificado = Integer.parseInt(in.readUTF());
	byte[] certificadoCliente= new byte[longitud_certificado];
	in.read(certificadoCliente);
	
	///////////////////////VERIFICAMOS EL CERTIFICADO DE FIRMA/////////////////////////////////////

	Certificate Certificado_TrustStore = (Servidor.TrustStore).getCertificate("cliente");//Meter alias del certificado del cliente
	byte[] CertificadoTrust = Certificado_TrustStore.getEncoded();	
	
	//if(certificadoCliente.equals(CertificadoTrust)){
	if(Arrays.equals(certificadoCliente,CertificadoTrust)){
		System.out.println("Certificado firma incorrecto");
		out.writeUTF("CERTIFICADO DE FIRMA INCORRECTO");
		return;
	}
	//System.out.println("Fin cert");
	///////////////////////////FIN VERIFICADO/////////////////////////////////////////////////////

		int longbloque;
		byte firma_byte[] = new byte[2048];
		try {
			
			String Alias= "Cliente";
			//System.out.println(firma.length);
			/*if (idPropietario.contains("2")) {
				trustAlias = "cliente2";
			} else {
				trustAlias = "cliente";
			}*/

			BufferedInputStream fichero=new BufferedInputStream(new FileInputStream(Servidor.path+"Documento"+Servidor.IDRegistro+".txt"));
 
			PublicKey publicKey = (Servidor.TrustStore).getCertificate(Alias).getPublicKey();
			Signature sign = Signature.getInstance("SHA1withRSA");
			sign.initVerify(publicKey);

			/*while ((longbloque = fichero.read(bloque)) !=-1) {
				sign.update(bloque, 0, longbloque);
			}*/
			while(fichero.read(firma_byte) != -1) {
				sign.update(firma_byte,0,firma_byte.length);//Enviamos el array de bytes por cachos de 128 bytes 
			}

			if (sign.verify(firmaCliente)) {
				System.out.println("La firma es correcta.");
				fichero.close();
				
			} else {
				System.out.println("La firma a tratar es incorrecta.");
				out.writeUTF("FIRMA INCORRECTA");
				fichero.close();
				return;
			
			}
		} catch (Exception e) {
			System.out.println("Fallo al verificar");
			System.out.println(e);
			return;
		}
		
		out.writeUTF("TODO CORRECTO");
		
	///////////////////////////////SELLO TEMPORAL/////////////////////////////
		
		selloTemporal = GregorianCalendar.getInstance().getTimeInMillis();
		timeStamp = longaBytes(selloTemporal);

		PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) KeyStore.getEntry("servidor",new KeyStore.PasswordProtection("servidor".toCharArray()));
		PrivateKey privateKey = privateKeyEntry.getPrivateKey();

		//Servidor.IDRegistro += 1;
		sigRD = firmaRegistro(privateKey, Servidor.IDRegistro,timeStamp,Servidor.path+"Documento"+Servidor.IDRegistro+".txt",firmaCliente);
		
		Documento nuevo = null;
		File fichero = null;
		FileOutputStream BufferGuardado = null;

		if(Confidencialidad.equals("PRIVADO")) {
			
			//fichero = new File(Servidor.path+"Documento_guardado_en_servidor"+Servidor.IDRegistro+".txt");
			//BufferGuardado = new FileOutputStream(fichero);
			cifradorAlmacen(/*BufferGuardado,*/archivo,Servidor.path+"Documento"+Servidor.IDRegistro);
			
			nuevo = new Documento(Servidor.path+"Documento"+Servidor.IDRegistro+"-cif.txt"/*Servidor.path+"Documento_recibido.txt"*/,firmaCliente,Servidor.IDRegistro,timeStamp,sigRD,certificadoCliente,Confidencialidad,idUsuario);
		archivo.delete();		
		}
		else{
			nuevo = new Documento(Servidor.path+"Documento"+Servidor.IDRegistro+".txt"/*Servidor.path+"Documento_recibido.txt"*/,firmaCliente,Servidor.IDRegistro,timeStamp,sigRD,certificadoCliente,Confidencialidad,idUsuario);
		}		
		Documentos.add(nuevo);

		out.writeUTF(Integer.toString(IDRegistro));
		//out.flush();
		out.writeUTF(Integer.toString(timeStamp.length));
		out.write(timeStamp);
		//out.flush();
		out.writeUTF(idUsuario);
		//out.flush();
		out.writeUTF(Integer.toString(sigRD.length));
		out.write(sigRD);
		//out.flush();
		byte[] certificado=KeyStore.getCertificate("servidor_cert").getEncoded();
		out.writeUTF(Integer.toString(certificado.length));
		out.write(certificado);
		//out.flush();

    	return;
    }
    
    public static File descifrador() throws NoSuchProviderException {
		try {

			byte[] array_bytes = new byte [128];
			//byte[] intermedio = new byte [128];
			//byte[] key_des_fich= new byte [256];			
			int bytes_leidos = 0,j=0;
			int bytes_recibidos = 0;
			byte[] byte_leidos=new byte[128];
			//int i = 0;
			String Alias = "servidor", contrasenha = "servidor";


			KeyStore = KeyStore.getInstance("JCEKS");
			KeyStore.load(new FileInputStream(Servidor.StorePath + Servidor.KeyStoreFile), Servidor.ContrasenhaKeyStore.toCharArray());

			PrivateKeyEntry pke = (PrivateKeyEntry) KeyStore.getEntry(Alias, new KeyStore.PasswordProtection(Servidor.ContrasenhaKeyStore.toCharArray()));

			PrivateKey privatekey = pke.getPrivateKey();
			//System.out.println(privatekey);
			//SecretKey secret_key = new SecretKeySpec(privatekey, 0, "RSA");
			

			//Desciframos la clave
			Cipher descifradorkey = Cipher.getInstance("RSA/ECB/PKCS1Padding");//"RSA/ECB/PKCS1Padding"
			descifradorkey.init(Cipher.DECRYPT_MODE, privatekey);
			
			int long_key_des_fich=(int) in.readLong();
			//System.out.println(long_key_des_fich);
			byte[] key_des_fich=new byte[long_key_des_fich];		
			
			in.read(key_des_fich);
			//System.out.println(key_des_fich);
			
			//decodedkey_des_fich=descifradorkey.update(key_des_fich,0,long_key_des_fich);
			//decodedkey_des_fich=descifradorkey.doFinal(key_des_fich);
			SecretKey key_des_doc = new SecretKeySpec(descifradorkey.doFinal(key_des_fich),  "AES");
			
			File archivo = new File(Servidor.path+"Documento"+Servidor.IDRegistro+".txt"); //Introducir path del archivo a utilizar
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
    

	
    public static byte[] firmaRegistro (PrivateKey key, int idRegistro, byte[] timestamp,
			String nombreDoc, byte[] sign) {

		try {
			FileInputStream texto = new FileInputStream(nombreDoc);
			Signature signer = Signature.getInstance("SHA256withRSA");
			signer.initSign(key);
			signer.update(intaBytes(idRegistro) , 0, 4);
			signer.update(timestamp, 0, timestamp.length);
			byte[] block = new byte[1024];
			int p = 0;
			while ((p = texto.read(block)) > 0) {
				signer.update(block, 0, block.length);
			}
			signer.update(sign, 0, sign.length);
			texto.close();
			return signer.sign();
		} catch (Exception err) {
			System.out.println("Error");
			return null;
		}
	}
	
    public static byte[] intaBytes(int x) {
		ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
		buffer.putInt(x);
		return buffer.array();
     }

    public static byte[] longaBytes(long x) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(x);
		return buffer.array();
    }	
	
    public static void cifradorAlmacen(/*FileOutputStream salida,*/ File fichero, String tmpPath) throws Exception {
		FileInputStream file = new FileInputStream(fichero);
		byte[] buffer = new byte[1024*1024];
		int bytesRead = 0;
		//String algor = "", trans= "";
		SecretKey key = null;

		//Servidor.AlgoritmoCifrado = Servidor.AlgoritmoCifrado.toLowerCase();
		//if (Servidor.AlgoritmoCifrado.equals("aes")) {
			File cifFile = new File(tmpPath.concat("-cif.txt"));
			FileOutputStream os = new FileOutputStream(cifFile);
			//algor = "AES";
			//trans = "/CBC/PKCS5Padding
			key = (SecretKey) KeyStore.getKey("servidor_cif_almacen", "servidor".toCharArray());

			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			byte[] inBlock = new byte[2024];
			byte[] outBlock = new byte[2048];
			int blockSize = 0;
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getEncoded(), "AES"));
			while ((blockSize = file.read(inBlock)) > 0) {
				outBlock = cipher.update(inBlock, 0, blockSize);
				os.write(outBlock, 0, outBlock.length);
			}
			outBlock = cipher.doFinal();
			os.write(outBlock, 0, outBlock.length);
			os.close();

			/*AlgorithmParameters params = cipher.getParameters();
			byte[] paramBytes = new byte[0];
			if (params != null) {
				paramBytes = params.getEncoded();
			}
			salida.write(intaBytes(paramBytes.length), 0, 4);
			salida.write(paramBytes, 0, paramBytes.length);
			FileInputStream is = new FileInputStream(cifFile);
			while ((bytesRead = is.read(buffer)) > 0) {
				salida.write(buffer, 0, bytesRead);
			}
			is.close();*/
			//cifFile.delete();
			file.close();
			return;
		//} else {
		//	System.out.println("Fallo con el algoritmo");
		//	file.close();
		//}

	}

	public  static File descifradorAlmacen(int idRegistro) throws Exception {

		SecretKey key = null;
		int blockSize = 0;
		byte[] inBlock = new byte[2024];
		byte[] outBlock = new byte[2048];

		File fichero = new File(Servidor.path+"DocDevolverCliente"+"borrar.txt");
		FileOutputStream file = new FileOutputStream(fichero);
		
		File fich = new File((Servidor.path)+"Documento"+idRegistro+"-cif.txt");
		FileInputStream filein = new FileInputStream(fich);
		
			key = (SecretKey) KeyStore.getKey("servidor_cif_almacen", "servidor".toCharArray());
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			//IvParameterSpec ivParameterSpec = new IvParameterSpec(key.getEncoded());
			cipher.init(Cipher.DECRYPT_MODE,key);

			//for(int i = 0; i< fich.length; i+=2048) {
			while((blockSize = filein.read(inBlock)) > 0){
				//outBlock = Arrays.copyOfRange(documento, i, i+2048);
				outBlock = cipher.update(inBlock, 0, blockSize);
				file.write(outBlock, 0, outBlock.length);
			}
			outBlock = cipher.doFinal();
			file.write(outBlock, 0, outBlock.length);
		
		file.close();
		return fichero;
	}

	


    public void Listar_Documentos() throws IOException, CertificateEncodingException, KeyStoreException {
    	
	String Confidencialidad="";
	int contador=0;
	int long_certificado=0;

	//System.out.println("Llega a listar documentos");

	Confidencialidad=in.readUTF();

	if(Confidencialidad.equals("PUBLICO")){
		//System.out.println("Confidencialidad publica");
		//in.readUTF(Confidencialidad);
		
		long_certificado=in.readInt();
		//System.out.println(long_certificado);
		byte[] Certificado_Cliente=new byte[long_certificado];
		in.read(Certificado_Cliente);
		//System.out.println(Certificado_Cliente);
		contador=0;
		Certificate Certificado_TrustStore = (Servidor.TrustStore).getCertificate("Cliente");//Meter alias del certificado del cliente
		byte[] CertificadoTrust = Certificado_TrustStore.getEncoded();

		if(!Arrays.equals(Certificado_Cliente,CertificadoTrust)){
			//System.out.println("Aqui");			
			out.writeUTF("CERTIFICADO CORRECTO");
			for(int i=0;i<Documentos.size();i++){
				if((Documentos.get(i).getConfidencialidad()).equals("PUBLICO")){
					contador++;
				}
			}
			out.writeUTF(Integer.toString(contador));//Tamano lista
			for(int j=0;j<Documentos.size();j++){
				
				if((Documentos.get(j).getConfidencialidad()).equals("PUBLICO")){
	
				out.writeUTF(Integer.toString(Documentos.get(j).getIDRegistro()));
				out.writeUTF(Documentos.get(j).getPropietario());
				out.writeUTF(Documentos.get(j).getNombreDoc());
				out.writeUTF(Integer.toString(Documentos.get(j).getSelloTemporal().length));
				out.write(Documentos.get(j).getSelloTemporal());
				
				}
			}
			return;	
		}else{
			out.writeUTF("CERTIFICADO INCORRECTO");
			return;
		}	

		
			
	}else{
		//System.out.println("Confidencialidad privada");
		//in.readUTF(Confidencialidad);
		
		long_certificado=in.readInt();
		//System.out.println(long_certificado);
		byte[] Certificado_Cliente=new byte[long_certificado];
		in.read(Certificado_Cliente);
		//System.out.println(Certificado_Cliente);
		contador=0;
		Certificate Certificado_TrustStore = (Servidor.TrustStore).getCertificate("Cliente");//Meter alias del certificado del cliente
		byte[] CertificadoTrust = Certificado_TrustStore.getEncoded();

		if(!Arrays.equals(Certificado_Cliente,CertificadoTrust)){
			//System.out.println("Aqui");			
			out.writeUTF("CERTIFICADO CORRECTO");
			for(int i=0;i<Documentos.size();i++){
				if((Documentos.get(i).getConfidencialidad()).equals("PRIVADO")){
					contador++;
				}
			}
			out.writeUTF(Integer.toString(contador));//Tamano lista
			for(int j=0;j<Documentos.size();j++){
				
				if((Documentos.get(j).getConfidencialidad()).equals("PRIVADO")){
	
				out.writeUTF(Integer.toString(Documentos.get(j).getIDRegistro()));
				out.writeUTF(Documentos.get(j).getPropietario());
				out.writeUTF(Documentos.get(j).getNombreDoc());
				out.writeUTF(Integer.toString(Documentos.get(j).getSelloTemporal().length));
				out.write(Documentos.get(j).getSelloTemporal());
				
				}
			}
			return;	
		}else{
			out.writeUTF("CERTIFICADO INCORRECTO");
			return;
		}	

	}



    }
    
    public void Recuperar_Documento() throws IOException, CertificateEncodingException, KeyStoreException, Exception {
    	
	int IDRegistro_Cliente=0;
	int long_cert_cliente=0;
	int Existe=0,PosicionDocArray=0;;
	File file_descifrado=null;
	File Documento=null;

	//System.out.println("Llega a recuperar Documento");

	IDRegistro_Cliente=in.readInt();
	//System.out.println(IDRegistro_Cliente);

	for(int i=0;i<Documentos.size();i++){
		if(Documentos.get(i).getIDRegistro()==IDRegistro_Cliente){
			out.writeUTF("DOCUMENTO EXISTE");
			PosicionDocArray=i;
			Existe++;
		}
	}
	
	if(Existe==0){
		out.writeUTF("DOCUMENTO NO EXISTE");
	}
	//System.out.println("Documento existe");

	long_cert_cliente=in.readInt();
	byte[] CertificadoCliente=new byte[long_cert_cliente];
	
	in.read(CertificadoCliente);

	Certificate Certificado_TrustStore = (Servidor.TrustStore).getCertificate("Cliente");//Meter alias del certificado del cliente
	byte[] CertificadoTrust = Certificado_TrustStore.getEncoded();

	if(Arrays.equals(CertificadoCliente,CertificadoTrust)){
		out.writeUTF("ACCESO NO PERMITIDO");
	}else{
		out.writeUTF("ACCESO PERMITIDO");
	}
	
	//byte[] Documento = new byte[Documentos.get(PosicionDocArray).getDocumento().length];
	//Documento=Documentos.get(PosicionDocArray).getDocumento();
	if((Documentos.get(PosicionDocArray).getConfidencialidad().equals("PRIVADO"))){
		file_descifrado=descifradorAlmacen(IDRegistro_Cliente);
	}else{
		file_descifrado= new File(Servidor.path+"Documento"+IDRegistro_Cliente+".txt");
	}
	/////////////////////////////////////////////CIFRADO PGP///////////////////////////////////////////////////
	byte[] byte_leidos= new byte[112];
	int j=0;
	//BufferedInputStream bis = new BufferedInputStream(new FileInputStream("Servidor/Documento_recibido.txt"));
	BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file_descifrado));
	
	//Documento=new File("Servidor/Documento_recibido.txt");
	Documento=file_descifrado;	

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
	
	X509Certificate certificado=(X509Certificate) (Servidor.TrustStore).getCertificate("cliente");
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
	//byte Espacio= (byte) espacio;
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
	file_descifrado.delete();

    }
}
