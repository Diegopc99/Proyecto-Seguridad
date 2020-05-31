//package Ej;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.regex.Pattern;

public class Documento {
	
	//private static final long serialVersionUID = 1L;
	public String nombreDoc, confidencialidad, propietario;
	public byte[] documento, firmaDoc, firmaReg, selloTemporal, cert_cliente;                         
    public int idRegistro;                                                             
 
    public Documento() {
    }

    public Documento(String nombreDoc, byte[] firmaDoc, int idRegistro, byte[] selloTemporal, byte[] firmaReg, byte[] cert_c, String confidencialidad, String propietario) {
        try {
            File archivo = new File(nombreDoc);                           
            this.documento = new byte[(int) archivo.length()];                                 
            int bytes = 0;
            int nbyte = 0;

            BufferedInputStream lectura = new BufferedInputStream(new FileInputStream(archivo));   

            while ((bytes = lectura.read()) != -1) {
                documento[nbyte] = (byte) bytes;
                nbyte++;                                                                   
            }
            lectura.close();
            
            String[] dominio_split = nombreDoc.split(Pattern.quote("\\"));
            
            this.nombreDoc = dominio_split[dominio_split.length-1];
            this.firmaDoc = firmaDoc;
            this.idRegistro = idRegistro;
            this.selloTemporal = selloTemporal;
            this.firmaReg = firmaReg;
            this.cert_cliente = cert_c;
            this.confidencialidad = confidencialidad;
            this.propietario = propietario;
            
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

	public String getNombreDoc() {
		return nombreDoc;
	}

	public void setNombreDoc(String nombreDoc) {
		this.nombreDoc = nombreDoc;
	}

	public String getPropietario() {
		return propietario;
	}

	public void setPropietario(String propietario) {
		this.propietario = propietario;
	}

	public String getConfidencialidad() {
		return confidencialidad;
	}

	public void setConfidencialidad(String confidencialidad) {
		this.confidencialidad = confidencialidad;
	}

	public byte[] getDocumento() {
		return documento;
	}

	public void setDocumento(byte[] documento) {
		this.documento = documento;
	}

	public byte[] getFirmaDoc() {
		return firmaDoc;
	}

	public void setFirmaDoc(byte[] firmaDoc) {
		this.firmaDoc = firmaDoc;
	}

	public byte[] getFirmaReg() {
		return firmaReg;
	}

	public void setFirmaReg(byte[] firmaReg) {
		this.firmaReg = firmaReg;
	}

	public byte[] getSelloTemporal() {
		return selloTemporal;
	}

	public void setSelloTemporal(byte[] selloTemporal) {
		this.selloTemporal = selloTemporal;
	}

	public byte[] getCert_cliente() {
		return cert_cliente;
	}

	public void setCert_cliente(byte[] cert_cliente) {
		this.cert_cliente = cert_cliente;
	}

	public int getIDRegistro() {
		return idRegistro;
	}

	public void setIdRegistro(int idRegistro) {
		this.idRegistro = idRegistro;
	}


}
