package br.com.tmsfasdom.assinador;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class Utils {

	public static String retornaDadosCNAB240(byte[] dados) throws Exception {
		
		CMSSignedDataParser sdp = new CMSSignedDataParser(
				new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), dados);
		String retornoCNAB240 = new String(lerInputStreamToByte(sdp.getSignedContent().getContentStream()));
		return retornoCNAB240;
	}

	public static byte[] lerInputStreamToByte(InputStream in) throws Exception {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		int next = in.read();
		while (next > -1) {
			bos.write(next);
			next = in.read();
		}
		bos.flush();
		byte[] result = bos.toByteArray();
		return result;
	}

	public static byte[] converteBase64ParaBinario(String strBase64) {
		byte[] arrayBytes = Base64.getDecoder().decode(strBase64);
		return arrayBytes;
	}

	public static List<String> lerArquivoTxt(String caminhoArquivo) throws IOException {

		File arquivo = new File(caminhoArquivo);
		List<String> dados = Files.readAllLines(arquivo.toPath());
		return dados;
	}

	public static byte[] lerArquivoBin(String caminhoArquivo) throws IOException {

		File arquivo = new File(caminhoArquivo);
		byte[] dados = Files.readAllBytes(arquivo.toPath());
		return dados;
	}

	public static void gravaArquivo(byte[] bytes, String caminho) throws Exception {

		File file = new File(caminho); // Criamos um nome para o arquivo
		BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(file, true)); // Criamos
																								// o
																								// arquivo
		bos.write(bytes); // Gravamos os bytes lá
		bos.close(); // Fechamos o stream.
	}

	public static List<String> removeInicioFimPKCS(List<String> linhas) {

		boolean remove = true;
		List<String> linhasParaRemover = new ArrayList<String>();
		for (String str : linhas) {
			if (str.contains("-----BEGIN PKCS7-----")) {
				remove = false;
				linhasParaRemover.add(str);
			}
			if (remove) {
				linhasParaRemover.add(str);
			}
			if (str.contains("-----END PKCS7-----")) {
				remove = true;
				linhasParaRemover.add(str);
			}

		}
		linhas.removeAll(linhasParaRemover);
		return linhas;
	}

}
