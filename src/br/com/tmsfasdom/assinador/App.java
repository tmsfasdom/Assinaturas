package br.com.tmsfasdom.assinador;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.crypto.Cipher;

import java.security.cert.X509Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class App {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		String caminho = "D:/Projetos/Java/Assinador/src/main/resources/files/remessa2.txt";
		String caminhoBinario = "D:/Projetos/Java/Assinador/src/main/resources/files/remessa2.bin";
		List<String> dadosLidos = Utils.lerArquivoTxt(caminho);
		Utils.removeInicioFimPKCS(dadosLidos);
		for (String str : dadosLidos) {
			Utils.gravaArquivo(Utils.converteBase64ParaBinario(str), caminhoBinario);
		}
		// ExibeCertificados(Utils.lerArquivoBin(caminhoBinario));

		System.out.println("Finalizado com sucesso");
	}

	private static void ExibeCertificados(byte[] dados) throws Exception {

		Security.addProvider(new BouncyCastleProvider());
		CMSSignedDataParser sp = new CMSSignedDataParser(
				new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), dados);
		sp.getSignedContent().drain();

		Store certStore = sp.getCertificates();
		SignerInformationStore signers = sp.getSignerInfos();

		Collection c = signers.getSigners();
		Iterator it = c.iterator();

		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			System.out.println("Digest = " + new String(signer.getContentDigest()));
			Collection certCollection = certStore.getMatches(signer.getSID());
			Iterator certIt = certCollection.iterator();

			X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
			X509Certificate certificado = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);
			PublicKey chavepublica = certificado.getPublicKey();
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			
			byte[] hashsha1 = md.digest();
			Signature clientSig = Signature.getInstance("RSA");
			clientSig.initVerify(certificado);
			clientSig.update(hashsha1);

			Cipher rsaCipher = null;
			rsaCipher = Cipher.getInstance("RSA");
			rsaCipher.init(Cipher.DECRYPT_MODE, chavepublica);
			byte[] hashOriginal = rsaCipher.doFinal(signer.getSignature());
			System.out.println("Hash Original = " + new String(hashOriginal));
			System.out.println("Hash Novo = " + new String(hashsha1));

			if (clientSig.verify(signer.getSignature())) {
				System.out.println("Mensagem assinada corretamente");
			} else {
				System.out.println("Mensagem não assinada corretamente");
			}

			System.out.println("verify returns: "
					+ signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)));
			System.out.println(cert.getSubject());

		}

	}

}
