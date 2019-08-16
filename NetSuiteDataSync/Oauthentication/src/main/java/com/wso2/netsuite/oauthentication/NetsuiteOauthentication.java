package com.wso2.netsuite.oauthentication;

import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;

import org.apache.synapse.MessageContext; 
import org.apache.synapse.mediators.AbstractMediator;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;


import org.apache.synapse.config.Entry;



public class NetsuiteOauthentication extends AbstractMediator { 
	
	
	private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	static String OAuth ="null";
	private String variableOAuth;
	private String SCRIPT_DEPLOYMENT_ID;
	private String SCRIPT_ID;
	
     
	public String encodeuri(String datatoencode){
		String encodedData = null;
		try {
			encodedData = URLEncoder.encode(datatoencode, "UTF-8")
			        .replaceAll("\\+", "%20")
			        .replaceAll("\\%21", "!")
			        .replaceAll("\\%27", "'")
			        .replaceAll("\\%28", "(")
			        .replaceAll("\\%29", ")")
			        .replaceAll("\\%7E", "~");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return encodedData;
	}
	
	public String randomAlphaNumeric(int count) {
		StringBuilder builder = new StringBuilder();
		while (count-- != 0) {
			int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
			builder.append(ALPHA_NUMERIC_STRING.charAt(character));
		}
		return builder.toString();
	}
	
	private String computeSignature(String baseString, String keyString) throws GeneralSecurityException, UnsupportedEncodingException {

		final String EMPTY_STRING = "";
		final String CARRIAGE_RETURN = "\r\n";
		final String UTF8 = "UTF-8";
		String HMAC_SHA1 = "HmacSHA1";
		
		SecretKeySpec key = new SecretKeySpec(keyString.getBytes(UTF8), HMAC_SHA1);
		Mac mac = Mac.getInstance(HMAC_SHA1);
		mac.init(key);
		byte[] bytes = mac.doFinal(baseString.getBytes(UTF8));
		String base= bytesToBase64String(bytes).replace(CARRIAGE_RETURN, EMPTY_STRING);
		return URLEncoder.encode(base, "UTF-8");
		
	}

	private String bytesToBase64String(byte[] bytes) {
		return Base64Encoder.getInstance().encode(bytes);
	}

	public boolean mediate(MessageContext context) { 
		try {
			String BASE_URL =  null;	
			String HTTP_METHOD =  null;	
			String TOKEN_ID = null;	
			String TOKEN_SECRET = null;	
			String CONSUMER_KEY = null;	
			String CONSUMER_SECRET = null;	
			String SIGNATURE_METHOD = null;	
			String OAUTH_NONCE = randomAlphaNumeric(20);
			String TIME_STAMP = String.valueOf(System.currentTimeMillis() / 1000);
			String OAUTH_VERSION = null;
			setScript_deployment_id( (String) context.getProperty("script_deployment_id"));
			setScript_id( (String) context.getProperty("script_id"));
			SCRIPT_DEPLOYMENT_ID = getScript_deployment_id();
			SCRIPT_ID = getScript_id();
			String REALM= null;	
			String LOCAL_ENTRY_ID = "NetsuiteConfig";
			String LOCAL_ENTRY_VALUE = null;
			Document xmldoc = null;
			
				
			Entry localEntryObj = (Entry) context.getConfiguration().getLocalRegistry().get(LOCAL_ENTRY_ID);
            if (localEntryObj != null) {
            	LOCAL_ENTRY_VALUE = localEntryObj.getValue().toString();
            	xmldoc = loadXMLFromString(LOCAL_ENTRY_VALUE);
            	BASE_URL= xmldoc.getElementsByTagName("baseurl").item(0).getTextContent();
            	HTTP_METHOD = xmldoc.getElementsByTagName("httpmethod").item(0).getTextContent();
            	TOKEN_ID = xmldoc.getElementsByTagName("tokenid").item(0).getTextContent();
            	TOKEN_SECRET = xmldoc.getElementsByTagName("tokensecret").item(0).getTextContent();
            	CONSUMER_KEY = xmldoc.getElementsByTagName("consumerkey").item(0).getTextContent();
            	CONSUMER_SECRET = xmldoc.getElementsByTagName("consumersecret").item(0).getTextContent();
            	SIGNATURE_METHOD = xmldoc.getElementsByTagName("signaturemethod").item(0).getTextContent();
            	OAUTH_VERSION = xmldoc.getElementsByTagName("oauthversion").item(0).getTextContent();
            	REALM = xmldoc.getElementsByTagName("realm").item(0).getTextContent();
            }
            else{
            	System.out.println("[ERROR] Cannot locate the local entry values...");
            }
           			
			String data = "";
			data = data + "deploy=" + SCRIPT_DEPLOYMENT_ID + "&";
			data = data + "oauth_consumer_key=" + CONSUMER_KEY + "&";
			data = data + "oauth_nonce=" + OAUTH_NONCE + "&";
			data = data + "oauth_signature_method=" + SIGNATURE_METHOD +"&";
			data = data + "oauth_timestamp=" + TIME_STAMP + "&";
			data = data + "oauth_token=" + TOKEN_ID + "&";
			data = data + "oauth_version=" + OAUTH_VERSION + "&";
			data = data + "script=" + SCRIPT_ID;
			String encodedData = encode(data);
			
			System.out.println("This is the Encoded Data.... : "+ encodedData);
			
			String completeData = HTTP_METHOD + "&" + encode(BASE_URL) + "&"+ encodedData;
			
			System.out.println("This is the completeData.... : "+ completeData);
			
			String key ="";
			key = encode(CONSUMER_SECRET) + "&" + encode(TOKEN_SECRET); 
			
			System.out.println("This is the constructed key.... : "+ key);
			String signature= computeSignature(completeData,key);
			
				
				OAuth = "OAuth realm=\"" + REALM + "\",";
				OAuth = OAuth + "oauth_consumer_key=\""+ CONSUMER_KEY + "\",";
				OAuth = OAuth + "oauth_token=\"" + TOKEN_ID + "\",";
				OAuth = OAuth + "oauth_signature_method=\"HMAC-SHA1\",";
				OAuth = OAuth + "oauth_timestamp=\"" + TIME_STAMP + "\",";
				OAuth = OAuth + "oauth_nonce=\"" + OAUTH_NONCE + "\",";
				OAuth = OAuth + "oauth_version=\"" + "1.0" + "\",";
				OAuth = OAuth + "oauth_signature=\"" + signature + "\"";
				
				setVariableOAuth(OAuth);
				
				context.setProperty("OAuthVal",OAuth);
				return true;
				
			} catch (UnsupportedEncodingException | GeneralSecurityException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		return true;
	}
	public String getVariableOAuth() {
		return variableOAuth;
	}
	public void setVariableOAuth(String variableOAuth) {
		this.variableOAuth = variableOAuth;
	}
	public String getScript_deployment_id() {
		return SCRIPT_DEPLOYMENT_ID;
	}
	public void setScript_deployment_id(String script_deployment_id) {
		this.SCRIPT_DEPLOYMENT_ID = script_deployment_id;
	}
	public String getScript_id() {
		return SCRIPT_ID;
	}
	public void setScript_id(String script_id) {
		this.SCRIPT_ID = script_id;
	}
		
	/**
	    * percentage encoding
	    *
	    * @return A encoded string
	 */
	 private String encode(String value) {  
	     String encoded = "";  
	     try {  
	       encoded = URLEncoder.encode(value, "UTF-8");  
	     } catch (Exception e) {  
	       e.printStackTrace();  
	     }  
	      String sb = "";  
	     char focus;  
	     for (int i = 0; i < encoded.length(); i++) {  
	       focus = encoded.charAt(i);  
	       if (focus == '*') {  
	         sb += "%2A"; 
	       } else if (focus == '+') {  
	         sb += "%20";
	       } else if (focus == '%' && i + 1 < encoded.length()  
	           && encoded.charAt(i + 1) == '7' && encoded.charAt(i + 2) == 'E') {  
	         sb += '~';
	         i += 2;  
	       } else {  
	         sb += focus;
	       }  
	     }  
	     return sb.toString();  
	   }  
	 
	 /**
	    * load xml from string
	    *
	    * @return A encoded string
	 */
	 public static Document loadXMLFromString(String xml) throws Exception
	 {
	     DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	     DocumentBuilder builder = factory.newDocumentBuilder();
	     InputSource is = new InputSource(new StringReader(xml));
	     return builder.parse(is);
	 }
			
}



