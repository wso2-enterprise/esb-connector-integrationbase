package com.wso2.netsuite.oauthentication;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.synapse.MessageContext; 
import org.apache.synapse.mediators.AbstractMediator;


public class NetsuiteOauthentication extends AbstractMediator { 
	
	
	private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	static String OAuth ="null";
	private String variableOAuth;
	
     
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
			// TODO Auto-generated catch block
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

		  
		    
		    //mac.init(secretKey);
		    //byte[] text = baseString.getBytes();
		
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
		
		
		
		 	//Mac mac = Mac.getInstance("HMAC-SHA1");
		 	//SecretKey secretKey = null;
		    //byte[] keyBytes = keyString.getBytes();
		    //secretKey = new SecretKeySpec(keyBytes, "HmacSHA1");
		 	
	        //mac.init(new SecretKeySpec(Base64.decodeBase64(keyString).getBytes("UTF-8"), "HMAC-SHA1"));
	        //String sig = new String(Base64.encodeBase64(mac.doFinal(baseString.getBytes())));
	        //return URLEncoder.encode(sig, "UTF-8");
		
		
	  
	   // return new String(Base64.encodeBase64String(text));
	}

	private String bytesToBase64String(byte[] bytes) {
		return Base64Encoder.getInstance().encode(bytes);
	}

	public boolean mediate(MessageContext context) { 
		try {
			String BASE_URL = "xxxxxxxxxxxxxxxxxxxx";
			String HTTP_METHOD = "GET";
			String TOKEN_ID = "xxxxxxxxxxxxxxxxxxxx";
			String TOKEN_SECRET = "xxxxxxxxxxxxxxxxxxxx";
			String CONSUMER_KEY = "xxxxxxxxxxxxxxxxxxxx";
			String CONSUMER_SECRET = "xxxxxxxxxxxxxxxxxxxx";
			String SIGNATURE_METHOD =  "HMAC-SHA1";
			String OAUTH_NONCE = randomAlphaNumeric(20);
			String TIME_STAMP = String.valueOf(System.currentTimeMillis() / 1000);
			String OAUTH_VERSION = "1.0";
			String SCRIPT_DEPLOYMENT_ID = "1";
			String REALM="xxxxxxxxxxxxxxxxxxxx";	
			String NETSUITE_ACCOUNT_ID = "xxxxxxxxxxxxxxxxxxxx";
			String SCRIPT_ID ="325";
			
			
			
			/**$baseString = oauth_get_sbs($httpMethod, $url, array('oauth_consumer_key' => $consumerKey,
					 'oauth_nonce' => $nonce,
					 'oauth_signature_method' => $signatureMethod,
					 'oauth_timestamp' => $timestamp,
					 'oauth_token' => $tokenKey,
					 'oauth_version' => $version));*/
		
			
			
			String data = "";
			data = data + "deploy=" + SCRIPT_DEPLOYMENT_ID + "&";
			data = data + "oauth_consumer_key=" + CONSUMER_KEY + "&";
			data = data + "oauth_nonce=" + OAUTH_NONCE + "&";
			data = data + "oauth_signature_method=" + "HMAC-SHA1" +"&";
			data = data + "oauth_timestamp=" + TIME_STAMP + "&";
			data = data + "oauth_token=" + TOKEN_ID + "&";
			data = data + "oauth_version=" + OAUTH_VERSION + "&";
			data = data + "script=" + SCRIPT_ID;
			String encodedData = encode(data);
			
			System.out.println("This is the Encoded Data.... : "+ encodedData);
			
			String completeData = HTTP_METHOD + "&" + encode(BASE_URL) + "&"+ encodedData;
			
			System.out.println("This is the completeData.... : "+ completeData);
			
			//String hmacsha1Data = CryptoJS.HmacSHA1(completeData, CONSUMER_SECRET + "&" + TOKEN_SECRET);
			//String base64EncodedData = Base64.stringify(hmacsha1Data);
			//String oauth_signature = encodeURIComponent(base64EncodedData);
			
			
			
			
			
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
			}
		return true;
	}
	public String getVariableOAuth() {
		return variableOAuth;
	}
	public void setVariableOAuth(String variableOAuth) {
		this.variableOAuth = variableOAuth;
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
			
}



