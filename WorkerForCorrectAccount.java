package kontachomika;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPConnection;
import javax.xml.soap.SOAPConnectionFactory;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
class WorkerForCorrectAccount
  implements Runnable
{
  private final String login;
  private final String password;
  SOAPConnectionFactory soapConnectionFactory;
  SOAPConnection soapConnection;
  
  public WorkerForCorrectAccount(String login, String password)
  {
    this.login = login;
    this.password = password;
  }

  public void run()
  {
    int counter = 0;
    
    while (login != null)
    {
      try
      {
        init();
        try
        {
          Thread.sleep(30000L);
        }
        catch (Exception ex) {}
        
        LoginResult lr;
        do
        {
          lr = sendLoginRequest(login, password, soapConnection);
          
          if (lr.Error)
          {
            System.out.println("Nieudana proba nawiazania polaczenia z serwerem");
            Thread.sleep(5000L);
          }
          
        } while (lr.Error);
        
        if (lr.Error)
        {
          counter++;
          System.out.println("Permission error: Nieudana proba zalogowania na konto kontrolne.");
          if (counter == 3)
          {
            System.out.println("Nieudana proba nawiazania polaczenia z serwerem");
          }
          
        }
        else
        {
          counter = 0;
          System.out.println("Udana proba zalogowania na konto kontrolne.");
          
        }
      }
      catch (Exception ex) {
        Logger.getLogger(WorkerForCorrectAccount.class.getName()).log(Level.SEVERE, null, ex);
      }
    }
  }
  
  private void init() {
    try {
      soapConnectionFactory = SOAPConnectionFactory.newInstance();
      soapConnection = soapConnectionFactory.createConnection();
    } catch (SOAPException|UnsupportedOperationException ex) {
      Logger.getLogger(Worker.class.getName()).log(Level.SEVERE, null, ex);
    }
  }
  
  private void OnFault(LoginResult lr)
  {
    System.out.println("Odpowiedz dla nieudanej proby:\n\n" + "\n\nException dla nieudanej proby:\n\n");
  }
  
  private String getPasswordHash(String password) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(password.getBytes());
    
    byte[] byteData = md.digest();
    
    StringBuilder hexString = new StringBuilder();
    for (int i = 0; i < byteData.length; i++) {
      String hex = Integer.toHexString(0xFF & byteData[i]);
      if (hex.length() == 1) {
        hexString.append('0');
      }
      hexString.append(hex);
    }
    
    return hexString.toString();
  }
  
  private LoginResult sendLoginRequest(String login, String password, SOAPConnection soapConnection)
  {
    System.out.println("Proba zalogowania na konto kontrolne...");
    
    LoginResult lr = new LoginResult();
    boolean Error = false;
    String Token = "";
    String exception = "";
    String Response = "";
    
    try
    {
      String url = "http://box.chomikuj.pl/services/ChomikBoxService.svc";
      SOAPMessage soapResponse = soapConnection.call(createLoginSOAPRequest(login, password), url);
      
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      soapResponse.writeTo(bout);
      Response = bout.toString("UTF-8");
      
      String status = getTagValue("a:status", "", soapResponse);
      Boolean result = Boolean.valueOf(status.toLowerCase().equals("ok"));
     Boolean permissionError = status.toLowerCase().equals("permissionerror");
      
      if (result.booleanValue()) {
        String token = getTagValue("a:token", "", soapResponse);
        Token = token;
      }
    }
    catch (UnsupportedOperationException ex)
    {
      Error = true;
      exception = ex.getMessage();
    }
    catch (Exception ex) {
      Error = true;
      exception = ex.getMessage();
    }
    
    return lr;
  }
  
  private String getTagValue(String tagName, String att, SOAPMessage soapResponse) {
    try {
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      soapResponse.writeTo(bout);
      String str = bout.toString("UTF-8");
      
      Pattern pattern = Pattern.compile("<" + tagName + att + ">(.+?)</" + tagName + ">");
      Matcher matcher = pattern.matcher(str);
      if (matcher.find()) {
        return matcher.group(1);
      }
    }
    catch (SOAPException|IOException ex) {}
    

    return "";
  }
  
  private SOAPMessage createLoginSOAPRequest(String login, String password) throws Exception {
    MessageFactory messageFactory = MessageFactory.newInstance();
    SOAPMessage soapMessage = messageFactory.createMessage();
    SOAPPart soapPart = soapMessage.getSOAPPart();
 
    SOAPEnvelope envelope = soapPart.getEnvelope();

    SOAPBody soapBody = envelope.getBody();
    
    SOAPElement authElement = soapBody.addChildElement("Auth", "", "http://chomikuj.pl/");
    SOAPElement nameElement = authElement.addChildElement("name");
    nameElement.addTextNode(login);
    SOAPElement passElement = authElement.addChildElement("passHash");
    passElement.addTextNode(getPasswordHash(password));
    SOAPElement verElement = authElement.addChildElement("ver");
    verElement.addTextNode("4");
    SOAPElement clientElement = authElement.addChildElement("client");
    SOAPElement clientNameElement = clientElement.addChildElement("name");
    clientNameElement.addTextNode("chomikbox");
    SOAPElement clientVersionElement = clientElement.addChildElement("version");
    clientVersionElement.addTextNode("2.0.4.3");
    
    MimeHeaders headers = soapMessage.getMimeHeaders();
    headers.addHeader("SOAPAction", "http://chomikuj.pl/IChomikBoxService/Auth");
    headers.addHeader("Content-Type", "text/xml;charset=utf-8");
    headers.addHeader("User-Agent", "Mozilla/5.0");
    
    soapMessage.saveChanges();
    
    return soapMessage;
  }
}
