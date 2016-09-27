package basicauthwebserver;

import java.io.*;
import java.net.*;
import java.util.*;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class BasicAuthWebServer {

  private static final int PORT = 8080;

  private static ServerSocket dServerSocket;

  public BasicAuthWebServer() throws Exception {
    dServerSocket = new ServerSocket(PORT);
  }

  public void run() throws Exception {
    while(true) {
      Socket s = dServerSocket.accept();
      processRequest(s);
    }
  }

  private String checkPath(String pathname) throws Exception {
    File target = new File(pathname);
    File cwd = new File(System.getProperty("user.dir"));
    String s1 = target.getCanonicalPath();
    String s2 = cwd.getCanonicalPath();

    if(!s1.startsWith(s2)) {
      throw new Exception();
    } else {
      return s1;
    }
  }

  public void processRequest(Socket s) throws Exception {
    BufferedReader br =
      new BufferedReader(
        new InputStreamReader(s.getInputStream()));

    OutputStreamWriter osw =
      new OutputStreamWriter(s.getOutputStream());

    String request = br.readLine();

    String command = null;
    String pathname = null;

    try {
      StringTokenizer st =
        new StringTokenizer(request, " ");
      command = st.nextToken();
      pathname = st.nextToken();
    } catch (Exception e) {
      osw.write("HTTP/1.0 400 Bad Request\n\n");
      osw.close();
      return;
    }

    if (command.equals("GET")) {
      Credentials c = getAuthorization(br);
      if ((c != null) && (MiniPasswordManager.checkPassword(
                                            c.getUsername(),
                                            c.getPassword()))) {
        serveFile(osw, pathname);
      } else {
        osw.write("HTTP/1.0 401 Unauthorized\n");
        osw.write("WWW-Authenticate: Basic realm=\"BasicAuthWebServer\"\n\n");
      }
    } else {
      osw.write("HTTP/1.0 501 Not Implemented\n\n");
    }
    osw.close();
  }

  private Credentials getAuthorization(BufferedReader br) {
    try {
      String header = null;
      while(!(header = br.readLine()).equals("")) {
        System.err.println(header);
        if(header.startsWith("Authorization")) {
          StringTokenizer st = new StringTokenizer(header, " ");
          st.nextToken(); // skip "Authorization"
          st.nextToken(); // skip "Basic"
          return new Credentials(st.nextToken());
        }
      }
    } catch (Exception e) {
      // No other condition
    }
    return null;
  }

  public void serveFile(OutputStreamWriter osw,
                        String pathname) throws Exception {
    FileReader fr = null;
    int c = -1;
    StringBuffer sb = new StringBuffer();

    if (pathname.charAt(0) == '/') {
      pathname = pathname.substring(1);
    }

    if (pathname.equals("")) {
      pathname = "index.html";
    }

    try {
      fr = new FileReader(checkPath(pathname));
      c = fr.read();
    } catch (Exception e) {
      osw.write("HTTP/1.0 404 Not Found\n\n");
      return;
    }

    osw.write("HTTP/1.0 200 OK\n\n");
    while(c != -1) {
      sb.append((char)c);
      c = fr.read();
    }
    osw.write(sb.toString());
  }

  public static void main (String args[]) throws Exception {
    if(args.length == 1) {
      MiniPasswordManager.init(args[0]);

      BasicAuthWebServer baws = new BasicAuthWebServer();
      baws.run();
    } else {
      System.err.println("Usage: java BasicAuthWebServer <pwdfile>");
    }
  }

}

class Credentials {
  private String dUsername;
  private String dPassword;

  public Credentials(String authString) throws Exception {
    authString = new String((new sun.misc.BASE64Decoder().decodeBuffer(authString)));
    StringTokenizer st = new StringTokenizer(authString, ":");
    dUsername = st.nextToken();
    dPassword = st.nextToken();
  }

  public String getUsername() {
    return dUsername;
  }

  public String getPassword() {
    return dPassword;
  }
}
