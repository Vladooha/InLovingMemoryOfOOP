import java.awt.List;
import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class LoginServer {
	// Server's info
	static ServerSocket serv;
	static Socket serv_helper;
	final static int PORT = 5676;
	
	// Server's command names
	final static String LOGIN_BY_TOKEN = "logByToken";
	final static String LOGIN = "log";
	final static String REGISTRATION = "reg";
	final static String CHECK = "check";
	final static String FIND = "find";
	
	// Output-command
	final static String BADACTION = "_false";
	final static String NODATA = "_nodata";
	final static String LOGIN_EXISTS = "_logX";
	final static String NO_AUTH = "-noauth";
	
	// User data CONST'S
	final static String USERDATA = "loginData";
	
	// Common const's for client-server
	final static String UID = "-uid";
	final static String EMAIL = "-email ";
    final static String PASS = "-pass ";
    final static String NICK = "-nick ";
    final static String BDAY = "-bDay ";
    final static String BMONTH = "-bMonth ";
    final static String BYEAR = "-bYear ";
    final static String URL = "-url ";
    final static String TOKEN = "-token ";
    
    // Common in-server const's
    final static String TOKEN_TIME = "-token_time ";
    final static int TOKEN_DIFF_TIME_MS = 6000000;
	
	public static void main(String[] args) {
		try {
			// Starting a server
			serv = new ServerSocket(PORT);
			System.out.println("Server started on adress: " + serv.getInetAddress().toString());
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		// Infinitely processing of requests
		for (int i = 0; i < 2; i = i++) {
			try {
				// Accepting a new request
				serv_helper = serv.accept();
				System.out.println("I've got a connection from " + serv.getInetAddress().toString());
			} catch (IOException e1) {
				System.out.println("Can't start up the server");
				if (e1.getMessage() != null) {
					System.out.println(e1.getMessage());
				}
				e1.printStackTrace();
			}
			try {
				// Creating a new processing thread for request
				new Thread(new Runnable() {
					
					abstract class AuthCmd {
						abstract String doCmd(String userData) throws IOException;
					}
					
					@Override
					public void run() {
						try {
							InputStream stream_reader = serv_helper.getInputStream();
							DataInputStream reader = new DataInputStream(stream_reader);
							String userRequestFull = decryptData(reader.readUTF());
							System.out.println("User's request: " + userRequestFull);
							
							String userRequest = userRequestFull.split(":", 2)[0];
							String userData = userRequestFull.split(":", 2)[1];
							DataOutputStream out = new DataOutputStream(serv_helper.getOutputStream());
							
							switch (userRequest) {
								// Commands for all users
								case REGISTRATION:
									System.out.println("Starting reg:");
									registration(userData, out);
									break;
								case LOGIN_BY_TOKEN:
									loginByToken(userData, out);
									break;
								case LOGIN:
									login(userData, out);
									break;
								case CHECK:
									sendData(userData, out);
									break;
								// Commands for authorized users
								case FIND:
									doAuthCmd(userData, out, new FindUser());
									break;
							}
							
							reader.close();
							out.close();
							
						} catch (IOException e) {
							System.out.println("Connection error!");
							if (e.getMessage() != null) {
								System.out.println(e.getMessage());
							}
							e.printStackTrace();
						} catch (Exception e) {
							System.out.println("Can't process the client's request");
							if (e.getMessage() != null) {
								System.out.println(e.getMessage());
							}
							e.printStackTrace();
						}
					}
					
					private String decryptData(String data) {
						return data;
					}
					
					private String encryptData(String data) {
						return data;
					}
					
					private void sendData(String data, DataOutputStream out) throws IOException {
						out.writeUTF(encryptData(data));
						out.flush();
						out.close();
					}
					
					private void sendDataAuth(String data, DataOutputStream out, String id) throws IOException {
						if (!checkTokenTime(id)) {
							String token = makeToken();
							writeToken(id, token);
							data += ":" + TOKEN + token;
						}
						out.writeUTF(encryptData(data));
						out.flush();
						out.close();
					}
					
					private String idByLogin(String login) {
						StringBuffer id = new StringBuffer();
						String zero = "0";
						for (int i = 0; i < login.length(); ++i) {
							String toAppend = String.valueOf((int)login.charAt(i));
							for (int j = toAppend.length(); j < 3; ++j) {
								id.append(zero);
							}
							id.append(toAppend);
						}
						return id.toString();
					}
					
					// Is it need?
					private String loginById(String id) {
						StringBuffer login = new StringBuffer();
						for (int i = 0; i < id.length(); i += 3) {
							login.append((char)Integer.parseInt(id.substring(i, i + 3)));
						}
						return login.toString();
					}
					
					private void doAuthCmd(String userData, DataOutputStream out, AuthCmd cmd) throws IOException {
						String[] userDataParts = userData.split(":", 3);
						String login = userDataParts[0];
						String id = userDataParts[1];
						if (checkAuth(login, id)) {
							userData = userDataParts[2];
							sendDataAuth(cmd.doCmd(userData), out, id);
						} else {
							sendData(NO_AUTH, out);
						}
					}
					
					private void registration(String userData, DataOutputStream out) throws IOException {
						String id;
						StringBuffer writeStream = new StringBuffer();
						File userFile;
						
						System.out.println("registration() got: " + userData);
						
						// Parsing login
						Pattern buffPattern = Pattern.compile(EMAIL + "[a-zA-Z0-9][a-zA-Z0-9_\\.-]{3,15}@[a-zA-Z0-9_\\.-]{1,9}.[a-zA-Z0-9]{2,4}:");
						Matcher buffMatch = buffPattern.matcher(userData);
						if (buffMatch.find()) {
							String userLogin = buffMatch.group(0).substring(7).replaceAll(":", "\r\n");
							writeStream.append(EMAIL + userLogin);
							id = idByLogin(userLogin);
							userFile = new File(USERDATA + "\\" + id + ".txt");
							if (userFile.exists()) {
								System.out.println("File already exists!");
								return;
							}
						} else {
							System.out.println("Not enough data for reg");
							sendData(BADACTION, out);
							return;
						}
							
						// Parsing password
						buffPattern = Pattern.compile(PASS + "[a-zA-Z0-9][a-zA-Z0-9_-]{7,18}:");
						buffMatch = buffPattern.matcher(userData);
						if (buffMatch.find()) {
							writeStream.append(buffMatch.group(0).replaceAll(":", "\r\n"));
						} else {
							System.out.println(PASS + "not found");
							sendData(BADACTION, out);
							return;
						}
						
						// Parsing nick
						buffPattern = Pattern.compile(NICK + "[a-zA-Z0-9][a-zA-Z0-9_\\.-]{3,15}:");
						buffMatch = buffPattern.matcher(userData);
						if (buffMatch.find()) {
							writeStream.append(buffMatch.group(0).replaceAll(":", "\r\n"));
						} else {
							System.out.println(NICK + "not found");
							sendData(BADACTION, out);
							return;
						}
						
						// Parsing birthday
						buffPattern = Pattern.compile(BYEAR + "[0-9]{4,4}:");
						buffMatch = buffPattern.matcher(userData);
						if (buffMatch.find()) {
							// Parsing all data or only year
							writeStream.append(buffMatch.group(0).replaceAll(":", "\r\n"));
							buffPattern = Pattern.compile(BMONTH + "[A-Za-z]{3,3}:");
							Matcher monthMatch = buffPattern.matcher(userData);
							if (monthMatch.find()) {
								buffPattern = Pattern.compile(BDAY + "[0-9]{1,2}:");
								buffMatch = buffPattern.matcher(userData);
								if (buffMatch.find()) {
									writeStream.append(monthMatch.group(0).replaceAll(":", "\r\n"));
									writeStream.append(buffMatch.group(0).replaceAll(":", "\r\n"));
								}
							}
						}
						
						// Creating a new userData file
						try {
							userFile.createNewFile();
						} catch (IOException e) {
							System.out.println("Can't create user's info file");
							if (e.getMessage() != null) {
								System.out.println(e.getMessage());
							}
							e.printStackTrace();
							sendData(BADACTION, out);
							return;
						}
						
						// Writing userData to file
						try {
							BufferedWriter userDataWriter = new BufferedWriter(new FileWriter(userFile));
							userDataWriter.write(writeStream.toString());
							userDataWriter.close();
						} catch (IOException e) {
							System.out.println("Can't get access to user's info file");
							if (e.getMessage() != null) {
								System.out.println(e.getMessage());
							}
							e.printStackTrace();
							sendData(BADACTION, out);
							return;
						}
						
						System.out.println("All's ok!");
						// If all's ok
						sendData(REGISTRATION, out);
						return;
					}
					
					private void loginByToken(String userData, DataOutputStream out) throws IOException {
						String id;
						File userFile;
						
						System.out.println("loginByToken() got: " + userData);
						
						// Parsing login
						Pattern buffPattern = Pattern.compile(EMAIL + "[a-zA-Z0-9][a-zA-Z0-9_\\.-]{3,15}@[a-zA-Z0-9_\\.-]{1,9}.[a-zA-Z0-9]:");
						Matcher buffMatch = buffPattern.matcher(userData);
						if (buffMatch.find()) {
							String userLogin = buffMatch.group(0).substring(7).replaceAll(":", "\r\n");
							id = idByLogin(userLogin);
							// Checking a userData file
							userFile = new File(USERDATA + "\\" + id + ".txt");
							if (!userFile.exists() || !userFile.canRead()) {
								System.out.println("File not exists!");
								sendData(BADACTION, out);
								return;
							}
						} else {
							System.out.println("Not enough data for log in");
							sendData(BADACTION, out);
							return;
						}
						
						// Parsing token
						buffPattern = Pattern.compile(TOKEN + "[^:]*:");
						buffMatch = buffPattern.matcher(userData);
						Scanner userFileReader = new Scanner(userFile);
						String token = "";
						if (buffMatch.find()) {
							token = buffMatch.group(0).substring(TOKEN.length(), buffMatch.group(0).length() - 1);
						}
						userFileReader.close();
						
						// Checking for user's token
						long tokenTime = getTokenTime(id);
						if (checkAuth(id, token)) {
							if (!checkTokenTime(id)) {
								// Rewriting token
								token = makeToken();
								writeToken(id, token);
							}
							sendData(TOKEN + token + ":", out);
						} else {
							sendData(BADACTION, out);
						}
					}
					
					private void login(String userData, DataOutputStream out) throws IOException {
						String id;
						File userFile;
						
						System.out.println("login() got: " + userData);
						
						// Parsing login
						Pattern buffPattern = Pattern.compile(EMAIL + "[a-zA-Z0-9][a-zA-Z0-9_\\.-]{3,15}@[a-zA-Z0-9_\\.-]{1,9}.[a-zA-Z0-9]:");
						Matcher buffMatch = buffPattern.matcher(userData);
						if (buffMatch.find()) {
							String userLogin = buffMatch.group(0).substring(7).replaceAll(":", "\r\n");
							id = idByLogin(userLogin);
							// Checking a userData file
							userFile = new File(USERDATA + "\\" + id + ".txt");
							if (!userFile.exists() || !userFile.canRead()) {
								System.out.println("File not exists!");
								sendData(BADACTION, out);
								return;
							}
						} else {
							System.out.println("Not enough data for log in");
							sendData(BADACTION, out);
							return;
						}
							
						// Parsing password
						buffPattern = Pattern.compile(PASS + "[a-zA-Z0-9][a-zA-Z0-9_-]{7,18}:");
						buffMatch = buffPattern.matcher(userData);
						Scanner userFileReader = new Scanner(userFile);
						String passBuff = "";
						if (buffMatch.find()) {
							passBuff = buffMatch.group(0).replaceAll(":", "\r\n");
						}
						boolean access = false;
						while (userFileReader.hasNextLine()) {
							if ((userFileReader.nextLine() + "\r\n").equals(passBuff)) {
								access = true;
							}
						}
						userFileReader.close();
						
						if (access) {
							System.out.println("Logged in! " + userData);
							try {
								// Checking a token with refreshing if it's old
								String token = makeToken();
								if (writeToken(id, token)) {
									sendData(userData + TOKEN + token, out);
								} else {
									sendData(userData, out);
								}
							} catch (Exception e) {
								System.out.println("Token writing error!");
								System.out.println(e.getMessage());
								sendData(BADACTION, out);
							}
							return;
						} else {
							System.out.println(PASS + "is wrong " + passBuff);
							sendData(BADACTION, out);
							return;
						}
					}
					
					final class FindUser extends AuthCmd {
						@Override
						String doCmd(String userData) throws IOException {
							StringBuilder result = new StringBuilder();
							
							// Parsing login
							Pattern buffPattern = Pattern.compile(EMAIL + "[a-zA-Z0-9][a-zA-Z0-9_\\.-]{3,15}@[a-zA-Z0-9_\\.-]{1,9}.[a-zA-Z0-9]:");
							Matcher buffMatch = buffPattern.matcher(userData);
							if (buffMatch.find()) {
								String userLogin = buffMatch.group(0).substring(7).replaceAll(":", "\r\n");
								// Checking a userData file
								File userFile = new File(USERDATA + "\\" + idByLogin(userLogin) + ".txt");
								if (!userFile.exists() || !userFile.canRead()) {
									return "0";
								}
								
								result.append("1:" + EMAIL + userLogin + ":");
								
								// Parsing nick
								String buff = parseFromFile(NICK + "[a-zA-Z0-9][a-zA-Z0-9_\\.-]{3,15}", userFile);
								if (buff != null) {
									result.append(buff);
								} else {
									return "0";
								}
								
								// Parsing birthday
								buff = parseFromFile(BYEAR + "[0-9]{4,4}", userFile);
								if (buff != null) {
									result.append(buff);
								}
								
								buff = parseFromFile(BMONTH + "[A-Za-z]{3,3}", userFile);
								if (buff != null) {
									result.append(buff);
								}
								
								buff = parseFromFile(BDAY + "[0-9]{1,2}", userFile);
								if (buff != null) {
									result.append(buff);
								}
								
								return result.toString();
							} else {
								return "0";
							}
						}			
					}
					
					private String parseFromFile(String regex, File file) throws IOException {
						Scanner userFileReader = new Scanner(file);
						Pattern buffPattern = Pattern.compile(regex);
						Matcher buffMatch = null;
						while (userFileReader.hasNextLine()) {
							buffMatch = buffPattern.matcher(userFileReader.nextLine());
							if (buffMatch.find()) {
								return buffMatch.group(0) + ":";
							}
						}
						return null;
					}
					
					private String makeToken() {
						int MIN_TOKEN_LENGTH = 15;
						int MAX_TOKEN_LENGTH = 20;
						int BEGIN_ENCR_SYMB = 65;
						int END_ENCR_SYMB = 90;
						
						Random rand = new Random(System.currentTimeMillis());
						int len = MIN_TOKEN_LENGTH + rand.nextInt(MAX_TOKEN_LENGTH - MIN_TOKEN_LENGTH + 1);
						String token = "";
						for (int i = 0; i < len; ++i) {
							token += (char)(BEGIN_ENCR_SYMB + rand.nextInt(END_ENCR_SYMB - BEGIN_ENCR_SYMB + 1));
						}
						return token;
					}
					
					private String getToken(String id) throws IOException {
						File userFile = new File(USERDATA + "\\" + id + ".txt");
						Scanner userFileScanner = new Scanner(userFile);
						Pattern pattTokenTime = Pattern.compile(TOKEN + "[^:]*\r\n");
						Matcher matchBuff;
						
						while (userFileScanner.hasNextLine()) {
							String strBuff = userFileScanner.nextLine();
							matchBuff = pattTokenTime.matcher(strBuff + "\r\n");
							if (matchBuff.find()) {
								userFileScanner.close();
								return strBuff.substring(TOKEN.length(), strBuff.length());
							}
						}
						userFileScanner.close();
						return BADACTION;
					}
					
					private long getTokenTime(String id) throws IOException {
						File userFile = new File(USERDATA + "\\" + id + ".txt");
						Scanner userFileScanner = new Scanner(userFile);
						Pattern pattTokenTime = Pattern.compile(TOKEN_TIME + "[0-9]*\r\n");
						Matcher matchBuff;
							
						System.out.println("Start lookin for a token!");
						while (userFileScanner.hasNextLine()) {
							String strBuff = userFileScanner.nextLine();
							matchBuff = pattTokenTime.matcher(strBuff + "\r\n");
							if (matchBuff.find()) {
								userFileScanner.close();
								return Long.parseLong(strBuff.substring(TOKEN_TIME.length(), strBuff.length()));
							}
						}
						userFileScanner.close();
						return -1;
					}
					
					private boolean writeToken(String id, String token) throws IOException {
						File userFile = new File(USERDATA + "\\" + id + ".txt");
						long tokenTime = getTokenTime(id);
						Date date = new Date();
						if (date.getTime() - tokenTime > TOKEN_DIFF_TIME_MS) {
							System.out.println("I'm makin a token!");
							// User already have overdue token
							BufferedReader userFileReader = new BufferedReader(new FileReader(userFile));
							Stream<String> userFileLines = userFileReader.lines();
							String lineBuff, writeBuff = "";
							Iterator<String> iter = userFileLines.iterator();
							while (iter.hasNext()) {
								lineBuff = iter.next();
								if (!lineBuff.contains(TOKEN) && !lineBuff.contains(TOKEN_TIME)) {
									writeBuff += lineBuff + "\r\n";
								}
							}
							writeBuff += TOKEN + token + "\r\n";
							writeBuff += TOKEN_TIME + String.valueOf(date.getTime()) + "\r\n";
							userFileReader.close();
							BufferedWriter userFileWriter = new BufferedWriter(new FileWriter(userFile));
							userFileWriter.write(writeBuff);
							userFileWriter.flush();
							userFileWriter.close();
							return true;
						} else {
							return false;
						}
					}
					
					private boolean checkAuth(String id, String token) {
						String currToken;
						try {
							currToken = getToken(id);
						} catch (IOException e) {
							if (e.getMessage() != null) {
								System.out.println(e.getMessage());
							}
							e.printStackTrace();
							return false;
						}
						return currToken.equals(token);
					}
					
					private boolean checkTokenTime(String id) throws IOException {
						long tokenTime = getTokenTime(id);
						if (tokenTime == -1 || new Date().getTime() - tokenTime > TOKEN_DIFF_TIME_MS) {
							return false;
						} else {
							return true;
						} 
					}

				}).start();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		try {
			serv.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
