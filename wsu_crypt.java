// Christopher Nelson
// christopher.w.nelso@wsu.edu
// CS 427
// Program 1


import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.Scanner;
import java.math.BigInteger;

public class wsu_crypt {
	static int[][] ftable = {
		{0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3, 0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9},
		{0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28},
		{0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53},
		{0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2},
		{0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8},
		{0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90},
		{0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76},
		{0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d},
		{0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18},
		{0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4},
		{0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40},
		{0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5},
		{0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2},
		{0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8},
		{0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac},
		{0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46}};
	static String bk;
	static String subkeys[][] = new String[16][12];
	
	// function from stackoverflow to convert string to binary
	public static String AsciiToBinary(String asciiString, int length){
		byte[] bytes = asciiString.getBytes();
		StringBuilder binary = new StringBuilder();
		for (byte b : bytes){
			int val = b;
			for (int i = 0; i < 8; i++){
				binary.append((val & 128) == 0 ? 0 : 1);
				val <<= 1;
			}
		}
		String bin = binary.toString();
		while(bin.length() < length*8){
			bin = "0"+bin;
		}
		return bin;
	}
	
	// convert hex to binary
	public static String HexToBinary(String hexString,int length){
		String hex = new BigInteger(hexString, 16).toString(2);
		while(hex.length() < length*4)
			hex = "0"+hex;
		return hex;
	}
	
	// convert hex to binary
	public static String HexToBinarySmaller(String hexString){
		String hex = new BigInteger(hexString, 16).toString(2);
		while(hex.length() < 8)
			hex = "0"+hex;
		return hex;
	}
	
	// convert binary to hex
	public static String BinaryToHex(String binaryString){
		return Integer.toHexString(Integer.parseInt(binaryString, 2));
	}
	
	
	// XOR two strings
	private static String XOR(String w, String k){
		StringBuilder xor_string = new StringBuilder();
		for(int i = 0; i < w.length() && i < k.length(); i++)
			xor_string.append(Integer.toString((int)(w.charAt(i) ^ k.charAt(i))));	
		return xor_string.toString();
	}
	
	// input whitening step
	private static String[] input_whitening (String binary_text, String binary_key){
		String R[] = new String[4];
				
		// split into 4 words/keys
		String w[] = binary_text.split("(?<=\\G.{16})");
		String k[] = binary_key.split("(?<=\\G.{16})");

		// XOR words/keys
		for(int i=0; i < 4; i++)
			R[i] = XOR(w[i],k[i]);
		return R;
	}
	
	// output whitening step
	private static String output_whitening (String []y){
		String C[] = new String[4];
		String k[] = bk.split("(?<=\\G.{16})");
		for(int i = 0; i < 4; i++){
			C[i]=XOR(y[i],k[i]);
		}
		String s = C[0]+C[1]+C[2]+C[3];
		BigInteger b = new BigInteger(s,2);
		String finalS = b.toString(16);
		while (finalS.length() < 16)
			finalS = "0"+finalS;
		return finalS;
	}	
	
	// output whitening step for decrypt
		private static String output_whitening_decrypt (String []y){
			String C[] = new String[4];
			String k[] = bk.split("(?<=\\G.{16})");
			for(int i = 0; i < 4; i++){
				C[i]=XOR(y[i],k[i]);

			}
			String s = C[0]+C[1]+C[2]+C[3];;
			
			String output = "";
			for(int i = 0; i <= s.length() - 8; i+=8)
			{
			    int w = Integer.parseInt(s.substring(i, i+8), 2);
			    output += (char) w;
			}   		
			return output;
		}	
	
	// Function F()
	private static String[] F_Function(String R0, String R1, int round){
		//create sub keys
		subkeys[round][0] = Key_Schedule(4*round);
		subkeys[round][1] = Key_Schedule(4*round+1);
		subkeys[round][2] = Key_Schedule(4*round+2);
		subkeys[round][3] = Key_Schedule(4*round+3);
		subkeys[round][4] = Key_Schedule(4*round);
		subkeys[round][5] = Key_Schedule(4*round+1);
		subkeys[round][6] = Key_Schedule(4*round+2);
		subkeys[round][7] = Key_Schedule(4*round+3);
		subkeys[round][8] = Key_Schedule(4*round);
		subkeys[round][9] = Key_Schedule(4*round+1);
		subkeys[round][10] = Key_Schedule(4*round+2);
		subkeys[round][11] = Key_Schedule(4*round+3);
		
		// compute T0,T1
		String T0 = G_Function(R0,round,subkeys[round][0],subkeys[round][1],subkeys[round][2],subkeys[round][3]);
		String T1 = G_Function(R1,round,subkeys[round][4],subkeys[round][5],subkeys[round][6],subkeys[round][7]);
		String F[] = new String[2];
		
		int T0_Dec = Integer.parseInt(T0,2);
		int T1_Dec = Integer.parseInt(T1,2);
		
		// compute F0
		int F0Sum = T0_Dec + (2*T1_Dec) + Integer.parseInt((subkeys[round][8]+subkeys[round][9]),2);
		F0Sum = (int) (F0Sum % (Math.pow(2, 16)));
		F[0] = Integer.toBinaryString(F0Sum);
		while(F[0].length() < 16)
			F[0] = "0"+F[0];

		// compute F1
		int F1Sum = (2*T0_Dec) + T1_Dec + Integer.parseInt((subkeys[round][10]+subkeys[round][11]),2);
		F1Sum = (int) (F1Sum % (Math.pow(2, 16)));
		F[1] = Integer.toBinaryString(F1Sum);
		while(F[1].length() < 16)
			F[1] = "0"+F[1];

		return F;
	}
	
	private static String[] F_Function_Decrypt(String R0, String R1, int round){		
		// compute T0,T1
		String T0 = G_Function(R0,round,subkeys[15-round][0],subkeys[15-round][1],subkeys[15-round][2],subkeys[15-round][3]);
		String T1 = G_Function(R1,round,subkeys[15-round][4],subkeys[15-round][5],subkeys[15-round][6],subkeys[15-round][7]);
		String F[] = new String[2];
		
		int T0_Dec = Integer.parseInt(T0,2);
		int T1_Dec = Integer.parseInt(T1,2);
		
		// compute F0
		int F0Sum = T0_Dec + (2*T1_Dec) + Integer.parseInt((subkeys[15-round][8]+subkeys[15-round][9]),2);
		F0Sum = (int) (F0Sum % (Math.pow(2, 16)));
		F[0] = Integer.toBinaryString(F0Sum);
		while(F[0].length() < 16)
			F[0] = "0"+F[0];

		// compute F1
		int F1Sum = (2*T0_Dec) + T1_Dec + Integer.parseInt((subkeys[15-round][10]+subkeys[15-round][11]),2);
		F1Sum = (int) (F1Sum % (Math.pow(2, 16)));
		F[1] = Integer.toBinaryString(F1Sum);
		while(F[1].length() < 16)
			F[1] = "0"+F[1];

		return F;
	}
	
	// get value from FTable
	private static String GetFTable (String x,String y){
		int row = Integer.valueOf(x, 16);
		int col = Integer.valueOf(y, 16);
		return Integer.toHexString(ftable[row][col]);
	}
	
	// G permutation
	private static String G_Function(String w, int round, String GK0, String GK1, String GK2, String GK3){
		String G[] = new String[6];
		String Temp0,Temp1;
		
		G[0] = w.substring(0, 8);
		G[1] = w.substring(8, 16);
		Temp0 = BinaryToHex((XOR(G[1],GK0).substring(0, 4)));
		Temp1 = BinaryToHex((XOR(G[1],GK0).substring(4, 8)));
		G[2] = XOR(HexToBinarySmaller(GetFTable(Temp0,Temp1)),G[0]);
		Temp0 = BinaryToHex((XOR(G[2],GK1).substring(0, 4)));
		Temp1 = BinaryToHex((XOR(G[2],GK1).substring(4, 8)));
		G[3] = XOR(HexToBinarySmaller(GetFTable(Temp0,Temp1)),G[1]);
		Temp0 = BinaryToHex((XOR(G[3],GK2).substring(0, 4)));
		Temp1 = BinaryToHex((XOR(G[3],GK2).substring(4, 8)));
		G[4] = XOR(HexToBinarySmaller(GetFTable(Temp0,Temp1)),G[2]);
		Temp0 = BinaryToHex((XOR(G[4],GK3).substring(0, 4)));
		Temp1 = BinaryToHex((XOR(G[4],GK3).substring(4, 8)));
		G[5] = XOR(HexToBinarySmaller(GetFTable(Temp0,Temp1)),G[3]);
		return G[4]+G[5];
	}
	
	// Key_Scehdule for encryption
	private static String Key_Schedule(int x){
		bk = bk.substring(1,64)+bk.substring(0,1);
		String K[] = bk.split("(?<=\\G.{8})");
		return K[x%8];
	}
	// Key_Scehdule for encryption
	private static String Key_Schedule_Decrypt(int x){
		String K[] = bk.split("(?<=\\G.{8})");
		String z=K[x%8];
		bk = bk.substring(63,64)+bk.substring(0,63);
		return z;
	}
	
	// main method
	public static void main(String[] args) throws IOException {
		String plain_text_file = new Scanner(new File("plaintext.txt")).useDelimiter("\\Z").next();
		String key_file = new Scanner(new File("key.txt")).useDelimiter("\\Z").next();
		// 64 bit key
		String binary_key = HexToBinary(key_file,key_file.length());
		
		while (binary_key.length() < 64){
			binary_key = binary_key.concat("0");
		}	
		
		bk = binary_key;
		PrintWriter writer = new PrintWriter("cyphertext.txt", "UTF-8");
		
		// ascii characters are 8 bits long, so split into substrings of length 8 for a total of 64 bits.
		String plain_text_strings[] = plain_text_file.split("(?<=\\G.{8})");
		for (int i = 0; i < plain_text_strings.length; i++){
			// convert to binary	
			String binary_plain_text = AsciiToBinary(plain_text_strings[i],plain_text_strings[i].length());
			
			// 64 bit blocks
			while (binary_plain_text.length() < 64){
				binary_plain_text = binary_plain_text.concat("0");
			}	
			String R[] = input_whitening(binary_plain_text,bk);
			// encryption
			for (int round = 0; round < 16; round++){
				String[] F = F_Function(R[0], R[1], round);
				String TempR0 = XOR(R[2],F[0]);
				TempR0 = TempR0.substring(15,16)+TempR0.substring(0,15);
				String TempR1 = R[3].substring(1, 16)+R[3].substring(0,1);
				TempR1 = XOR(TempR1,F[1]);
				R[2] = R[0];
				R[3] = R[1];
				R[0] = TempR0;
				R[1] = TempR1;
			}
			String y[] = new String[4];
			y[0] = R[2];
			y[1] = R[3];
			y[2] = R[0];
			y[3] = R[1];
			// output encrypted file
			writer.print(output_whitening(y));			
		}
		writer.close();
		
		// decryption
		String cypher_text_file = new Scanner(new File("cyphertext.txt")).useDelimiter("\\Z").next();
		String cypher_text_strings[] = cypher_text_file.split("(?<=\\G.{16})");
		bk = binary_key;
		
		PrintWriter writer2 = new PrintWriter("decyphertext.txt", "UTF-8");
		
		for (int i = 0; i < cypher_text_strings.length; i++){
			String binary_cypher_text = HexToBinary(cypher_text_strings[i],cypher_text_strings[i].length());
			while (binary_cypher_text.length() < 64){
				binary_cypher_text = binary_cypher_text.concat("0");
			}
			String Rdecrypt[] = input_whitening(binary_cypher_text,bk);
		
			for (int round = 0; round < 16; round++){
				String[] F = F_Function_Decrypt(Rdecrypt[0], Rdecrypt[1], round);
				String TempR0 = Rdecrypt[2].substring(1,16)+Rdecrypt[2].substring(0,1);
				TempR0 = XOR(TempR0,F[0]);
				String TempR1 = XOR(Rdecrypt[3],F[1]);
				TempR1 = TempR1.substring(15,16)+TempR1.substring(0,15);
				Rdecrypt[2] = Rdecrypt[0];
				Rdecrypt[3] = Rdecrypt[1];
				Rdecrypt[0] = TempR0;
				Rdecrypt[1] = TempR1;
			}
			String w[] = new String[4];
			w[0] = Rdecrypt[2];
			w[1] = Rdecrypt[3];
			w[2] = Rdecrypt[0];
			w[3] = Rdecrypt[1];	
			writer2.print(output_whitening_decrypt(w));
		}
		writer2.close();
	}
}
