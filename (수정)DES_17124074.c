#include <stdio.h>
#include <string.h>
void P2B( char* inp_plain, unsigned long long* plainBlock); // 16���� �Է¹��� ���� 2���� �迭�� ��ȯ�ϴ� �Լ�
void Cipher(unsigned long long plainBlock, unsigned long long* RoundKeys, unsigned long long* cipherBlock); // plainBlock�� RoundKey�迭�� �޾Ƽ� ��ȣȭ�Ͽ� cipherBlock�� ����� �Լ�
void permute(int size1, int size2, unsigned long long baseBlock, unsigned long long* finalBlock, char* Table); // ġȯ�Լ� 
void split(int size1, int size2, unsigned long long inBlock, unsigned int* leftBlock, unsigned int* rightBlock); // size1��ŭ�� ��Ʈ�� size2������ ���� �и��ϴ� split�Լ�
void mixer(unsigned int* leftBlock, unsigned int* rightBlock, unsigned long long RoundKey); // left��ϰ� right���, ����Ű�� �޾Ƽ� right��ϰ� ���� Ű�� function(�����Լ�)�� ���� left��ϰ� ��Ÿ�� ������ ���ϴ� �Լ�
void copy(int size, unsigned int* baseBlock, unsigned int* finalBlock); // ���ڸ��� �޾Ƽ� size��ŭ �����ϴ� �Լ�
void function(unsigned int inBlock, unsigned long long roundKey, unsigned long long* outBlock); // right��ϰ� ���� Ű���޾Ƽ� Ȯ�� P�ڽ� , s�ڽ� , �ܼ�s�ڽ��� ���� ������� ���� ���� �Լ�
void exclusiveOr(int size, unsigned long long baseBlock, unsigned long long roundKey, unsigned long long* finalBlcok); // ��Ÿ�� ����(XOR)�� ���ϴ� �Լ�
void substitute(unsigned long long inBlock, unsigned int* outBlock, unsigned char table[8][4][16]); // s�ڽ����̺��� �޾� s�ڽ��� ���ϴ� �Լ�
void shiftLeft(unsigned int *block, char numOfShifts); // ����� ���庰 ��ȯ �̵� ���� ���� ��Ʈ����Ʈ ������ �ϴ� �Լ�
void Key_generator(unsigned long long keyWithParities, unsigned long long* roundKeys, int ShiftTable[16]); // ����ڿ��Լ� ���� Ű�� ���ڷ� �ְ� �� ���庰 ����Ű�� ������ �Լ�
void swapper(unsigned int* leftBlock, unsigned int* rightBlock); // ���忡�� mixer�� ������ left��ϰ� right����� ���� �ٲ��ִ� �Լ�
void Combine(int size1, int size2, unsigned int leftBlock, unsigned int rightBlock, unsigned long long* outBlock); // �� 2���� �迭�� �޾Ƽ� �ϳ��� ������� �ٽ� �����ִ� �Լ�
void Hexa(unsigned long long text,int size); // 2������ 16������ ��ȯ�ϴ� �Լ�


unsigned long long inBlock; // �ʱ�ġȯ�� �� �����ϴ� �迭
unsigned int leftBlock = 0; //�� ���忡�� �и��� left����� �����ϴ� �迭
unsigned int rightBlock = 0; //�� ���忡�� �и��� right����� �����ϴ� �迭

//char inp_plain[16];
//char inp_key[16];
char inp_plain[16] = {'1','2','3','4','5','6','A','B','C','D','1','3','2','5','3','6'};// ����ڰ� �Է��� �� ���� �����ϴ� �迭
char inp_key[16] = { 'A','A','B','B','0','9','1','8','2','7','3','6','C','C','D','D' };// ����ڰ� �Է��� Ű ���� �����ϴ� �迭
unsigned long long cipherBlock = 0; // ��ȣ���� �����ϴ� 64��Ʈ 
unsigned long long plainBlock = 0; // 16������ ���� ���� 64��Ʈ�� �����ϴ� ����
unsigned long long keyBlock = 0; // 16������ ���� Ű�� 64��Ʈ�� �����ϴ� �迭 ( �и�Ƽ��Ʈ�� ������ �ִ� 64 ��Ʈ )
unsigned long long RoundKeys[16]; // 64��Ʈ Ű�� �޾Ƽ� �� ���庰 48��Ʈ�� �� 16���� ����Ű�� ������ �迭 ( 48 ��Ʈ ������ ���� 64��Ʈ long long �迭�� ���� ) 
char InitialPermutationTable[64] = { 58, 50, 42, 34, 26, 18, 10, 2, // �ʱ�ġȯ ���̺�
			60, 52, 44, 36, 28, 20, 12, 4,
			62, 54, 46, 38, 30, 22, 14, 6,
			64, 56, 48, 40, 32, 24, 16, 8,
			57, 49, 41, 33, 25, 17, 9, 1,
			59, 51, 43, 35, 27, 19, 11, 3,
			61, 53, 45, 37, 29, 21, 13, 5,
			63, 55, 47, 39, 31, 23, 15, 7 };
char Final_permutation[64] = { 40, 8, 48, 16, 56, 24, 64, 32, //����ġȯ ���̺�
		 39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41, 9, 49, 17, 57, 25 };
char Expansion_PermutationTable[48] = { 32,  1,  2,  3,  4,  5, //Ȯ�� P�ڽ� ġȯ���̺�
			  4,  5,  6,  7,  8,  9,
			  8,  9, 10, 11, 12, 13,
			 12, 13, 14, 15, 16, 17,
			 16, 17, 18, 19, 20, 21,
			 20, 21, 22, 23, 24, 25,
			 24, 25, 26, 27, 28, 29,
			 28, 29, 30, 31, 32, 1 };
char Straight_PermutationTable[32] = { 16,  7, 20, 21, 29, 12, 28, 17, //�ܼ� P�ڽ� ġȯ���̺�
				   1, 15, 23, 26,  5, 18, 31, 10,
			  2,  8, 24, 14, 32, 27,  3,  9,
			 19, 13, 30,  6, 22, 11,  4, 25 };
char S_PermutationTable[8][4][16] = { //S�ڽ� ���̺� 4/16���� �̷���� �� 8���� s�ڽ�

	//S-�ڽ�1
	{{14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7},
	 { 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8},
	 { 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0},
	 {15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13}  },

	 //S-�ڽ�2
	  {{15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10},
	   { 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5},
	   { 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15},
	   {13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9}  },

	   //S-�ڽ�3
		{{10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8},
		 {13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1},
		 {13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7},
		 { 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12}  },

		  
		 //S-�ڽ�4
		  {{ 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15},
		   {13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9},
		   {10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4},
		   { 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14}  },

		   //S-�ڽ�5
			{{ 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9},
			 {14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6},
			 { 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14},
			 {11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3}  },


			 //S-�ڽ�6
			  {{12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11},
			   {10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8},
			   { 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6},
			   { 4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13}  },


			   //S-�ڽ�7
				{{ 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1},
				 {13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6},
				 { 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2},
				 { 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12}  },


				 //S-�ڽ�8
				 {{13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7},
				  { 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2},
				  { 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8},
				  { 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11}  }
};
char ParityDropTable[56] = { 57,49,41,33,25,17,9,1,  //����ڰ� �Է��� Ű���� Parity��Ʈ�� �����ϱ� ���� ParityTable
							58,50,42,34,26,18,10,2,
							59,51,43,35,27,19,11,3,
							60,52,44,36,63,55,47,39,
							31,23,15,7,62,54,46,38,
							30,22,14,6,61,53,45,37,
							29,21,13,5,28,20,12,4 };
char KeyCompressionTable[48] = { 14 ,17 ,11 ,24 ,1 ,5 ,3 ,28, // �� ���� Ű�� �̴� KeyCompression���̺�
								15 ,6 ,21 ,10 ,23 ,19 ,12 ,4,
								26 ,8 ,16 ,7 ,27 ,20 ,13 ,2,
								41 ,52 ,31 ,37 ,47 ,55 ,30 ,40,
								51 ,45 ,33 ,48 ,44 ,49 ,39 ,56 ,
								34 ,53 ,46 ,42 ,50 ,36 ,29 ,32 };
int ShiftTable[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 }; // ��ȯ�̵� ��Ʈ���� ��Ÿ���� ���̺�
void main() {
	printf("17124074 ������\n");
	printf("16���� �� 16�ڸ� �Է� :");
	gets(inp_plain); // �� �Է¹޾� ����
	printf("\n");
	P2B(inp_plain, &plainBlock); // �Է¹��� 16���� ���� 64��Ʈ 2������ ��ȯ
	
	printf("\n16���� Ű 16�ڸ� �Է� : ");
	gets(inp_key);
	
	printf("\n\n");
	printf("����            Left                 Right                  ���� Key\n");
	P2B(inp_key, &keyBlock); // �Է¹��� 16���� Ű�� 64��Ʈ 2������ ��ȯ�Ͽ� keyBlock�� ����
	Key_generator(keyBlock, RoundKeys, ShiftTable);  //Ű ���� �Լ�
	
	
	Cipher(plainBlock, RoundKeys, &cipherBlock); //��ȣȭ �Լ�
	
	printf("CipherText ��� :");
	Hexa(cipherBlock,64); //��ȣ�� ���
	printf("\n\n");
	
}

void P2B(char* inp_plain, unsigned long long* plainBlock) { // 16���� �迭�� 2���� �迭�� ��ȯ�ϴ� �Լ�
	char Num; 
	int i = 0; // char �迭�� ���� ���� ������ �ε���
	
	unsigned long long num64 = 0; //memcpy�� ��Ʈ�� �����ϱ� ���� 8��Ʈ �迭, 8��Ʈ�� 2���� 16���� �Է�
	while (i != 16) {
		if (inp_plain[i] < 65 && inp_plain[i] >47)
		{
			Num = inp_plain[i] - 48; // ������ ��� 48�����Ͽ� ���ڿ� �����ϴ� �ƽ�Ű�ڵ�� ��ȯ
		}
		else {
			Num = inp_plain[i] - 55; //  A~F�� ��� 55�����Ͽ� ���ڿ� �����ϴ� �ƽ�Ű �ڵ�� ��ȯ
		}

		num64 = num64 | Num;

		if (i != 15) {
			num64 = num64 << 4;
		};
		i++;
	}
	memcpy(plainBlock, &num64, 8);
}

void Cipher(unsigned long long plainBlock, unsigned long long* RoundKeys, unsigned long long* cipherBlock) { // DES��ȣȭ �Լ�
	int round = 0;
	unsigned long long outBlock;
	permute(64, 64, plainBlock, &inBlock, InitialPermutationTable);// ���� �ʱ�ġȯ
	split(64, 32, inBlock, &leftBlock, &rightBlock); //ġȯ�� ���� left��ϰ� right������� �и�
	while (round != 16) { //�� 16���� ����
		
		mixer(&leftBlock, &rightBlock, RoundKeys[round]); //���� ����

		if (round != 15) { // ������ ����� swapper�� �������� ����
			swapper(&leftBlock, &rightBlock);// left��ϰ� right��� ���� ��ü
		}
		printf("Round %02d         ", round + 1);
		printf("leftBlock:");
		Hexa(leftBlock,32); // ���
		printf("    rightBlock:");
		Hexa(rightBlock,32); // ���
		printf("    roundKey:");
		Hexa(RoundKeys[round],48); // ���
		printf("\n\n");

		round++;
	}
	Combine(32, 64, leftBlock, rightBlock, &outBlock); // �и��Ǿ��ִ� left��� right����� ����
	printf("After combination :");
	Hexa(outBlock,64); // ���� ġȯ�� ���� 16���� ���
	printf("\n");
	permute(64, 64, outBlock, cipherBlock, Final_permutation); // ����ġȯ���̺� ���� ���� ġȯ
}

void permute(int size1, int size2, unsigned long long baseBlock, unsigned long long* finalBlock, char* Table){ // ġȯ �Լ�(Table�� �޾� base�� ���� ����� ġȯǥ�� ���� ġȯ�Ͽ� final��� �迭�� ����
	int t;
	for (int i = 0; i < size2; i++) {
		t = Table[i] - 1;
		long long value = (baseBlock >> (size1 -1 - t)) & 0x1; // ���� i��° (���ʿ�������) ��Ʈ�� 1���� 0���� Ž��

		*finalBlock = (value << (size2 - i - 1)) ^ *finalBlock; // i���� ��Ʈ�� ���̺� ���� ��ġ ���ġ 
	}
}
void split(int size1, int size2, unsigned long long inBlock, unsigned int* leftBlock, unsigned int* rightBlock) { //inBlock ����� left��ϰ� right������� �и��ϴ� split �Լ�
	int index = 64 - size1; // 56 ��Ʈ�� ���ڷ� ���� ��� ���
	unsigned int right = 0;

	unsigned long long bitXor = inBlock >> size2;

	*leftBlock = (unsigned int)bitXor;

	right = (unsigned int) inBlock; // 32��Ʈ �и�
	right = right << (index / 2); // 32��Ʈ�� �ʿ���� �պκ� ��Ʈ ���� ( Ű ������ 28��Ʈ�� ��ȿ�� ����ϱ� ������ �� 4��Ʈ ���� )
	right = right >> (index / 2);
	*rightBlock = right;
} 

void Combine(int size1, int size2, unsigned int leftBlock, unsigned int rightBlock, unsigned long long* outBlock) { // ���ڷ� �޴� left��ϰ� right����� �����Ͽ� outBlock�� �����ϴ� �Լ�
	unsigned long long left = leftBlock; // 32��Ʈ unsigned int�� leftBlock�� 64��Ʈ ������ �Է�
	left = left << size1; // ���� size1��Ʈ�� �ִ� leftBlock�� ����Ʈ�����Ͽ� �ڸ� ���� ( �� ���� 64��Ʈ ���ս� 32��Ʈ ���� , 56��Ʈ ���ս� 28��Ʈ ����)

	*outBlock = rightBlock; //rightBlock outBlock�� ���� 
	*outBlock = *outBlock | left; // �ڸ����� �� leftBlock �� | ����
}
void mixer(unsigned int* leftBlock, unsigned int* rightBlock, unsigned long long RoundKey) { // ���� �����ϴ� mixer �Լ� 
	unsigned int T1 = 0, T4 = 0;
	unsigned long long T2 = 0, T3 = 0;
	copy(32, rightBlock, &T1); //right��� ���� T1�� �ӽ� ����
	function(T1, RoundKey, &T2); //T1�� ����Ű�� �����Լ��� �־ ���� �� �� T2�� ����
	exclusiveOr(32, *leftBlock, T2, &T3);//left��ϰ� �����Լ��� ��ģ T2�� ��Ÿ�� �������� ������ �Ͽ� T3����
	T4 = (unsigned int)T3; // ��Ÿ�� ���� ���������� long long ���� ����� ���� int�� ����ȯ
	copy(32, &T4, leftBlock); // T4���� left��Ͽ� ����
} 
void copy(int size, unsigned int* baseBlock, unsigned int* finalBlock) { // ���� �Լ�
	int cpSize = size / 8;
	memcpy(finalBlock, baseBlock, cpSize); // baseBlock �Ű������� ���� ���� cpsize ����Ʈ��ŭ ��Ʈ�����ϴ� �Լ�
}
void function(unsigned int inBlock, unsigned long long roundKey, unsigned long long* outBlock) { // ���� �Լ�
	unsigned long long T1 = 0, T2 = 0; 
	unsigned int T3 = 0;
	permute(32, 48, inBlock, &T1, Expansion_PermutationTable); //  ���� Ű�� 48��Ʈ �̹Ƿ� ������ ���� right����� Ȯ��P�ڽ��� ���� 48��Ʈ�� Ȯ��
	exclusiveOr(48,T1,roundKey,&T2); // ����Ű�� Ȯ��� ��Ʈ�� ��Ÿ�� ������
	substitute(T2, &T3, S_PermutationTable); // s�ڽ��� ���ؼ� �ٽ� 48��Ʈ ����� 32��Ʈ�� ���
	permute(32, 32, T3, outBlock, Straight_PermutationTable); // �ܼ� P �ڽ��� ���
}
void exclusiveOr(int size, unsigned long long baseBlock, unsigned long long roundKey, unsigned long long* finalBlock) { //��Ÿ�� ���� XOR
	*finalBlock = baseBlock ^ roundKey; // ��Ÿ�� ���� ����
}
void substitute(unsigned long long inBlock, unsigned int* outBlock, unsigned char table[8][4][16]) { //s�ڽ�
	unsigned char row, col, value;
	for (int i = 0; i < 8; i++) {
		row = 2 * ((inBlock >> (47 - i * 6)) & 0x1) + ((inBlock >> (42 - i * 6)) & 0x1); // 1��°�� 6��° �� S�ڽ��� ������ �� 48��Ʈ���� 6��Ʈ ������ ��� s�ڽ� �� ����
		col = 8 * ((inBlock >> (46 - i * 6)) & 0x1) + 4 * ((inBlock >> (45 - i * 6)) & 0x1) + 2 * ((inBlock >> (44 - i * 6)) & 0x1) + ((inBlock >> (43 - i * 6)) & 0x1); // ������ 2,3,4,5 ��° ��Ʈ�� ����
		
		value = table[i][row][col]; // s�ڽ��� �� ����

		*outBlock = *outBlock | value;  // s�ڽ� ���̺��� ���� 4��Ʈ ����
		if (i != 7) {
			*outBlock = *outBlock << 4; // ���� ��Ʈ�� �������� 4��Ʈ �о�� ���� ���� 4��Ʈ�� ���� Ȯ��
		}
	}
}
void swapper(unsigned int* leftBlock, unsigned int* rightBlock) { //  left ��ϰ� right����� ����ġȯ�ϴ� �Լ�
	unsigned int T;
	copy(32, leftBlock, &T); //  T�� left��� �ӽ� ����
	copy(32, rightBlock, leftBlock); // right����� left��Ͽ� ����
	copy(32, &T, rightBlock); // T�� right��Ͽ� ����
}
void Key_generator(unsigned long long keyWithParities, unsigned long long * roundKeys, int ShiftTable[16]) { // Ű ���� �Լ� 
	unsigned long long cipherKey = 0 , preRoundKey = 0;
	unsigned int leftKey = 0, rightKey = 0;
	
	permute(64, 56, keyWithParities, &cipherKey, ParityDropTable); // �и�Ƽ ��Ʈ�� �����ϱ� ���� �и�Ƽ ���̺� ���� ġȯ�Ͽ� �Է¹��� 64��Ʈ Ű�� 56��Ʈ�� ���
	
	split(56, 28, cipherKey, &leftKey, &rightKey); // 56��Ʈ Ű�� 28��Ʈ�� �и�
	for (int round = 0; round < 16; round++) { // �� 16����ġ Ű ���� ����
		shiftLeft(&leftKey, ShiftTable[round]); // ��ȯ�̵� ��Ʈ���� ���� ��������Ʈ ����
		shiftLeft(&rightKey, ShiftTable[round]); // ��ȯ�̵� ��Ʈ��(ShiftTable) �� ���� ��������Ʈ
		Combine(28, 56, leftKey, rightKey, &preRoundKey); // 56��Ʈ�� ����
		permute(56, 48, preRoundKey, &roundKeys[round], KeyCompressionTable); // keyCompressionTable�� ���� 48��Ʈ�� �ɷ����� �� ���� ���� Ű�� ���� 
	}
}
void shiftLeft(unsigned int* block, char numOfShifts) { //  �½���Ʈ ���� �Լ�
	unsigned char T;
	for (int i = 0; i < numOfShifts; i++) { // shift ���̺��� ���� ���� �ݺ�
		T = *block >> 27; // �� ���� ù ��Ʈ ����
		*block = *block << 1; // �������� ����Ʈ
		*block = *block | T; // �и��� ��Ʈ�� ��Ʈ �������� �־���
		*block = *block & 0x0FFFFFFF; // �������� 4��Ʈ ���� ( ���� 28 ��Ʈ �̿ܿ��� ��� x)
	}
}


void Hexa(unsigned long long Block,int size) // 2������ 16������ ��ȯ�ϴ� �Լ�
{
	if (size != 32)
	{
		printf("%012llX", Block); // 16������ ��� ( 48,64 ��Ʈ�� �� %llX )
	}
	else {
		printf("%08X", (int)Block); // 16���� ��� ( 32 ��Ʈ�� �� %X );
	}	
}