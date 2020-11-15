#include <stdio.h>

void P2B( char* inp_plain, unsigned char * plainBlock); // 16진수 입력받은 평문을 2진수 배열로 변환하는 함수
void Cipher(unsigned char plainBlock[64], unsigned char RoundKeys[16][48], unsigned char cipherBlock[64]); // plainBlock과 RoundKey배열을 받아서 암호화하여 cipherBlock을 만드는 함수
void permute(int size1, int size2, unsigned char* baseBlock, unsigned char* finalBlock, char* Table); // 치환함수 
void split(int size1, int size2, unsigned char* inBlock, unsigned char* leftBlock, unsigned char* rightBlock); // size1만큼의 비트를 size2단위로 절반 분리하는 split함수
void mixer(unsigned char* leftBlock, unsigned char* rightBlock, unsigned char* RoundKey); // left블록과 right블록, 라운드키를 받아서 right블록과 라운드 키를 function(라운드함수)한 값을 left블록과 배타적 논리합을 취하는 함수
void copy(int size, unsigned char* baseBlock, unsigned char* finalBlock); // 인자를을 받아서 size만큼 복사하는 함수
void function(unsigned char* inBlock, unsigned char* roundKey, unsigned char* outBlock); // right블록과 라운드 키를받아서 확장 P박스 , s박스 , 단순s박스를 취해 결과값을 내는 라운드 함수
void exclusiveOr(int size, unsigned char* baseBlock, unsigned char* roundKey, unsigned char* finalBlcok); // 배타적 논리합(XOR)를 취하는 함수
void substitute(unsigned char* inBlock, unsigned char* outBlock, unsigned char table[8][4][16]); // s박스테이블을 받아 s박스를 취하는 함수
void shiftLeft(unsigned char* block, char numOfShifts); // 블록을 라운드별 순환 이동 값에 따라 비트쉬프트 연산을 하는 함수
void Key_generator(unsigned char* keyWithParities, unsigned char roundKeys[16][48], int ShiftTable[16]); // 사용자에게서 받은 키를 인자로 넣고 각 라운드별 라운드키를 만들어내는 함수
void swapper(unsigned char* leftBlock, unsigned char* rightBlock); // 라운드에서 mixer가 끝난후 left블록과 right블록을 서로 바꿔주는 함수
void Combine(int size1, int size2, unsigned char* leftBlock, unsigned char* rightBlock, unsigned char* outBlock); // 두 2진수 배열을 받아서 하나의 블록으로 다시 합쳐주는 함수
void Hexa(unsigned char* text,int size); // 2진수를 16진수로 변환하는 함수


unsigned char inBlock[64]; // 초기치환된 평문 저장하는 배열
unsigned char leftBlock[32]; //각 라운드에서 분리된 left블록을 저장하는 배열
unsigned char rightBlock[32]; //각 라운드에서 분리된 right블록을 저장하는 배열

char inp_plain[16];
char inp_key[16];
//char inp_plain[16] = {'1','2','3','4','5','6','A','B','C','D','1','3','2','5','3','6'};// 사용자가 입력한 평문 값을 저장하는 배열
//char inp_key[16] = { 'A','A','B','B','0','9','1','8','2','7','3','6','C','C','D','D' };// 사용자가 입력한 키 값을 저장하는 배열
unsigned char keyBlock[64]; // 16진수로 받은 키를 2진수로 변환하여 저장하는 배열
unsigned char cipherBlock[64]; // 암호화를 거친 후 2진수 암호문을 저장할 배열
unsigned char plainBlock[64]; // 평문을 2진수로 변환하여 저장하는 배열
unsigned char RoundKeys[16][48]; // 64비트 키를 받아서 각 라운드별 48비트씩 총 16개의 라운드키를 저장할 배열
char InitialPermutationTable[64] = { 58, 50, 42, 34, 26, 18, 10, 2, // 초기치환 테이블
			60, 52, 44, 36, 28, 20, 12, 4,
			62, 54, 46, 38, 30, 22, 14, 6,
			64, 56, 48, 40, 32, 24, 16, 8,
			57, 49, 41, 33, 25, 17, 9, 1,
			59, 51, 43, 35, 27, 19, 11, 3,
			61, 53, 45, 37, 29, 21, 13, 5,
			63, 55, 47, 39, 31, 23, 15, 7 };
char Final_permutation[64] = { 40, 8, 48, 16, 56, 24, 64, 32, //최종치환 테이블
		 39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41, 9, 49, 17, 57, 25 };
char Expansion_PermutationTable[48] = { 32,  1,  2,  3,  4,  5, //확장 P박스 치환테이블
			  4,  5,  6,  7,  8,  9,
			  8,  9, 10, 11, 12, 13,
			 12, 13, 14, 15, 16, 17,
			 16, 17, 18, 19, 20, 21,
			 20, 21, 22, 23, 24, 25,
			 24, 25, 26, 27, 28, 29,
			 28, 29, 30, 31, 32, 1 };
char Straight_PermutationTable[32] = { 16,  7, 20, 21, 29, 12, 28, 17, //단순 P박스 치환테이블
				   1, 15, 23, 26,  5, 18, 31, 10,
			  2,  8, 24, 14, 32, 27,  3,  9,
			 19, 13, 30,  6, 22, 11,  4, 25 };
char S_PermutationTable[8][4][16] = { //S박스 테이블 4/16으로 이루어진 총 8개의 s박스

	//S-박스1
	{{14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7},
	 { 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8},
	 { 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0},
	 {15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13}  },

	 //S-박스2
	  {{15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10},
	   { 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5},
	   { 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15},
	   {13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9}  },

	   //S-박스3
		{{10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8},
		 {13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1},
		 {13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7},
		 { 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12}  },

		  
		 //S-박스4
		  {{ 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15},
		   {13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9},
		   {10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4},
		   { 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14}  },

		   //S-박스5
			{{ 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9},
			 {14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6},
			 { 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14},
			 {11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3}  },


			 //S-박스6
			  {{12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11},
			   {10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8},
			   { 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6},
			   { 4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13}  },


			   //S-박스7
				{{ 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1},
				 {13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6},
				 { 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2},
				 { 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12}  },


				 //S-박스8
				 {{13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7},
				  { 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2},
				  { 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8},
				  { 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11}  }
};
char ParityDropTable[56] = { 57,49,41,33,25,17,9,1,  //사용자가 입력한 키에서 Parity비트를 제거하기 위한 ParityTable
							58,50,42,34,26,18,10,2,
							59,51,43,35,27,19,11,3,
							60,52,44,36,63,55,47,39,
							31,23,15,7,62,54,46,38,
							30,22,14,6,61,53,45,37,
							29,21,13,5,28,20,12,4 };
char KeyCompressionTable[48] = { 14 ,17 ,11 ,24 ,1 ,5 ,3 ,28, // 각 라운드 키를 뽑는 KeyCompression테이블
								15 ,6 ,21 ,10 ,23 ,19 ,12 ,4,
								26 ,8 ,16 ,7 ,27 ,20 ,13 ,2,
								41 ,52 ,31 ,37 ,47 ,55 ,30 ,40,
								51 ,45 ,33 ,48 ,44 ,49 ,39 ,56 ,
								34 ,53 ,46 ,42 ,50 ,36 ,29 ,32 };
int ShiftTable[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 }; // 순환이동 비트량을 나타내는 테이블
void main() {
	printf("17124074 정욱현\n");
	printf("16진수 평문 16자리 입력 :");
	gets(inp_plain); // 평문 입력받아 저장
	printf("\n");
	P2B(inp_plain, plainBlock); // 입력받은 16진수 평문을 64비트 2진수로 변환
	
	printf("\n16진수 키 16자리 입력 : ");
	gets(inp_key);
	
	printf("\n\n");
	printf("라운드            Left                 Right                  라운드 Key\n");
	P2B(inp_key, keyBlock); // 입력받은 16진수 키를 64비트 2진수 키 배열로 변환
	
	Key_generator(keyBlock, RoundKeys, ShiftTable);  //키 생성
	
	
	Cipher(plainBlock, RoundKeys, cipherBlock); //암호화 
	
	printf("CipherText 출력 :");
	Hexa(cipherBlock,64); //암호문 출력
	printf("\n\n");
	
}

void P2B(char* inp_plain, unsigned char* plainBlock) { // 16진수 배열을 2진수 배열로 변환하는 함수
	int Num; 
	int i = 0; // char 배열로 받은 평문을 참조할 인덱스
	int t = 0; // 평문을 2진수한 배열 plainBlock 에 참조할 인덱스
	while (i != 16) {
		if (inp_plain[i] < 65 && inp_plain[i] >47)
		{
			Num = inp_plain[i] - 48; // 숫자일 경우 48감소하여 숫자에 대응하는 아스키코드로 변환
		}
		else {
			Num = inp_plain[i] - 55; //  A~F일 경우 55감소하여 숫자에 대응하는 아스키 코드로 변환
		}

		for (int j = 4; j < 8; j++) {
			if (((0x80) & (Num << j)) == 0) { // 0x80(1000 0000) 비트와 &연산하여 평문 한 문자의 이진 배열을 앞에서부터 저장
				plainBlock[t] = 0;
			}
			else {
				plainBlock[t] = 1;
			}
			t++;
		}
		i++;
	}
	
}

	
void Cipher(unsigned char plainBlock[64], unsigned char RoundKeys[16][48], unsigned char cipherBlock[64]) { // DES암호화 함수
	int round = 0;
	unsigned char outBlock[64];
	permute(64, 64, plainBlock, inBlock, InitialPermutationTable);// 평문을 초기치환
	split(64, 32, inBlock, leftBlock, rightBlock); //치환된 평문을 left블록과 right블록으로 분리
	while (round != 16) { //총 16라운드 진행
		
		mixer(leftBlock, rightBlock, RoundKeys[round]); //라운드 진행
		


		if (round != 15) { // 마지막 라운드는 swapper을 시행하지 않음
			swapper(leftBlock, rightBlock);// left블록과 right블록 서로 교체
		}
		printf("Round %02d         ", round + 1);
		printf("leftBlock:");
		Hexa(leftBlock,32);
		printf("    rightBlock:");
		Hexa(rightBlock,32);
		printf("    roundKey:");
		Hexa(RoundKeys[round],48);
		printf("\n\n");

		round++;
	}
	Combine(32, 64, leftBlock, rightBlock, outBlock); // 분리되어있는 left블록 right블록 을 하나로 병합
	printf("After combination :");
	Hexa(outBlock,64); // 최종 치환전 값을 16진수 출력
	printf("\n");
	permute(64, 64, outBlock, cipherBlock, Final_permutation); // 최종치환테이블에 따라서 최종 치환
}

void permute(int size1, int size2, unsigned char* baseBlock, unsigned char* finalBlock, char* Table){ // 치환 함수(Table을 받아 base로 받은 블록을 치환표에 따라 치환하여 final블록 배열로 저장
	for (int i = 0; i < size2; i++) {
		finalBlock[i] = baseBlock[Table[i] - 1];  // 치환된 값을 저장하는 배열에 치환테이블을 따라 비트 재배치
	}
}
void split(int size1, int size2, unsigned char* inBlock, unsigned char* leftBlock, unsigned char* rightBlock) { //inBlock 블록을 left블록과 right블록으로 분리하는 split 함수
	for (int i = 0; i < size2; i++) {
		leftBlock[i] = inBlock[i]; // 0~ size2-1 번째 비트(비트의 절반)는 LeftBlock 으로
	}
	for (int i = size2; i < size1; i++) {
		rightBlock[i - size2] = inBlock[i]; //size2~ size1-1 번째 비트(나머지 절반)는 RightBlock으로 분리
	}
}
void Combine(int size1, int size2, unsigned char* leftBlock, unsigned char* rightBlock, unsigned char* outBlock) { // 인자로 받는 left블록과 right블록을 병합하여 outBlock에 저장하는 함수
	for (int i = 0; i < size1; i++) {
		outBlock[i] = leftBlock[i]; //left블록을 절반 저장
	}
	for (int i = size1; i < size2; i++) {
		outBlock[i] = rightBlock[i - size1]; //나머지에 right블록 저장
	}
}
void mixer(unsigned char* leftBlock, unsigned char* rightBlock, unsigned char* RoundKey) { // 라운드 진행하는 mixer 함수 
	unsigned char T1[32],  T2[32], T3[32];
	copy(32, rightBlock, T1); //right블록 값을 T1에 임시 저장
	function(T1, RoundKey, T2); //T1과 라운드키를 라운드함수에 넣어서 값을 얻어낸 후 T2에 저장
	exclusiveOr(32, leftBlock, T2, T3);//left블록과 라운드함수를 거친 T2를 배타적 논리합으로 논리연산 하여 T3저장
	copy(32, T3, leftBlock); // T3값을 left블록에 저장
}
void copy(int size, unsigned char* baseBlock, unsigned char* finalBlock) { // 복사 함수
	for (int i = 0; i < size; i++) {
		finalBlock[i] = baseBlock[i]; 
	}
}
void function(unsigned char* inBlock, unsigned char* roundKey, unsigned char* outBlock) { // 라운드 함수
	unsigned char T1[48], T2[48], T3[48];
	permute(32, 48, inBlock, T1, Expansion_PermutationTable); //  라운드 키가 48비트 이므로 연산을 위해 right블록을 확산P박스를 통해 48비트로 확산
	exclusiveOr(48,T1,roundKey,T2); // 라운드키와 확산된 비트를 배타적 논리연산
	substitute(T2, T3, S_PermutationTable); // s박스를 통해서 다시 48비트 블록을 32비트로 축소
	permute(32, 32, T3, outBlock, Straight_PermutationTable); // 단순 P 박스를 통과
}
void exclusiveOr(int size, unsigned char* baseBlock, unsigned char* roundKey, unsigned char* finalBlock) { //배타적 논리합 XOR
	for (int i = 0; i < size; i++) {
		finalBlock[i] = (baseBlock[i] != roundKey[i]); // 다르면 1 같으면 0 저장
	}
}
void substitute(unsigned char* inBlock, unsigned char* outBlock, unsigned char table[8][4][16]) { //s박스
	int row, col, value;
	for (int i = 0; i < 8; i++) {
		row = 2 * inBlock[i * 6 ] + inBlock[i * 6 + 5]; // 1번째와 6번째 는 S박스의 행으로
		col = 8 * inBlock[i * 6 + 1] + 4 * inBlock[i * 6 + 2] + 2 * inBlock[i * 6 + 3] + inBlock[i * 6 + 4]; // 나머지 2,3,4,5 번째 비트는 열로

		value = table[i][row][col]; // s박스의 값 참조

		outBlock[i * 4] = value / 8; // s박스의 값이 10진수임으로 2의 3승 = 8 , 2의 2승 = 4 2의 1승 = 2으로 나눠서 
		value = value % 8; //이미 나눈 값을 제외하기위해 나머지연산(mod연산)
		outBlock[i * 4 + 1] = value / 4; 
		value = value % 4;
		outBlock[i * 4 + 2] = value / 2;
		value = value % 2;
		outBlock[i * 4 + 3] = value;
		


	}
}
void swapper(unsigned char* leftBlock, unsigned char* rightBlock) { //  left 블록과 right블록을 서로치환하는 함수
	unsigned char T[32];
	copy(32, leftBlock, T); //  T에 left블록 임시 저장
	copy(32, rightBlock, leftBlock); // right블록을 left블록에 저장
	copy(32, T, rightBlock); // T를 right블록에 저장

}
void Key_generator(unsigned char* keyWithParities, unsigned char roundKeys[16][48], int ShiftTable[16]) { // 키 생성 함수 
	unsigned char cipherKey[56],leftKey[28],rightKey[28],preRoundKey[56];
	
	permute(64, 56, keyWithParities, cipherKey, ParityDropTable); // 패리티 비트를 제거하기 위해 패리티 테이블에 따라 치환하여 입력받은 64비트 키를 56비트로 축소
	
	split(56, 28, cipherKey, leftKey, rightKey); // 56비트 키를 28비트씩 분리
	for (int round = 0; round < 16; round++) { // 총 16라운드치 키 값을 생성
		shiftLeft(leftKey, ShiftTable[round]); // 순환이동 비트량에 따라서 좌쉬프트
		shiftLeft(rightKey, ShiftTable[round]); // 순환이동 비트량(ShiftTable) 에 따라서 좌쉬프트
		Combine(28, 56, leftKey, rightKey, preRoundKey); // 다시 56비트로 병함
		permute(56, 48, preRoundKey, roundKeys[round], KeyCompressionTable); // keyCompressionTable에 따라서 48비트로 걸러내고 이 값을 라운드 키로 저장 

	}

}
void shiftLeft(unsigned char* block, char numOfShifts) { //  좌쉬프트 연산 함수
	unsigned char T;
	for (int i = 0; i < numOfShifts; i++) { // shift 테이블의 값에 따라 반복
		T = block[0]; // 첫비트를 빼두고
		for (int j = 1; j < 28; j++) {
			block[j - 1] = block[j]; // 좌측으로 쉬프트

		}
		block[27] = T; //첫 비트를 마지막에 넣음
	}
}


void Hexa(unsigned char* Block,int size) // 2진수를 16진수로 변환하는 함수
{
	int i = 0;
	int t = size / 8; // 변환할 블록의 양을 8비트로 나눠서 출력시 반복할 횟수 구함
	unsigned char hexa[8] = { 0,0,0,0,0,0,0,0}; //  hexa배열의 한 원소당 8비트를 저장 최대 64비트까지 저장
	while (i * 8 < size) {
		for (int j = 0; j < 8; j++) {
			hexa[i] = hexa[i] | (Block[i * 8+j] << (7-j)); // 변환할 2진수는 0 과 1(0000 0000, 0000 0001)로 이루어져 있으므로 좌측으로 쉬프트하여 맨 마지막 비트의 위치를 맞춘후 |(논리합)연산하여 hexa의 한 원소에 변환하고자 하는 2진수를 8비트씩 끊어서 저장
		}
		i++;
	}
	

	for (i = 0; i < t; i++) //  반복횟수 t만큼
	{
		
		printf("%02X", hexa[i]); // 8비트씩 읽어서 16진수로 출력
	}

}