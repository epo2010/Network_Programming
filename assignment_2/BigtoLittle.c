#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


// 빅엔디언에서 리틀엔디언으로 변환하는 함수
int BigtoLittle(uint32_t buf) {
	uint32_t result;

// 비트연산으로 엔디언 변환하는 코드
	result = (buf >> 24) | ((buf >> 8 ) & 0x0000FF00) | ((buf << 8) & 0x00FF0000) | (buf << 24);
	return result;
}

int main(int argc, char *argv[]) {
// 입력 파일, 출력 파일 모두 읽어야 하므로 인자가 제대로 받아지지 않는다면 다음을 출력
  if (argc != 3) {
    printf("Usage: %s <입력 파일> <출력 파일>\n", argv[0]);
  }

// 파일을 바이너리로 읽어 in_f 위치에 저장
FILE *in_f = fopen(argv[1], "rb");
if (in_f == NULL ) {
	printf("일치하는 파일이 없습니다");}  // 일치하는 파일이 없는 경우 


// 4바이트 크기 바이너리를 넣어줄 변수 선언
uint32_t buffer;
// fread()함수를 이용해 파일로부터 지정한 크기 만큼 자료를 읽어들여 저장
fread(&buffer, 4, 1, in_f); // fread(읽은 데이터가 저장될 포인터, 읽을 크기, 읽을 개수, 읽을 파일)
fclose(in_f); // 파일 닫기  

buffer = BigtoLittle(buffer); // 빅엔디언에서 리틀엔디언으로 바꾸는 함수 호출

FILE *out_f = fopen(argv[2], "wb"); // 출력 파일 포인터 선언
fwrite(&buffer, 4, 1, out_f); // 출력 파일에 적어준다.
fclose(out_f); // 파일 닫기
}