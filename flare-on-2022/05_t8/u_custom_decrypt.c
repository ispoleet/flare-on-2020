// Compile Me: gcc u_custom_decrypt.c -o u_custom_decrypt -lm
#include <stdio.h>
#include <stdlib.h>
#include <math.h>


// Function is as it is from IDA decompiler window.
int u_custom_decrypt(unsigned int X, unsigned int Y)
{
  unsigned int v2; // ecx
  int v3; // esi
  unsigned int v4; // eax
  float v5; // xmm0_4
  float v7; // [esp+2Ch] [ebp+14h]

  v2 = (X >> 16);
  v3 = (X & 0xFFFF) - 1;
  if ( (X >> 16) > 2 )
    v3 = (X & 0xFFFF);
  v4 = v2 + 12;
  if ( v2 > 2 )
    v4 = (X >> 16);
  v7 = (float)((float)((double)(int)(v3 / 100 / 4
                                   + (Y >> 16)
                                   + (int)((double)(v3 + 4716) * 365.25)
                                   - (int)((double)(int)(v4 + 1) * -30.6001)
                                   - v3 / 100
                                   + 2)
                     - 1524.5)
             - 2451549.5)
     / 29.53;
  v5 = floor(v7);
  return (int)roundf((float)(v7 - v5) * 29.53);
}


int main(int argc, char *argv[]) {
  printf("%d\n", u_custom_decrypt(atoi(argv[1]), atoi(argv[2])));

  return 0;
}