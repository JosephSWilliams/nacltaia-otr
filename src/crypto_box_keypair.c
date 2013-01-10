#include <nacl/crypto_box.h>
int main(){
unsigned char rk     [ 1];
unsigned char pk     [32];
unsigned char sk     [32];

while (1) {
if (read(0,rk,1)<1) exit(0);
  crypto_box_keypair(pk,sk);
             write(1,pk,32);
             write(1,sk,32);}}
