int main()
{
  int fd = -1;
  while (fd==-1)
  {
    fd = open("/dev/urandom",0);
    if (fd==-1) sleep(1);
  }

  unsigned char sk[32]={0};
  read(fd,sk,32);

  printf("SECKEY: ");
  int i;
  for (i=0;i<32;++i) printf("%02x",sk[i]);
  printf("\n");
}
