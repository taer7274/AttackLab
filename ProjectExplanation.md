## Overview

The goal of this project is to get more familiar with code injection and return-oriented programming techniques. 

To investigate both of the targets, make sure to disassemble them. You can do so using the following commands: 

        objdump -d rtarget > rtarget.s
        objdump -d ctarget > ctarget.s
        
Additionally, you can use the 'gdb' debugger to step through the code, investigate what's stored in the registers, etc. 
You can begin a 'gdb' session by using the following command: 

        gdb ctarget
        
Here's some more helpful commands: 
        break getbuf    set a breakpoint at getbuf
        run             run program
        x/10i $pc       next 10 instructions
        x/10i touch1    next 10 instructions for function touch1
        si              step in
        ni              next instruction
        p/x $rsp        print hex value of stack pointer


All of these attacks will leverage the 'getbuf' function to create a buffer overflow. 

Therefore, the first step will be to understand the size of the buffer, which can be done by inspecting the getbuf function. 

### getbuf

    0000000000401474 <getbuf>:
      401474:	48 83 ec 18          	sub    $0x18,%rsp
      401478:	48 89 e7             	mov    %rsp,%rdi
      40147b:	e8 94 02 00 00       	callq  401714 <Gets>
      401480:	b8 01 00 00 00       	mov    $0x1,%eax
      401485:	48 83 c4 18          	add    $0x18,%rsp
      401489:	c3                   	retq   
  
We can see in the first line of 'getbuf' that we subtract $0x18, or 24 bytes, from the stack, creating a buffer of size 24. Therefore, in order to overflow the stack, we will need to create strings that are larger than size 24. 

## Phase 1
In the first phase, our goal is to use overflow the buffer, rewriting the return address of the getbuf function to be the address of the Touch1 function. 

Let's look at the Touch1 function to see what our address is: 

