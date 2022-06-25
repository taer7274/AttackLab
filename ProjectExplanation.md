## Phase 1

There are a few major functions in this project: 

### getbuf

    0000000000401474 <getbuf>:
      401474:	48 83 ec 18          	sub    $0x18,%rsp
      401478:	48 89 e7             	mov    %rsp,%rdi
      40147b:	e8 94 02 00 00       	callq  401714 <Gets>
      401480:	b8 01 00 00 00       	mov    $0x1,%eax
      401485:	48 83 c4 18          	add    $0x18,%rsp
      401489:	c3                   	retq   
  
