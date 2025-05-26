
solver_sample:     file format elf64-x86-64


Disassembly of section .interp:

0000000000000318 <.interp>:
 318:	2f                   	(bad)  
 319:	6c                   	ins    BYTE PTR es:[rdi],dx
 31a:	69 62 36 34 2f 6c 64 	imul   esp,DWORD PTR [rdx+0x36],0x646c2f34
 321:	2d 6c 69 6e 75       	sub    eax,0x756e696c
 326:	78 2d                	js     355 <__abi_tag-0x37>
 328:	78 38                	js     362 <__abi_tag-0x2a>
 32a:	36 2d 36 34 2e 73    	ss sub eax,0x732e3436
 330:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 331:	2e 32 00             	cs xor al,BYTE PTR [rax]

Disassembly of section .note.gnu.property:

0000000000000338 <.note.gnu.property>:
 338:	04 00                	add    al,0x0
 33a:	00 00                	add    BYTE PTR [rax],al
 33c:	20 00                	and    BYTE PTR [rax],al
 33e:	00 00                	add    BYTE PTR [rax],al
 340:	05 00 00 00 47       	add    eax,0x47000000
 345:	4e 55                	rex.WRX push rbp
 347:	00 02                	add    BYTE PTR [rdx],al
 349:	00 00                	add    BYTE PTR [rax],al
 34b:	c0 04 00 00          	rol    BYTE PTR [rax+rax*1],0x0
 34f:	00 03                	add    BYTE PTR [rbx],al
 351:	00 00                	add    BYTE PTR [rax],al
 353:	00 00                	add    BYTE PTR [rax],al
 355:	00 00                	add    BYTE PTR [rax],al
 357:	00 02                	add    BYTE PTR [rdx],al
 359:	80 00 c0             	add    BYTE PTR [rax],0xc0
 35c:	04 00                	add    al,0x0
 35e:	00 00                	add    BYTE PTR [rax],al
 360:	01 00                	add    DWORD PTR [rax],eax
 362:	00 00                	add    BYTE PTR [rax],al
 364:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .note.gnu.build-id:

0000000000000368 <.note.gnu.build-id>:
 368:	04 00                	add    al,0x0
 36a:	00 00                	add    BYTE PTR [rax],al
 36c:	14 00                	adc    al,0x0
 36e:	00 00                	add    BYTE PTR [rax],al
 370:	03 00                	add    eax,DWORD PTR [rax]
 372:	00 00                	add    BYTE PTR [rax],al
 374:	47                   	rex.RXB
 375:	4e 55                	rex.WRX push rbp
 377:	00 fc                	add    ah,bh
 379:	00 33                	add    BYTE PTR [rbx],dh
 37b:	fc                   	cld    
 37c:	eb e3                	jmp    361 <__abi_tag-0x2b>
 37e:	28 69 ab             	sub    BYTE PTR [rcx-0x55],ch
 381:	b1 5e                	mov    cl,0x5e
 383:	fb                   	sti    
 384:	d9 73 9c             	fnstenv [rbx-0x64]
 387:	29 d2                	sub    edx,edx
 389:	03 29                	add    ebp,DWORD PTR [rcx]
 38b:	b9                   	.byte 0xb9

Disassembly of section .note.ABI-tag:

000000000000038c <__abi_tag>:
 38c:	04 00                	add    al,0x0
 38e:	00 00                	add    BYTE PTR [rax],al
 390:	10 00                	adc    BYTE PTR [rax],al
 392:	00 00                	add    BYTE PTR [rax],al
 394:	01 00                	add    DWORD PTR [rax],eax
 396:	00 00                	add    BYTE PTR [rax],al
 398:	47                   	rex.RXB
 399:	4e 55                	rex.WRX push rbp
 39b:	00 00                	add    BYTE PTR [rax],al
 39d:	00 00                	add    BYTE PTR [rax],al
 39f:	00 03                	add    BYTE PTR [rbx],al
 3a1:	00 00                	add    BYTE PTR [rax],al
 3a3:	00 02                	add    BYTE PTR [rdx],al
 3a5:	00 00                	add    BYTE PTR [rax],al
 3a7:	00 00                	add    BYTE PTR [rax],al
 3a9:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .gnu.hash:

00000000000003b0 <.gnu.hash>:
 3b0:	03 00                	add    eax,DWORD PTR [rax]
 3b2:	00 00                	add    BYTE PTR [rax],al
 3b4:	07                   	(bad)  
 3b5:	00 00                	add    BYTE PTR [rax],al
 3b7:	00 01                	add    BYTE PTR [rcx],al
 3b9:	00 00                	add    BYTE PTR [rax],al
 3bb:	00 06                	add    BYTE PTR [rsi],al
 3bd:	00 00                	add    BYTE PTR [rax],al
 3bf:	00 00                	add    BYTE PTR [rax],al
 3c1:	00 81 00 00 41 10    	add    BYTE PTR [rcx+0x10410000],al
 3c7:	01 07                	add    DWORD PTR [rdi],eax
 3c9:	00 00                	add    BYTE PTR [rax],al
 3cb:	00 09                	add    BYTE PTR [rcx],cl
 3cd:	00 00                	add    BYTE PTR [rax],al
 3cf:	00 00                	add    BYTE PTR [rax],al
 3d1:	00 00                	add    BYTE PTR [rax],al
 3d3:	00 28                	add    BYTE PTR [rax],ch
 3d5:	1d 8c 1c d1 65       	sbb    eax,0x65d11c8c
 3da:	ce                   	(bad)  
 3db:	6d                   	ins    DWORD PTR es:[rdi],dx
 3dc:	b9                   	.byte 0xb9
 3dd:	2b 6b 15             	sub    ebp,DWORD PTR [rbx+0x15]

Disassembly of section .dynsym:

00000000000003e0 <.dynsym>:
	...
 3f8:	10 00                	adc    BYTE PTR [rax],al
 3fa:	00 00                	add    BYTE PTR [rax],al
 3fc:	12 00                	adc    al,BYTE PTR [rax]
	...
 40e:	00 00                	add    BYTE PTR [rax],al
 410:	73 00                	jae    412 <__abi_tag+0x86>
 412:	00 00                	add    BYTE PTR [rax],al
 414:	20 00                	and    BYTE PTR [rax],al
	...
 426:	00 00                	add    BYTE PTR [rax],al
 428:	30 00                	xor    BYTE PTR [rax],al
 42a:	00 00                	add    BYTE PTR [rax],al
 42c:	12 00                	adc    al,BYTE PTR [rax]
	...
 43e:	00 00                	add    BYTE PTR [rax],al
 440:	8f 00                	pop    QWORD PTR [rax]
 442:	00 00                	add    BYTE PTR [rax],al
 444:	20 00                	and    BYTE PTR [rax],al
	...
 456:	00 00                	add    BYTE PTR [rax],al
 458:	29 00                	sub    DWORD PTR [rax],eax
 45a:	00 00                	add    BYTE PTR [rax],al
 45c:	12 00                	adc    al,BYTE PTR [rax]
	...
 46e:	00 00                	add    BYTE PTR [rax],al
 470:	9e                   	sahf   
 471:	00 00                	add    BYTE PTR [rax],al
 473:	00 20                	add    BYTE PTR [rax],ah
	...
 485:	00 00                	add    BYTE PTR [rax],al
 487:	00 22                	add    BYTE PTR [rdx],ah
 489:	00 00                	add    BYTE PTR [rax],al
 48b:	00 11                	add    BYTE PTR [rcx],dl
 48d:	00 1a                	add    BYTE PTR [rdx],bl
 48f:	00 10                	add    BYTE PTR [rax],dl
 491:	40 00 00             	rex add BYTE PTR [rax],al
 494:	00 00                	add    BYTE PTR [rax],al
 496:	00 00                	add    BYTE PTR [rax],al
 498:	08 00                	or     BYTE PTR [rax],al
 49a:	00 00                	add    BYTE PTR [rax],al
 49c:	00 00                	add    BYTE PTR [rax],al
 49e:	00 00                	add    BYTE PTR [rax],al
 4a0:	01 00                	add    DWORD PTR [rax],eax
 4a2:	00 00                	add    BYTE PTR [rax],al
 4a4:	22 00                	and    al,BYTE PTR [rax]
	...
 4b6:	00 00                	add    BYTE PTR [rax],al
 4b8:	41 00 00             	add    BYTE PTR [r8],al
 4bb:	00 12                	add    BYTE PTR [rdx],dl
	...

Disassembly of section .dynstr:

00000000000004d0 <.dynstr>:
 4d0:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 4d3:	63 78 61             	movsxd edi,DWORD PTR [rax+0x61]
 4d6:	5f                   	pop    rdi
 4d7:	66 69 6e 61 6c 69    	imul   bp,WORD PTR [rsi+0x61],0x696c
 4dd:	7a 65                	jp     544 <__abi_tag+0x1b8>
 4df:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 4e2:	6c                   	ins    BYTE PTR es:[rdi],dx
 4e3:	69 62 63 5f 73 74 61 	imul   esp,DWORD PTR [rdx+0x63],0x6174735f
 4ea:	72 74                	jb     560 <__abi_tag+0x1d4>
 4ec:	5f                   	pop    rdi
 4ed:	6d                   	ins    DWORD PTR es:[rdi],dx
 4ee:	61                   	(bad)  
 4ef:	69 6e 00 73 74 64 6f 	imul   ebp,DWORD PTR [rsi+0x0],0x6f647473
 4f6:	75 74                	jne    56c <__abi_tag+0x1e0>
 4f8:	00 66 66             	add    BYTE PTR [rsi+0x66],ah
 4fb:	6c                   	ins    BYTE PTR es:[rdi],dx
 4fc:	75 73                	jne    571 <__abi_tag+0x1e5>
 4fe:	68 00 5f 5f 73       	push   0x735f5f00
 503:	74 61                	je     566 <__abi_tag+0x1da>
 505:	63 6b 5f             	movsxd ebp,DWORD PTR [rbx+0x5f]
 508:	63 68 6b             	movsxd ebp,DWORD PTR [rax+0x6b]
 50b:	5f                   	pop    rdi
 50c:	66 61                	data16 (bad) 
 50e:	69 6c 00 70 72 69 6e 	imul   ebp,DWORD PTR [rax+rax*1+0x70],0x746e6972
 515:	74 
 516:	66 00 6c 69 62       	data16 add BYTE PTR [rcx+rbp*2+0x62],ch
 51b:	63 2e                	movsxd ebp,DWORD PTR [rsi]
 51d:	73 6f                	jae    58e <__abi_tag+0x202>
 51f:	2e 36 00 47 4c       	cs ss add BYTE PTR [rdi+0x4c],al
 524:	49                   	rex.WB
 525:	42                   	rex.X
 526:	43 5f                	rex.XB pop r15
 528:	32 2e                	xor    ch,BYTE PTR [rsi]
 52a:	34 00                	xor    al,0x0
 52c:	47                   	rex.RXB
 52d:	4c                   	rex.WR
 52e:	49                   	rex.WB
 52f:	42                   	rex.X
 530:	43 5f                	rex.XB pop r15
 532:	32 2e                	xor    ch,BYTE PTR [rsi]
 534:	32 2e                	xor    ch,BYTE PTR [rsi]
 536:	35 00 47 4c 49       	xor    eax,0x494c4700
 53b:	42                   	rex.X
 53c:	43 5f                	rex.XB pop r15
 53e:	32 2e                	xor    ch,BYTE PTR [rsi]
 540:	33 34 00             	xor    esi,DWORD PTR [rax+rax*1]
 543:	5f                   	pop    rdi
 544:	49 54                	rex.WB push r12
 546:	4d 5f                	rex.WRB pop r15
 548:	64 65 72 65          	fs gs jb 5b1 <__abi_tag+0x225>
 54c:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
 553:	4d 
 554:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
 556:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 557:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 558:	65 54                	gs push rsp
 55a:	61                   	(bad)  
 55b:	62                   	(bad)  
 55c:	6c                   	ins    BYTE PTR es:[rdi],dx
 55d:	65 00 5f 5f          	add    BYTE PTR gs:[rdi+0x5f],bl
 561:	67 6d                	ins    DWORD PTR es:[edi],dx
 563:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 564:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 565:	5f                   	pop    rdi
 566:	73 74                	jae    5dc <__abi_tag+0x250>
 568:	61                   	(bad)  
 569:	72 74                	jb     5df <__abi_tag+0x253>
 56b:	5f                   	pop    rdi
 56c:	5f                   	pop    rdi
 56d:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
 570:	54                   	push   rsp
 571:	4d 5f                	rex.WRB pop r15
 573:	72 65                	jb     5da <__abi_tag+0x24e>
 575:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
 57c:	4d 
 57d:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
 57f:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 580:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 581:	65 54                	gs push rsp
 583:	61                   	(bad)  
 584:	62                   	.byte 0x62
 585:	6c                   	ins    BYTE PTR es:[rdi],dx
 586:	65                   	gs
	...

Disassembly of section .gnu.version:

0000000000000588 <.gnu.version>:
 588:	00 00                	add    BYTE PTR [rax],al
 58a:	02 00                	add    al,BYTE PTR [rax]
 58c:	01 00                	add    DWORD PTR [rax],eax
 58e:	04 00                	add    al,0x0
 590:	01 00                	add    DWORD PTR [rax],eax
 592:	03 00                	add    eax,DWORD PTR [rax]
 594:	01 00                	add    DWORD PTR [rax],eax
 596:	03 00                	add    eax,DWORD PTR [rax]
 598:	03 00                	add    eax,DWORD PTR [rax]
 59a:	03 00                	add    eax,DWORD PTR [rax]

Disassembly of section .gnu.version_r:

00000000000005a0 <.gnu.version_r>:
 5a0:	01 00                	add    DWORD PTR [rax],eax
 5a2:	03 00                	add    eax,DWORD PTR [rax]
 5a4:	48 00 00             	rex.W add BYTE PTR [rax],al
 5a7:	00 10                	add    BYTE PTR [rax],dl
 5a9:	00 00                	add    BYTE PTR [rax],al
 5ab:	00 00                	add    BYTE PTR [rax],al
 5ad:	00 00                	add    BYTE PTR [rax],al
 5af:	00 14 69             	add    BYTE PTR [rcx+rbp*2],dl
 5b2:	69 0d 00 00 04 00 52 	imul   ecx,DWORD PTR [rip+0x40000],0x52        # 405bc <_end+0x3c59c>
 5b9:	00 00 00 
 5bc:	10 00                	adc    BYTE PTR [rax],al
 5be:	00 00                	add    BYTE PTR [rax],al
 5c0:	75 1a                	jne    5dc <__abi_tag+0x250>
 5c2:	69 09 00 00 03 00    	imul   ecx,DWORD PTR [rcx],0x30000
 5c8:	5c                   	pop    rsp
 5c9:	00 00                	add    BYTE PTR [rax],al
 5cb:	00 10                	add    BYTE PTR [rax],dl
 5cd:	00 00                	add    BYTE PTR [rax],al
 5cf:	00 b4 91 96 06 00 00 	add    BYTE PTR [rcx+rdx*4+0x696],dh
 5d6:	02 00                	add    al,BYTE PTR [rax]
 5d8:	68 00 00 00 00       	push   0x0
 5dd:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .rela.dyn:

00000000000005e0 <.rela.dyn>:
 5e0:	a8 3d                	test   al,0x3d
 5e2:	00 00                	add    BYTE PTR [rax],al
 5e4:	00 00                	add    BYTE PTR [rax],al
 5e6:	00 00                	add    BYTE PTR [rax],al
 5e8:	08 00                	or     BYTE PTR [rax],al
 5ea:	00 00                	add    BYTE PTR [rax],al
 5ec:	00 00                	add    BYTE PTR [rax],al
 5ee:	00 00                	add    BYTE PTR [rax],al
 5f0:	70 11                	jo     603 <__abi_tag+0x277>
 5f2:	00 00                	add    BYTE PTR [rax],al
 5f4:	00 00                	add    BYTE PTR [rax],al
 5f6:	00 00                	add    BYTE PTR [rax],al
 5f8:	b0 3d                	mov    al,0x3d
 5fa:	00 00                	add    BYTE PTR [rax],al
 5fc:	00 00                	add    BYTE PTR [rax],al
 5fe:	00 00                	add    BYTE PTR [rax],al
 600:	08 00                	or     BYTE PTR [rax],al
 602:	00 00                	add    BYTE PTR [rax],al
 604:	00 00                	add    BYTE PTR [rax],al
 606:	00 00                	add    BYTE PTR [rax],al
 608:	30 11                	xor    BYTE PTR [rcx],dl
 60a:	00 00                	add    BYTE PTR [rax],al
 60c:	00 00                	add    BYTE PTR [rax],al
 60e:	00 00                	add    BYTE PTR [rax],al
 610:	08 40 00             	or     BYTE PTR [rax+0x0],al
 613:	00 00                	add    BYTE PTR [rax],al
 615:	00 00                	add    BYTE PTR [rax],al
 617:	00 08                	add    BYTE PTR [rax],cl
 619:	00 00                	add    BYTE PTR [rax],al
 61b:	00 00                	add    BYTE PTR [rax],al
 61d:	00 00                	add    BYTE PTR [rax],al
 61f:	00 08                	add    BYTE PTR [rax],cl
 621:	40 00 00             	rex add BYTE PTR [rax],al
 624:	00 00                	add    BYTE PTR [rax],al
 626:	00 00                	add    BYTE PTR [rax],al
 628:	d0 3f                	sar    BYTE PTR [rdi],1
 62a:	00 00                	add    BYTE PTR [rax],al
 62c:	00 00                	add    BYTE PTR [rax],al
 62e:	00 00                	add    BYTE PTR [rax],al
 630:	06                   	(bad)  
 631:	00 00                	add    BYTE PTR [rax],al
 633:	00 01                	add    BYTE PTR [rcx],al
	...
 63d:	00 00                	add    BYTE PTR [rax],al
 63f:	00 d8                	add    al,bl
 641:	3f                   	(bad)  
 642:	00 00                	add    BYTE PTR [rax],al
 644:	00 00                	add    BYTE PTR [rax],al
 646:	00 00                	add    BYTE PTR [rax],al
 648:	06                   	(bad)  
 649:	00 00                	add    BYTE PTR [rax],al
 64b:	00 02                	add    BYTE PTR [rdx],al
	...
 655:	00 00                	add    BYTE PTR [rax],al
 657:	00 e0                	add    al,ah
 659:	3f                   	(bad)  
 65a:	00 00                	add    BYTE PTR [rax],al
 65c:	00 00                	add    BYTE PTR [rax],al
 65e:	00 00                	add    BYTE PTR [rax],al
 660:	06                   	(bad)  
 661:	00 00                	add    BYTE PTR [rax],al
 663:	00 09                	add    BYTE PTR [rcx],cl
	...
 66d:	00 00                	add    BYTE PTR [rax],al
 66f:	00 e8                	add    al,ch
 671:	3f                   	(bad)  
 672:	00 00                	add    BYTE PTR [rax],al
 674:	00 00                	add    BYTE PTR [rax],al
 676:	00 00                	add    BYTE PTR [rax],al
 678:	06                   	(bad)  
 679:	00 00                	add    BYTE PTR [rax],al
 67b:	00 04 00             	add    BYTE PTR [rax+rax*1],al
	...
 686:	00 00                	add    BYTE PTR [rax],al
 688:	f0 3f                	lock (bad) 
 68a:	00 00                	add    BYTE PTR [rax],al
 68c:	00 00                	add    BYTE PTR [rax],al
 68e:	00 00                	add    BYTE PTR [rax],al
 690:	06                   	(bad)  
 691:	00 00                	add    BYTE PTR [rax],al
 693:	00 06                	add    BYTE PTR [rsi],al
	...
 69d:	00 00                	add    BYTE PTR [rax],al
 69f:	00 f8                	add    al,bh
 6a1:	3f                   	(bad)  
 6a2:	00 00                	add    BYTE PTR [rax],al
 6a4:	00 00                	add    BYTE PTR [rax],al
 6a6:	00 00                	add    BYTE PTR [rax],al
 6a8:	06                   	(bad)  
 6a9:	00 00                	add    BYTE PTR [rax],al
 6ab:	00 08                	add    BYTE PTR [rax],cl
	...
 6b5:	00 00                	add    BYTE PTR [rax],al
 6b7:	00 10                	add    BYTE PTR [rax],dl
 6b9:	40 00 00             	rex add BYTE PTR [rax],al
 6bc:	00 00                	add    BYTE PTR [rax],al
 6be:	00 00                	add    BYTE PTR [rax],al
 6c0:	05 00 00 00 07       	add    eax,0x7000000
	...

Disassembly of section .rela.plt:

00000000000006d0 <.rela.plt>:
 6d0:	c0 3f 00             	sar    BYTE PTR [rdi],0x0
 6d3:	00 00                	add    BYTE PTR [rax],al
 6d5:	00 00                	add    BYTE PTR [rax],al
 6d7:	00 07                	add    BYTE PTR [rdi],al
 6d9:	00 00                	add    BYTE PTR [rax],al
 6db:	00 03                	add    BYTE PTR [rbx],al
	...
 6e5:	00 00                	add    BYTE PTR [rax],al
 6e7:	00 c8                	add    al,cl
 6e9:	3f                   	(bad)  
 6ea:	00 00                	add    BYTE PTR [rax],al
 6ec:	00 00                	add    BYTE PTR [rax],al
 6ee:	00 00                	add    BYTE PTR [rax],al
 6f0:	07                   	(bad)  
 6f1:	00 00                	add    BYTE PTR [rax],al
 6f3:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 6f9 <__abi_tag+0x36d>
 6f9:	00 00                	add    BYTE PTR [rax],al
 6fb:	00 00                	add    BYTE PTR [rax],al
 6fd:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    rsp,0x8
    1008:	48 8b 05 d9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd9]        # 3fe8 <__gmon_start__@Base>
    100f:	48 85 c0             	test   rax,rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   rax
    1016:	48 83 c4 08          	add    rsp,0x8
    101a:	c3                   	ret    

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 8a 2f 00 00    	push   QWORD PTR [rip+0x2f8a]        # 3fb0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 8b 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f8b]        # 3fb8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nop    DWORD PTR [rax]
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	push   0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    103f:	90                   	nop
    1040:	f3 0f 1e fa          	endbr64 
    1044:	68 01 00 00 00       	push   0x1
    1049:	f2 e9 d1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    104f:	90                   	nop

Disassembly of section .plt.got:

0000000000001050 <printf@plt>:
    1050:	f3 0f 1e fa          	endbr64 
    1054:	f2 ff 25 85 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f85]        # 3fe0 <printf@GLIBC_2.2.5>
    105b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001060 <__cxa_finalize@plt>:
    1060:	f3 0f 1e fa          	endbr64 
    1064:	f2 ff 25 8d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f8d]        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    106b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .plt.sec:

0000000000001070 <__stack_chk_fail@plt>:
    1070:	f3 0f 1e fa          	endbr64 
    1074:	f2 ff 25 45 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f45]        # 3fc0 <__stack_chk_fail@GLIBC_2.4>
    107b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001080 <fflush@plt>:
    1080:	f3 0f 1e fa          	endbr64 
    1084:	f2 ff 25 3d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f3d]        # 3fc8 <fflush@GLIBC_2.2.5>
    108b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000001090 <_start>:
    1090:	f3 0f 1e fa          	endbr64 
    1094:	31 ed                	xor    ebp,ebp
    1096:	49 89 d1             	mov    r9,rdx
    1099:	5e                   	pop    rsi
    109a:	48 89 e2             	mov    rdx,rsp
    109d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    10a1:	50                   	push   rax
    10a2:	54                   	push   rsp
    10a3:	45 31 c0             	xor    r8d,r8d
    10a6:	31 c9                	xor    ecx,ecx
    10a8:	48 8d 3d b3 01 00 00 	lea    rdi,[rip+0x1b3]        # 1262 <main>
    10af:	ff 15 1b 2f 00 00    	call   QWORD PTR [rip+0x2f1b]        # 3fd0 <__libc_start_main@GLIBC_2.34>
    10b5:	f4                   	hlt    
    10b6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    10bd:	00 00 00 

00000000000010c0 <deregister_tm_clones>:
    10c0:	48 8d 3d 49 2f 00 00 	lea    rdi,[rip+0x2f49]        # 4010 <stdout@GLIBC_2.2.5>
    10c7:	48 8d 05 42 2f 00 00 	lea    rax,[rip+0x2f42]        # 4010 <stdout@GLIBC_2.2.5>
    10ce:	48 39 f8             	cmp    rax,rdi
    10d1:	74 15                	je     10e8 <deregister_tm_clones+0x28>
    10d3:	48 8b 05 fe 2e 00 00 	mov    rax,QWORD PTR [rip+0x2efe]        # 3fd8 <_ITM_deregisterTMCloneTable@Base>
    10da:	48 85 c0             	test   rax,rax
    10dd:	74 09                	je     10e8 <deregister_tm_clones+0x28>
    10df:	ff e0                	jmp    rax
    10e1:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    10e8:	c3                   	ret    
    10e9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000000010f0 <register_tm_clones>:
    10f0:	48 8d 3d 19 2f 00 00 	lea    rdi,[rip+0x2f19]        # 4010 <stdout@GLIBC_2.2.5>
    10f7:	48 8d 35 12 2f 00 00 	lea    rsi,[rip+0x2f12]        # 4010 <stdout@GLIBC_2.2.5>
    10fe:	48 29 fe             	sub    rsi,rdi
    1101:	48 89 f0             	mov    rax,rsi
    1104:	48 c1 ee 3f          	shr    rsi,0x3f
    1108:	48 c1 f8 03          	sar    rax,0x3
    110c:	48 01 c6             	add    rsi,rax
    110f:	48 d1 fe             	sar    rsi,1
    1112:	74 14                	je     1128 <register_tm_clones+0x38>
    1114:	48 8b 05 d5 2e 00 00 	mov    rax,QWORD PTR [rip+0x2ed5]        # 3ff0 <_ITM_registerTMCloneTable@Base>
    111b:	48 85 c0             	test   rax,rax
    111e:	74 08                	je     1128 <register_tm_clones+0x38>
    1120:	ff e0                	jmp    rax
    1122:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1128:	c3                   	ret    
    1129:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001130 <__do_global_dtors_aux>:
    1130:	f3 0f 1e fa          	endbr64 
    1134:	80 3d dd 2e 00 00 00 	cmp    BYTE PTR [rip+0x2edd],0x0        # 4018 <completed.0>
    113b:	75 2b                	jne    1168 <__do_global_dtors_aux+0x38>
    113d:	55                   	push   rbp
    113e:	48 83 3d b2 2e 00 00 	cmp    QWORD PTR [rip+0x2eb2],0x0        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1145:	00 
    1146:	48 89 e5             	mov    rbp,rsp
    1149:	74 0c                	je     1157 <__do_global_dtors_aux+0x27>
    114b:	48 8b 3d b6 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2eb6]        # 4008 <__dso_handle>
    1152:	e8 09 ff ff ff       	call   1060 <__cxa_finalize@plt>
    1157:	e8 64 ff ff ff       	call   10c0 <deregister_tm_clones>
    115c:	c6 05 b5 2e 00 00 01 	mov    BYTE PTR [rip+0x2eb5],0x1        # 4018 <completed.0>
    1163:	5d                   	pop    rbp
    1164:	c3                   	ret    
    1165:	0f 1f 00             	nop    DWORD PTR [rax]
    1168:	c3                   	ret    
    1169:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001170 <frame_dummy>:
    1170:	f3 0f 1e fa          	endbr64 
    1174:	e9 77 ff ff ff       	jmp    10f0 <register_tm_clones>

0000000000001179 <solver>:
    1179:	f3 0f 1e fa          	endbr64 
    117d:	55                   	push   rbp
    117e:	48 89 e5             	mov    rbp,rsp
    1181:	48 83 ec 20          	sub    rsp,0x20
    1185:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
    1189:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1190:	00 00 
    1192:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1196:	31 c0                	xor    eax,eax
    1198:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
    119f:	00 
    11a0:	48 8d 45 f0          	lea    rax,[rbp-0x10]
    11a4:	48 83 c0 08          	add    rax,0x8
    11a8:	48 8b 10             	mov    rdx,QWORD PTR [rax]
    11ab:	48 8d 45 f0          	lea    rax,[rbp-0x10]
    11af:	48 83 c0 08          	add    rax,0x8
    11b3:	4c 8b 45 e8          	mov    r8,QWORD PTR [rbp-0x18]
    11b7:	48 89 d1             	mov    rcx,rdx
    11ba:	48 89 c2             	mov    rdx,rax
    11bd:	be 08 00 00 00       	mov    esi,0x8
    11c2:	48 8d 05 3f 0e 00 00 	lea    rax,[rip+0xe3f]        # 2008 <_IO_stdin_used+0x8>
    11c9:	48 89 c7             	mov    rdi,rax
    11cc:	b8 00 00 00 00       	mov    eax,0x0
    11d1:	41 ff d0             	call   r8
    11d4:	48 8d 45 f0          	lea    rax,[rbp-0x10]
    11d8:	48 83 c0 10          	add    rax,0x10
    11dc:	48 8b 10             	mov    rdx,QWORD PTR [rax]
    11df:	48 8d 45 f0          	lea    rax,[rbp-0x10]
    11e3:	48 83 c0 10          	add    rax,0x10
    11e7:	4c 8b 45 e8          	mov    r8,QWORD PTR [rbp-0x18]
    11eb:	48 89 d1             	mov    rcx,rdx
    11ee:	48 89 c2             	mov    rdx,rax
    11f1:	be 10 00 00 00       	mov    esi,0x10
    11f6:	48 8d 05 33 0e 00 00 	lea    rax,[rip+0xe33]        # 2030 <_IO_stdin_used+0x30>
    11fd:	48 89 c7             	mov    rdi,rax
    1200:	b8 00 00 00 00       	mov    eax,0x0
    1205:	41 ff d0             	call   r8
    1208:	48 8d 45 f0          	lea    rax,[rbp-0x10]
    120c:	48 83 c0 18          	add    rax,0x18
    1210:	48 8b 10             	mov    rdx,QWORD PTR [rax]
    1213:	48 8d 45 f0          	lea    rax,[rbp-0x10]
    1217:	48 83 c0 18          	add    rax,0x18
    121b:	4c 8b 45 e8          	mov    r8,QWORD PTR [rbp-0x18]
    121f:	48 89 d1             	mov    rcx,rdx
    1222:	48 89 c2             	mov    rdx,rax
    1225:	be 18 00 00 00       	mov    esi,0x18
    122a:	48 8d 05 1f 0e 00 00 	lea    rax,[rip+0xe1f]        # 2050 <_IO_stdin_used+0x50>
    1231:	48 89 c7             	mov    rdi,rax
    1234:	b8 00 00 00 00       	mov    eax,0x0
    1239:	41 ff d0             	call   r8
    123c:	48 8b 05 cd 2d 00 00 	mov    rax,QWORD PTR [rip+0x2dcd]        # 4010 <stdout@GLIBC_2.2.5>
    1243:	48 89 c7             	mov    rdi,rax
    1246:	e8 35 fe ff ff       	call   1080 <fflush@plt>
    124b:	90                   	nop
    124c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    1250:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
    1257:	00 00 
    1259:	74 05                	je     1260 <solver+0xe7>
    125b:	e8 10 fe ff ff       	call   1070 <__stack_chk_fail@plt>
    1260:	c9                   	leave  
    1261:	c3                   	ret    

0000000000001262 <main>:
    1262:	f3 0f 1e fa          	endbr64 
    1266:	55                   	push   rbp
    1267:	48 89 e5             	mov    rbp,rsp
    126a:	48 83 ec 20          	sub    rsp,0x20
    126e:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1275:	00 00 
    1277:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    127b:	31 c0                	xor    eax,eax
    127d:	48 b8 2a 2a 20 6d 61 	movabs rax,0x206e69616d202a2a
    1284:	69 6e 20 
    1287:	48 ba 3d 20 25 70 0a 	movabs rdx,0xa7025203d
    128e:	00 00 00 
    1291:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    1295:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
    1299:	48 8d 45 e0          	lea    rax,[rbp-0x20]
    129d:	48 8d 15 be ff ff ff 	lea    rdx,[rip+0xffffffffffffffbe]        # 1262 <main>
    12a4:	48 89 d6             	mov    rsi,rdx
    12a7:	48 89 c7             	mov    rdi,rax
    12aa:	b8 00 00 00 00       	mov    eax,0x0
    12af:	e8 9c fd ff ff       	call   1050 <printf@plt>
    12b4:	48 8b 05 25 2d 00 00 	mov    rax,QWORD PTR [rip+0x2d25]        # 3fe0 <printf@GLIBC_2.2.5>
    12bb:	48 89 c7             	mov    rdi,rax
    12be:	e8 b6 fe ff ff       	call   1179 <solver>
    12c3:	b8 00 00 00 00       	mov    eax,0x0
    12c8:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    12cc:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
    12d3:	00 00 
    12d5:	74 05                	je     12dc <main+0x7a>
    12d7:	e8 94 fd ff ff       	call   1070 <__stack_chk_fail@plt>
    12dc:	c9                   	leave  
    12dd:	c3                   	ret    

Disassembly of section .fini:

00000000000012e0 <_fini>:
    12e0:	f3 0f 1e fa          	endbr64 
    12e4:	48 83 ec 08          	sub    rsp,0x8
    12e8:	48 83 c4 08          	add    rsp,0x8
    12ec:	c3                   	ret    

Disassembly of section .rodata:

0000000000002000 <_IO_stdin_used>:
    2000:	01 00                	add    DWORD PTR [rax],eax
    2002:	02 00                	add    al,BYTE PTR [rax]
    2004:	00 00                	add    BYTE PTR [rax],al
    2006:	00 00                	add    BYTE PTR [rax],al
    2008:	63 61 6e             	movsxd esp,DWORD PTR [rcx+0x6e]
    200b:	61                   	(bad)  
    200c:	72 79                	jb     2087 <__GNU_EH_FRAME_HDR+0x17>
    200e:	20 2d 3e 20 26 70    	and    BYTE PTR [rip+0x7026203e],ch        # 70264052 <_end+0x70260032>
    2014:	74 72                	je     2088 <__GNU_EH_FRAME_HDR+0x18>
    2016:	2b 25 78 3a 20 25    	sub    esp,DWORD PTR [rip+0x25203a78]        # 25205a94 <_end+0x25201a74>
    201c:	70 2c                	jo     204a <_IO_stdin_used+0x4a>
    201e:	20 76 61             	and    BYTE PTR [rsi+0x61],dh
    2021:	6c                   	ins    BYTE PTR es:[rdi],dx
    2022:	20 3d 20 25 6c 6c    	and    BYTE PTR [rip+0x6c6c2520],bh        # 6c6c4548 <_end+0x6c6c0528>
    2028:	78 0a                	js     2034 <_IO_stdin_used+0x34>
    202a:	00 00                	add    BYTE PTR [rax],al
    202c:	00 00                	add    BYTE PTR [rax],al
    202e:	00 00                	add    BYTE PTR [rax],al
    2030:	72 62                	jb     2094 <__GNU_EH_FRAME_HDR+0x24>
    2032:	70 20                	jo     2054 <_IO_stdin_used+0x54>
    2034:	2d 3e 20 26 70       	sub    eax,0x7026203e
    2039:	74 72                	je     20ad <__GNU_EH_FRAME_HDR+0x3d>
    203b:	2b 25 78 3a 20 25    	sub    esp,DWORD PTR [rip+0x25203a78]        # 25205ab9 <_end+0x25201a99>
    2041:	70 2c                	jo     206f <_IO_stdin_used+0x6f>
    2043:	20 76 61             	and    BYTE PTR [rsi+0x61],dh
    2046:	6c                   	ins    BYTE PTR es:[rdi],dx
    2047:	20 3d 20 25 6c 6c    	and    BYTE PTR [rip+0x6c6c2520],bh        # 6c6c456d <_end+0x6c6c054d>
    204d:	78 0a                	js     2059 <_IO_stdin_used+0x59>
    204f:	00 72 61             	add    BYTE PTR [rdx+0x61],dh
    2052:	20 2d 3e 20 26 70    	and    BYTE PTR [rip+0x7026203e],ch        # 70264096 <_end+0x70260076>
    2058:	74 72                	je     20cc <__GNU_EH_FRAME_HDR+0x5c>
    205a:	2b 25 78 3a 20 25    	sub    esp,DWORD PTR [rip+0x25203a78]        # 25205ad8 <_end+0x25201ab8>
    2060:	70 2c                	jo     208e <__GNU_EH_FRAME_HDR+0x1e>
    2062:	20 76 61             	and    BYTE PTR [rsi+0x61],dh
    2065:	6c                   	ins    BYTE PTR es:[rdi],dx
    2066:	20 3d 20 25 6c 6c    	and    BYTE PTR [rip+0x6c6c2520],bh        # 6c6c458c <_end+0x6c6c056c>
    206c:	78 0a                	js     2078 <__GNU_EH_FRAME_HDR+0x8>
	...

Disassembly of section .eh_frame_hdr:

0000000000002070 <__GNU_EH_FRAME_HDR>:
    2070:	01 1b                	add    DWORD PTR [rbx],ebx
    2072:	03 3b                	add    edi,DWORD PTR [rbx]
    2074:	3c 00                	cmp    al,0x0
    2076:	00 00                	add    BYTE PTR [rax],al
    2078:	06                   	(bad)  
    2079:	00 00                	add    BYTE PTR [rax],al
    207b:	00 b0 ef ff ff 70    	add    BYTE PTR [rax+0x70ffffef],dh
    2081:	00 00                	add    BYTE PTR [rax],al
    2083:	00 e0                	add    al,ah
    2085:	ef                   	out    dx,eax
    2086:	ff                   	(bad)  
    2087:	ff 98 00 00 00 00    	call   FWORD PTR [rax+0x0]
    208d:	f0 ff                	lock (bad) 
    208f:	ff b0 00 00 00 20    	push   QWORD PTR [rax+0x20000000]
    2095:	f0 ff                	lock (bad) 
    2097:	ff 58 00             	call   FWORD PTR [rax+0x0]
    209a:	00 00                	add    BYTE PTR [rax],al
    209c:	09 f1                	or     ecx,esi
    209e:	ff                   	(bad)  
    209f:	ff c8                	dec    eax
    20a1:	00 00                	add    BYTE PTR [rax],al
    20a3:	00 f2                	add    dl,dh
    20a5:	f1                   	int1   
    20a6:	ff                   	(bad)  
    20a7:	ff                   	(bad)  
    20a8:	e8                   	.byte 0xe8
    20a9:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .eh_frame:

00000000000020b0 <__FRAME_END__-0xc8>:
    20b0:	14 00                	adc    al,0x0
    20b2:	00 00                	add    BYTE PTR [rax],al
    20b4:	00 00                	add    BYTE PTR [rax],al
    20b6:	00 00                	add    BYTE PTR [rax],al
    20b8:	01 7a 52             	add    DWORD PTR [rdx+0x52],edi
    20bb:	00 01                	add    BYTE PTR [rcx],al
    20bd:	78 10                	js     20cf <__GNU_EH_FRAME_HDR+0x5f>
    20bf:	01 1b                	add    DWORD PTR [rbx],ebx
    20c1:	0c 07                	or     al,0x7
    20c3:	08 90 01 00 00 14    	or     BYTE PTR [rax+0x14000001],dl
    20c9:	00 00                	add    BYTE PTR [rax],al
    20cb:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    20ce:	00 00                	add    BYTE PTR [rax],al
    20d0:	c0 ef ff             	shr    bh,0xff
    20d3:	ff 26                	jmp    QWORD PTR [rsi]
    20d5:	00 00                	add    BYTE PTR [rax],al
    20d7:	00 00                	add    BYTE PTR [rax],al
    20d9:	44 07                	rex.R (bad) 
    20db:	10 00                	adc    BYTE PTR [rax],al
    20dd:	00 00                	add    BYTE PTR [rax],al
    20df:	00 24 00             	add    BYTE PTR [rax+rax*1],ah
    20e2:	00 00                	add    BYTE PTR [rax],al
    20e4:	34 00                	xor    al,0x0
    20e6:	00 00                	add    BYTE PTR [rax],al
    20e8:	38 ef                	cmp    bh,ch
    20ea:	ff                   	(bad)  
    20eb:	ff 30                	push   QWORD PTR [rax]
    20ed:	00 00                	add    BYTE PTR [rax],al
    20ef:	00 00                	add    BYTE PTR [rax],al
    20f1:	0e                   	(bad)  
    20f2:	10 46 0e             	adc    BYTE PTR [rsi+0xe],al
    20f5:	18 4a 0f             	sbb    BYTE PTR [rdx+0xf],cl
    20f8:	0b 77 08             	or     esi,DWORD PTR [rdi+0x8]
    20fb:	80 00 3f             	add    BYTE PTR [rax],0x3f
    20fe:	1a 3a                	sbb    bh,BYTE PTR [rdx]
    2100:	2a 33                	sub    dh,BYTE PTR [rbx]
    2102:	24 22                	and    al,0x22
    2104:	00 00                	add    BYTE PTR [rax],al
    2106:	00 00                	add    BYTE PTR [rax],al
    2108:	14 00                	adc    al,0x0
    210a:	00 00                	add    BYTE PTR [rax],al
    210c:	5c                   	pop    rsp
    210d:	00 00                	add    BYTE PTR [rax],al
    210f:	00 40 ef             	add    BYTE PTR [rax-0x11],al
    2112:	ff                   	(bad)  
    2113:	ff 20                	jmp    QWORD PTR [rax]
	...
    211d:	00 00                	add    BYTE PTR [rax],al
    211f:	00 14 00             	add    BYTE PTR [rax+rax*1],dl
    2122:	00 00                	add    BYTE PTR [rax],al
    2124:	74 00                	je     2126 <__GNU_EH_FRAME_HDR+0xb6>
    2126:	00 00                	add    BYTE PTR [rax],al
    2128:	48 ef                	rex.W out dx,eax
    212a:	ff                   	(bad)  
    212b:	ff 20                	jmp    QWORD PTR [rax]
	...
    2135:	00 00                	add    BYTE PTR [rax],al
    2137:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    213a:	00 00                	add    BYTE PTR [rax],al
    213c:	8c 00                	mov    WORD PTR [rax],es
    213e:	00 00                	add    BYTE PTR [rax],al
    2140:	39 f0                	cmp    eax,esi
    2142:	ff                   	(bad)  
    2143:	ff                   	(bad)  
    2144:	e9 00 00 00 00       	jmp    2149 <__GNU_EH_FRAME_HDR+0xd9>
    2149:	45 0e                	rex.RB (bad) 
    214b:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
    2151:	02 e0                	add    ah,al
    2153:	0c 07                	or     al,0x7
    2155:	08 00                	or     BYTE PTR [rax],al
    2157:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    215a:	00 00                	add    BYTE PTR [rax],al
    215c:	ac                   	lods   al,BYTE PTR ds:[rsi]
    215d:	00 00                	add    BYTE PTR [rax],al
    215f:	00 02                	add    BYTE PTR [rdx],al
    2161:	f1                   	int1   
    2162:	ff                   	(bad)  
    2163:	ff                   	(bad)  
    2164:	7c 00                	jl     2166 <__GNU_EH_FRAME_HDR+0xf6>
    2166:	00 00                	add    BYTE PTR [rax],al
    2168:	00 45 0e             	add    BYTE PTR [rbp+0xe],al
    216b:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
    2171:	02 73 0c             	add    dh,BYTE PTR [rbx+0xc]
    2174:	07                   	(bad)  
    2175:	08 00                	or     BYTE PTR [rax],al
	...

0000000000002178 <__FRAME_END__>:
    2178:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .init_array:

0000000000003da8 <__frame_dummy_init_array_entry>:
    3da8:	70 11                	jo     3dbb <_DYNAMIC+0x3>
    3daa:	00 00                	add    BYTE PTR [rax],al
    3dac:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .fini_array:

0000000000003db0 <__do_global_dtors_aux_fini_array_entry>:
    3db0:	30 11                	xor    BYTE PTR [rcx],dl
    3db2:	00 00                	add    BYTE PTR [rax],al
    3db4:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .dynamic:

0000000000003db8 <_DYNAMIC>:
    3db8:	01 00                	add    DWORD PTR [rax],eax
    3dba:	00 00                	add    BYTE PTR [rax],al
    3dbc:	00 00                	add    BYTE PTR [rax],al
    3dbe:	00 00                	add    BYTE PTR [rax],al
    3dc0:	48 00 00             	rex.W add BYTE PTR [rax],al
    3dc3:	00 00                	add    BYTE PTR [rax],al
    3dc5:	00 00                	add    BYTE PTR [rax],al
    3dc7:	00 0c 00             	add    BYTE PTR [rax+rax*1],cl
    3dca:	00 00                	add    BYTE PTR [rax],al
    3dcc:	00 00                	add    BYTE PTR [rax],al
    3dce:	00 00                	add    BYTE PTR [rax],al
    3dd0:	00 10                	add    BYTE PTR [rax],dl
    3dd2:	00 00                	add    BYTE PTR [rax],al
    3dd4:	00 00                	add    BYTE PTR [rax],al
    3dd6:	00 00                	add    BYTE PTR [rax],al
    3dd8:	0d 00 00 00 00       	or     eax,0x0
    3ddd:	00 00                	add    BYTE PTR [rax],al
    3ddf:	00 e0                	add    al,ah
    3de1:	12 00                	adc    al,BYTE PTR [rax]
    3de3:	00 00                	add    BYTE PTR [rax],al
    3de5:	00 00                	add    BYTE PTR [rax],al
    3de7:	00 19                	add    BYTE PTR [rcx],bl
    3de9:	00 00                	add    BYTE PTR [rax],al
    3deb:	00 00                	add    BYTE PTR [rax],al
    3ded:	00 00                	add    BYTE PTR [rax],al
    3def:	00 a8 3d 00 00 00    	add    BYTE PTR [rax+0x3d],ch
    3df5:	00 00                	add    BYTE PTR [rax],al
    3df7:	00 1b                	add    BYTE PTR [rbx],bl
    3df9:	00 00                	add    BYTE PTR [rax],al
    3dfb:	00 00                	add    BYTE PTR [rax],al
    3dfd:	00 00                	add    BYTE PTR [rax],al
    3dff:	00 08                	add    BYTE PTR [rax],cl
    3e01:	00 00                	add    BYTE PTR [rax],al
    3e03:	00 00                	add    BYTE PTR [rax],al
    3e05:	00 00                	add    BYTE PTR [rax],al
    3e07:	00 1a                	add    BYTE PTR [rdx],bl
    3e09:	00 00                	add    BYTE PTR [rax],al
    3e0b:	00 00                	add    BYTE PTR [rax],al
    3e0d:	00 00                	add    BYTE PTR [rax],al
    3e0f:	00 b0 3d 00 00 00    	add    BYTE PTR [rax+0x3d],dh
    3e15:	00 00                	add    BYTE PTR [rax],al
    3e17:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    3e1a:	00 00                	add    BYTE PTR [rax],al
    3e1c:	00 00                	add    BYTE PTR [rax],al
    3e1e:	00 00                	add    BYTE PTR [rax],al
    3e20:	08 00                	or     BYTE PTR [rax],al
    3e22:	00 00                	add    BYTE PTR [rax],al
    3e24:	00 00                	add    BYTE PTR [rax],al
    3e26:	00 00                	add    BYTE PTR [rax],al
    3e28:	f5                   	cmc    
    3e29:	fe                   	(bad)  
    3e2a:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3e2d:	00 00                	add    BYTE PTR [rax],al
    3e2f:	00 b0 03 00 00 00    	add    BYTE PTR [rax+0x3],dh
    3e35:	00 00                	add    BYTE PTR [rax],al
    3e37:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 3e3d <_DYNAMIC+0x85>
    3e3d:	00 00                	add    BYTE PTR [rax],al
    3e3f:	00 d0                	add    al,dl
    3e41:	04 00                	add    al,0x0
    3e43:	00 00                	add    BYTE PTR [rax],al
    3e45:	00 00                	add    BYTE PTR [rax],al
    3e47:	00 06                	add    BYTE PTR [rsi],al
    3e49:	00 00                	add    BYTE PTR [rax],al
    3e4b:	00 00                	add    BYTE PTR [rax],al
    3e4d:	00 00                	add    BYTE PTR [rax],al
    3e4f:	00 e0                	add    al,ah
    3e51:	03 00                	add    eax,DWORD PTR [rax]
    3e53:	00 00                	add    BYTE PTR [rax],al
    3e55:	00 00                	add    BYTE PTR [rax],al
    3e57:	00 0a                	add    BYTE PTR [rdx],cl
    3e59:	00 00                	add    BYTE PTR [rax],al
    3e5b:	00 00                	add    BYTE PTR [rax],al
    3e5d:	00 00                	add    BYTE PTR [rax],al
    3e5f:	00 b8 00 00 00 00    	add    BYTE PTR [rax+0x0],bh
    3e65:	00 00                	add    BYTE PTR [rax],al
    3e67:	00 0b                	add    BYTE PTR [rbx],cl
    3e69:	00 00                	add    BYTE PTR [rax],al
    3e6b:	00 00                	add    BYTE PTR [rax],al
    3e6d:	00 00                	add    BYTE PTR [rax],al
    3e6f:	00 18                	add    BYTE PTR [rax],bl
    3e71:	00 00                	add    BYTE PTR [rax],al
    3e73:	00 00                	add    BYTE PTR [rax],al
    3e75:	00 00                	add    BYTE PTR [rax],al
    3e77:	00 15 00 00 00 00    	add    BYTE PTR [rip+0x0],dl        # 3e7d <_DYNAMIC+0xc5>
	...
    3e85:	00 00                	add    BYTE PTR [rax],al
    3e87:	00 03                	add    BYTE PTR [rbx],al
    3e89:	00 00                	add    BYTE PTR [rax],al
    3e8b:	00 00                	add    BYTE PTR [rax],al
    3e8d:	00 00                	add    BYTE PTR [rax],al
    3e8f:	00 a8 3f 00 00 00    	add    BYTE PTR [rax+0x3f],ch
    3e95:	00 00                	add    BYTE PTR [rax],al
    3e97:	00 02                	add    BYTE PTR [rdx],al
    3e99:	00 00                	add    BYTE PTR [rax],al
    3e9b:	00 00                	add    BYTE PTR [rax],al
    3e9d:	00 00                	add    BYTE PTR [rax],al
    3e9f:	00 30                	add    BYTE PTR [rax],dh
    3ea1:	00 00                	add    BYTE PTR [rax],al
    3ea3:	00 00                	add    BYTE PTR [rax],al
    3ea5:	00 00                	add    BYTE PTR [rax],al
    3ea7:	00 14 00             	add    BYTE PTR [rax+rax*1],dl
    3eaa:	00 00                	add    BYTE PTR [rax],al
    3eac:	00 00                	add    BYTE PTR [rax],al
    3eae:	00 00                	add    BYTE PTR [rax],al
    3eb0:	07                   	(bad)  
    3eb1:	00 00                	add    BYTE PTR [rax],al
    3eb3:	00 00                	add    BYTE PTR [rax],al
    3eb5:	00 00                	add    BYTE PTR [rax],al
    3eb7:	00 17                	add    BYTE PTR [rdi],dl
    3eb9:	00 00                	add    BYTE PTR [rax],al
    3ebb:	00 00                	add    BYTE PTR [rax],al
    3ebd:	00 00                	add    BYTE PTR [rax],al
    3ebf:	00 d0                	add    al,dl
    3ec1:	06                   	(bad)  
    3ec2:	00 00                	add    BYTE PTR [rax],al
    3ec4:	00 00                	add    BYTE PTR [rax],al
    3ec6:	00 00                	add    BYTE PTR [rax],al
    3ec8:	07                   	(bad)  
    3ec9:	00 00                	add    BYTE PTR [rax],al
    3ecb:	00 00                	add    BYTE PTR [rax],al
    3ecd:	00 00                	add    BYTE PTR [rax],al
    3ecf:	00 e0                	add    al,ah
    3ed1:	05 00 00 00 00       	add    eax,0x0
    3ed6:	00 00                	add    BYTE PTR [rax],al
    3ed8:	08 00                	or     BYTE PTR [rax],al
    3eda:	00 00                	add    BYTE PTR [rax],al
    3edc:	00 00                	add    BYTE PTR [rax],al
    3ede:	00 00                	add    BYTE PTR [rax],al
    3ee0:	f0 00 00             	lock add BYTE PTR [rax],al
    3ee3:	00 00                	add    BYTE PTR [rax],al
    3ee5:	00 00                	add    BYTE PTR [rax],al
    3ee7:	00 09                	add    BYTE PTR [rcx],cl
    3ee9:	00 00                	add    BYTE PTR [rax],al
    3eeb:	00 00                	add    BYTE PTR [rax],al
    3eed:	00 00                	add    BYTE PTR [rax],al
    3eef:	00 18                	add    BYTE PTR [rax],bl
    3ef1:	00 00                	add    BYTE PTR [rax],al
    3ef3:	00 00                	add    BYTE PTR [rax],al
    3ef5:	00 00                	add    BYTE PTR [rax],al
    3ef7:	00 1e                	add    BYTE PTR [rsi],bl
    3ef9:	00 00                	add    BYTE PTR [rax],al
    3efb:	00 00                	add    BYTE PTR [rax],al
    3efd:	00 00                	add    BYTE PTR [rax],al
    3eff:	00 08                	add    BYTE PTR [rax],cl
    3f01:	00 00                	add    BYTE PTR [rax],al
    3f03:	00 00                	add    BYTE PTR [rax],al
    3f05:	00 00                	add    BYTE PTR [rax],al
    3f07:	00 fb                	add    bl,bh
    3f09:	ff                   	(bad)  
    3f0a:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f0d:	00 00                	add    BYTE PTR [rax],al
    3f0f:	00 01                	add    BYTE PTR [rcx],al
    3f11:	00 00                	add    BYTE PTR [rax],al
    3f13:	08 00                	or     BYTE PTR [rax],al
    3f15:	00 00                	add    BYTE PTR [rax],al
    3f17:	00 fe                	add    dh,bh
    3f19:	ff                   	(bad)  
    3f1a:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f1d:	00 00                	add    BYTE PTR [rax],al
    3f1f:	00 a0 05 00 00 00    	add    BYTE PTR [rax+0x5],ah
    3f25:	00 00                	add    BYTE PTR [rax],al
    3f27:	00 ff                	add    bh,bh
    3f29:	ff                   	(bad)  
    3f2a:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f2d:	00 00                	add    BYTE PTR [rax],al
    3f2f:	00 01                	add    BYTE PTR [rcx],al
    3f31:	00 00                	add    BYTE PTR [rax],al
    3f33:	00 00                	add    BYTE PTR [rax],al
    3f35:	00 00                	add    BYTE PTR [rax],al
    3f37:	00 f0                	add    al,dh
    3f39:	ff                   	(bad)  
    3f3a:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f3d:	00 00                	add    BYTE PTR [rax],al
    3f3f:	00 88 05 00 00 00    	add    BYTE PTR [rax+0x5],cl
    3f45:	00 00                	add    BYTE PTR [rax],al
    3f47:	00 f9                	add    cl,bh
    3f49:	ff                   	(bad)  
    3f4a:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f4d:	00 00                	add    BYTE PTR [rax],al
    3f4f:	00 03                	add    BYTE PTR [rbx],al
	...

Disassembly of section .got:

0000000000003fa8 <_GLOBAL_OFFSET_TABLE_>:
    3fa8:	b8 3d 00 00 00       	mov    eax,0x3d
	...
    3fbd:	00 00                	add    BYTE PTR [rax],al
    3fbf:	00 30                	add    BYTE PTR [rax],dh
    3fc1:	10 00                	adc    BYTE PTR [rax],al
    3fc3:	00 00                	add    BYTE PTR [rax],al
    3fc5:	00 00                	add    BYTE PTR [rax],al
    3fc7:	00 40 10             	add    BYTE PTR [rax+0x10],al
	...

Disassembly of section .data:

0000000000004000 <__data_start>:
	...

0000000000004008 <__dso_handle>:
    4008:	08 40 00             	or     BYTE PTR [rax+0x0],al
    400b:	00 00                	add    BYTE PTR [rax],al
    400d:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .bss:

0000000000004010 <stdout@GLIBC_2.2.5>:
	...

0000000000004018 <completed.0>:
	...

Disassembly of section .comment:

0000000000000000 <.comment>:
   0:	47                   	rex.RXB
   1:	43                   	rex.XB
   2:	43 3a 20             	rex.XB cmp spl,BYTE PTR [r8]
   5:	28 55 62             	sub    BYTE PTR [rbp+0x62],dl
   8:	75 6e                	jne    78 <__abi_tag-0x314>
   a:	74 75                	je     81 <__abi_tag-0x30b>
   c:	20 31                	and    BYTE PTR [rcx],dh
   e:	31 2e                	xor    DWORD PTR [rsi],ebp
  10:	33 2e                	xor    ebp,DWORD PTR [rsi]
  12:	30 2d 31 75 62 75    	xor    BYTE PTR [rip+0x75627531],ch        # 75627549 <_end+0x75623529>
  18:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  19:	74 75                	je     90 <__abi_tag-0x2fc>
  1b:	31 7e 32             	xor    DWORD PTR [rsi+0x32],edi
  1e:	32 2e                	xor    ch,BYTE PTR [rsi]
  20:	30 34 29             	xor    BYTE PTR [rcx+rbp*1],dh
  23:	20 31                	and    BYTE PTR [rcx],dh
  25:	31 2e                	xor    DWORD PTR [rsi],ebp
  27:	33 2e                	xor    ebp,DWORD PTR [rsi]
  29:	30 00                	xor    BYTE PTR [rax],al
