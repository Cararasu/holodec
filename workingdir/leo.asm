
leo:     Dateiformat elf64-x86-64


Disassembly of section .init:

0000000000400ec8 <_init>:
  400ec8:	48 83 ec 08          	sub    $0x8,%rsp
  400ecc:	48 8b 05 25 31 20 00 	mov    0x203125(%rip),%rax        # 603ff8 <_fini+0x2018e4>
  400ed3:	48 85 c0             	test   %rax,%rax
  400ed6:	74 05                	je     400edd <_init+0x15>
  400ed8:	e8 93 02 00 00       	callq  401170 <__gmon_start__@plt>
  400edd:	48 83 c4 08          	add    $0x8,%rsp
  400ee1:	c3                   	retq   

Disassembly of section .plt:

0000000000400ef0 <curl_global_cleanup@plt-0x10>:
  400ef0:	ff 35 12 31 20 00    	pushq  0x203112(%rip)        # 604008 <_fini+0x2018f4>
  400ef6:	ff 25 14 31 20 00    	jmpq   *0x203114(%rip)        # 604010 <_fini+0x2018fc>
  400efc:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000400f00 <curl_global_cleanup@plt>:
  400f00:	ff 25 12 31 20 00    	jmpq   *0x203112(%rip)        # 604018 <_fini+0x201904>
  400f06:	68 00 00 00 00       	pushq  $0x0
  400f0b:	e9 e0 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400f10 <syslog@plt>:
  400f10:	ff 25 0a 31 20 00    	jmpq   *0x20310a(%rip)        # 604020 <_fini+0x20190c>
  400f16:	68 01 00 00 00       	pushq  $0x1
  400f1b:	e9 d0 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400f20 <popen@plt>:
  400f20:	ff 25 02 31 20 00    	jmpq   *0x203102(%rip)        # 604028 <_fini+0x201914>
  400f26:	68 02 00 00 00       	pushq  $0x2
  400f2b:	e9 c0 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400f30 <write@plt>:
  400f30:	ff 25 fa 30 20 00    	jmpq   *0x2030fa(%rip)        # 604030 <_fini+0x20191c>
  400f36:	68 03 00 00 00       	pushq  $0x3
  400f3b:	e9 b0 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400f40 <curl_easy_getinfo@plt>:
  400f40:	ff 25 f2 30 20 00    	jmpq   *0x2030f2(%rip)        # 604038 <_fini+0x201924>
  400f46:	68 04 00 00 00       	pushq  $0x4
  400f4b:	e9 a0 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400f50 <unlink@plt>:
  400f50:	ff 25 ea 30 20 00    	jmpq   *0x2030ea(%rip)        # 604040 <_fini+0x20192c>
  400f56:	68 05 00 00 00       	pushq  $0x5
  400f5b:	e9 90 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400f60 <posix_memalign@plt>:
  400f60:	ff 25 e2 30 20 00    	jmpq   *0x2030e2(%rip)        # 604048 <_fini+0x201934>
  400f66:	68 06 00 00 00       	pushq  $0x6
  400f6b:	e9 80 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400f70 <strncpy@plt>:
  400f70:	ff 25 da 30 20 00    	jmpq   *0x2030da(%rip)        # 604050 <_fini+0x20193c>
  400f76:	68 07 00 00 00       	pushq  $0x7
  400f7b:	e9 70 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400f80 <memset@plt>:
  400f80:	ff 25 d2 30 20 00    	jmpq   *0x2030d2(%rip)        # 604058 <_fini+0x201944>
  400f86:	68 08 00 00 00       	pushq  $0x8
  400f8b:	e9 60 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400f90 <sysconf@plt>:
  400f90:	ff 25 ca 30 20 00    	jmpq   *0x2030ca(%rip)        # 604060 <_fini+0x20194c>
  400f96:	68 09 00 00 00       	pushq  $0x9
  400f9b:	e9 50 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400fa0 <creat@plt>:
  400fa0:	ff 25 c2 30 20 00    	jmpq   *0x2030c2(%rip)        # 604068 <_fini+0x201954>
  400fa6:	68 0a 00 00 00       	pushq  $0xa
  400fab:	e9 40 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400fb0 <sleep@plt>:
  400fb0:	ff 25 ba 30 20 00    	jmpq   *0x2030ba(%rip)        # 604070 <_fini+0x20195c>
  400fb6:	68 0b 00 00 00       	pushq  $0xb
  400fbb:	e9 30 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400fc0 <memcpy@plt>:
  400fc0:	ff 25 b2 30 20 00    	jmpq   *0x2030b2(%rip)        # 604078 <_fini+0x201964>
  400fc6:	68 0c 00 00 00       	pushq  $0xc
  400fcb:	e9 20 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400fd0 <system@plt>:
  400fd0:	ff 25 aa 30 20 00    	jmpq   *0x2030aa(%rip)        # 604080 <_fini+0x20196c>
  400fd6:	68 0d 00 00 00       	pushq  $0xd
  400fdb:	e9 10 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400fe0 <openlog@plt>:
  400fe0:	ff 25 a2 30 20 00    	jmpq   *0x2030a2(%rip)        # 604088 <_fini+0x201974>
  400fe6:	68 0e 00 00 00       	pushq  $0xe
  400feb:	e9 00 ff ff ff       	jmpq   400ef0 <_init+0x28>

0000000000400ff0 <strcpy@plt>:
  400ff0:	ff 25 9a 30 20 00    	jmpq   *0x20309a(%rip)        # 604090 <_fini+0x20197c>
  400ff6:	68 0f 00 00 00       	pushq  $0xf
  400ffb:	e9 f0 fe ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401000 <closelog@plt>:
  401000:	ff 25 92 30 20 00    	jmpq   *0x203092(%rip)        # 604098 <_fini+0x201984>
  401006:	68 10 00 00 00       	pushq  $0x10
  40100b:	e9 e0 fe ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401010 <curl_easy_init@plt>:
  401010:	ff 25 8a 30 20 00    	jmpq   *0x20308a(%rip)        # 6040a0 <_fini+0x20198c>
  401016:	68 11 00 00 00       	pushq  $0x11
  40101b:	e9 d0 fe ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401020 <fflush@plt>:
  401020:	ff 25 82 30 20 00    	jmpq   *0x203082(%rip)        # 6040a8 <_fini+0x201994>
  401026:	68 12 00 00 00       	pushq  $0x12
  40102b:	e9 c0 fe ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401030 <free@plt>:
  401030:	ff 25 7a 30 20 00    	jmpq   *0x20307a(%rip)        # 6040b0 <_fini+0x20199c>
  401036:	68 13 00 00 00       	pushq  $0x13
  40103b:	e9 b0 fe ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401040 <exit@plt>:
  401040:	ff 25 72 30 20 00    	jmpq   *0x203072(%rip)        # 6040b8 <_fini+0x2019a4>
  401046:	68 14 00 00 00       	pushq  $0x14
  40104b:	e9 a0 fe ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401050 <malloc@plt>:
  401050:	ff 25 6a 30 20 00    	jmpq   *0x20306a(%rip)        # 6040c0 <_fini+0x2019ac>
  401056:	68 15 00 00 00       	pushq  $0x15
  40105b:	e9 90 fe ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401060 <strcmp@plt>:
  401060:	ff 25 62 30 20 00    	jmpq   *0x203062(%rip)        # 6040c8 <_fini+0x2019b4>
  401066:	68 16 00 00 00       	pushq  $0x16
  40106b:	e9 80 fe ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401070 <curl_easy_setopt@plt>:
  401070:	ff 25 5a 30 20 00    	jmpq   *0x20305a(%rip)        # 6040d0 <_fini+0x2019bc>
  401076:	68 17 00 00 00       	pushq  $0x17
  40107b:	e9 70 fe ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401080 <pclose@plt>:
  401080:	ff 25 52 30 20 00    	jmpq   *0x203052(%rip)        # 6040d8 <_fini+0x2019c4>
  401086:	68 18 00 00 00       	pushq  $0x18
  40108b:	e9 60 fe ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401090 <read@plt>:
  401090:	ff 25 4a 30 20 00    	jmpq   *0x20304a(%rip)        # 6040e0 <_fini+0x2019cc>
  401096:	68 19 00 00 00       	pushq  $0x19
  40109b:	e9 50 fe ff ff       	jmpq   400ef0 <_init+0x28>

00000000004010a0 <chdir@plt>:
  4010a0:	ff 25 42 30 20 00    	jmpq   *0x203042(%rip)        # 6040e8 <_fini+0x2019d4>
  4010a6:	68 1a 00 00 00       	pushq  $0x1a
  4010ab:	e9 40 fe ff ff       	jmpq   400ef0 <_init+0x28>

00000000004010b0 <curl_easy_cleanup@plt>:
  4010b0:	ff 25 3a 30 20 00    	jmpq   *0x20303a(%rip)        # 6040f0 <_fini+0x2019dc>
  4010b6:	68 1b 00 00 00       	pushq  $0x1b
  4010bb:	e9 30 fe ff ff       	jmpq   400ef0 <_init+0x28>

00000000004010c0 <fread@plt>:
  4010c0:	ff 25 32 30 20 00    	jmpq   *0x203032(%rip)        # 6040f8 <_fini+0x2019e4>
  4010c6:	68 1c 00 00 00       	pushq  $0x1c
  4010cb:	e9 20 fe ff ff       	jmpq   400ef0 <_init+0x28>

00000000004010d0 <puts@plt>:
  4010d0:	ff 25 2a 30 20 00    	jmpq   *0x20302a(%rip)        # 604100 <_fini+0x2019ec>
  4010d6:	68 1d 00 00 00       	pushq  $0x1d
  4010db:	e9 10 fe ff ff       	jmpq   400ef0 <_init+0x28>

00000000004010e0 <feof@plt>:
  4010e0:	ff 25 22 30 20 00    	jmpq   *0x203022(%rip)        # 604108 <_fini+0x2019f4>
  4010e6:	68 1e 00 00 00       	pushq  $0x1e
  4010eb:	e9 00 fe ff ff       	jmpq   400ef0 <_init+0x28>

00000000004010f0 <curl_easy_perform@plt>:
  4010f0:	ff 25 1a 30 20 00    	jmpq   *0x20301a(%rip)        # 604110 <_fini+0x2019fc>
  4010f6:	68 1f 00 00 00       	pushq  $0x1f
  4010fb:	e9 f0 fd ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401100 <mprotect@plt>:
  401100:	ff 25 12 30 20 00    	jmpq   *0x203012(%rip)        # 604118 <_fini+0x201a04>
  401106:	68 20 00 00 00       	pushq  $0x20
  40110b:	e9 e0 fd ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401110 <curl_easy_strerror@plt>:
  401110:	ff 25 0a 30 20 00    	jmpq   *0x20300a(%rip)        # 604120 <_fini+0x201a0c>
  401116:	68 21 00 00 00       	pushq  $0x21
  40111b:	e9 d0 fd ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401120 <__xpg_basename@plt>:
  401120:	ff 25 02 30 20 00    	jmpq   *0x203002(%rip)        # 604128 <_fini+0x201a14>
  401126:	68 22 00 00 00       	pushq  $0x22
  40112b:	e9 c0 fd ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401130 <strcat@plt>:
  401130:	ff 25 fa 2f 20 00    	jmpq   *0x202ffa(%rip)        # 604130 <_fini+0x201a1c>
  401136:	68 23 00 00 00       	pushq  $0x23
  40113b:	e9 b0 fd ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401140 <umask@plt>:
  401140:	ff 25 f2 2f 20 00    	jmpq   *0x202ff2(%rip)        # 604138 <_fini+0x201a24>
  401146:	68 24 00 00 00       	pushq  $0x24
  40114b:	e9 a0 fd ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401150 <__libc_start_main@plt>:
  401150:	ff 25 ea 2f 20 00    	jmpq   *0x202fea(%rip)        # 604140 <_fini+0x201a2c>
  401156:	68 25 00 00 00       	pushq  $0x25
  40115b:	e9 90 fd ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401160 <mktemp@plt>:
  401160:	ff 25 e2 2f 20 00    	jmpq   *0x202fe2(%rip)        # 604148 <_fini+0x201a34>
  401166:	68 26 00 00 00       	pushq  $0x26
  40116b:	e9 80 fd ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401170 <__gmon_start__@plt>:
  401170:	ff 25 da 2f 20 00    	jmpq   *0x202fda(%rip)        # 604150 <_fini+0x201a3c>
  401176:	68 27 00 00 00       	pushq  $0x27
  40117b:	e9 70 fd ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401180 <curl_global_init@plt>:
  401180:	ff 25 d2 2f 20 00    	jmpq   *0x202fd2(%rip)        # 604158 <_fini+0x201a44>
  401186:	68 28 00 00 00       	pushq  $0x28
  40118b:	e9 60 fd ff ff       	jmpq   400ef0 <_init+0x28>

0000000000401190 <close@plt>:
  401190:	ff 25 ca 2f 20 00    	jmpq   *0x202fca(%rip)        # 604160 <_fini+0x201a4c>
  401196:	68 29 00 00 00       	pushq  $0x29
  40119b:	e9 50 fd ff ff       	jmpq   400ef0 <_init+0x28>

Disassembly of section .text:

00000000004011a0 <.text>:
  4011a0:	31 ed                	xor    %ebp,%ebp
  4011a2:	49 89 d1             	mov    %rdx,%r9
  4011a5:	5e                   	pop    %rsi
  4011a6:	48 89 e2             	mov    %rsp,%rdx
  4011a9:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  4011ad:	50                   	push   %rax
  4011ae:	54                   	push   %rsp
  4011af:	49 c7 c0 10 27 40 00 	mov    $0x402710,%r8
  4011b6:	48 c7 c1 a0 26 40 00 	mov    $0x4026a0,%rcx
  4011bd:	48 c7 c7 7f 1c 40 00 	mov    $0x401c7f,%rdi
  4011c4:	e8 87 ff ff ff       	callq  401150 <__libc_start_main@plt>
  4011c9:	f4                   	hlt    
  4011ca:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  4011d0:	b8 7f 41 60 00       	mov    $0x60417f,%eax
  4011d5:	55                   	push   %rbp
  4011d6:	48 2d 78 41 60 00    	sub    $0x604178,%rax
  4011dc:	48 83 f8 0e          	cmp    $0xe,%rax
  4011e0:	48 89 e5             	mov    %rsp,%rbp
  4011e3:	77 02                	ja     4011e7 <close@plt+0x57>
  4011e5:	5d                   	pop    %rbp
  4011e6:	c3                   	retq   
  4011e7:	b8 00 00 00 00       	mov    $0x0,%eax
  4011ec:	48 85 c0             	test   %rax,%rax
  4011ef:	74 f4                	je     4011e5 <close@plt+0x55>
  4011f1:	5d                   	pop    %rbp
  4011f2:	bf 78 41 60 00       	mov    $0x604178,%edi
  4011f7:	ff e0                	jmpq   *%rax
  4011f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  401200:	b8 78 41 60 00       	mov    $0x604178,%eax
  401205:	55                   	push   %rbp
  401206:	48 2d 78 41 60 00    	sub    $0x604178,%rax
  40120c:	48 c1 f8 03          	sar    $0x3,%rax
  401210:	48 89 e5             	mov    %rsp,%rbp
  401213:	48 89 c2             	mov    %rax,%rdx
  401216:	48 c1 ea 3f          	shr    $0x3f,%rdx
  40121a:	48 01 d0             	add    %rdx,%rax
  40121d:	48 d1 f8             	sar    %rax
  401220:	75 02                	jne    401224 <close@plt+0x94>
  401222:	5d                   	pop    %rbp
  401223:	c3                   	retq   
  401224:	ba 00 00 00 00       	mov    $0x0,%edx
  401229:	48 85 d2             	test   %rdx,%rdx
  40122c:	74 f4                	je     401222 <close@plt+0x92>
  40122e:	5d                   	pop    %rbp
  40122f:	48 89 c6             	mov    %rax,%rsi
  401232:	bf 78 41 60 00       	mov    $0x604178,%edi
  401237:	ff e2                	jmpq   *%rdx
  401239:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  401240:	80 3d 41 2f 20 00 00 	cmpb   $0x0,0x202f41(%rip)        # 604188 <stdout+0x8>
  401247:	75 11                	jne    40125a <close@plt+0xca>
  401249:	55                   	push   %rbp
  40124a:	48 89 e5             	mov    %rsp,%rbp
  40124d:	e8 7e ff ff ff       	callq  4011d0 <close@plt+0x40>
  401252:	5d                   	pop    %rbp
  401253:	c6 05 2e 2f 20 00 01 	movb   $0x1,0x202f2e(%rip)        # 604188 <stdout+0x8>
  40125a:	f3 c3                	repz retq 
  40125c:	0f 1f 40 00          	nopl   0x0(%rax)
  401260:	48 83 3d a8 2b 20 00 	cmpq   $0x0,0x202ba8(%rip)        # 603e10 <_fini+0x2016fc>
  401267:	00 
  401268:	74 1e                	je     401288 <close@plt+0xf8>
  40126a:	b8 00 00 00 00       	mov    $0x0,%eax
  40126f:	48 85 c0             	test   %rax,%rax
  401272:	74 14                	je     401288 <close@plt+0xf8>
  401274:	55                   	push   %rbp
  401275:	bf 10 3e 60 00       	mov    $0x603e10,%edi
  40127a:	48 89 e5             	mov    %rsp,%rbp
  40127d:	ff d0                	callq  *%rax
  40127f:	5d                   	pop    %rbp
  401280:	e9 7b ff ff ff       	jmpq   401200 <close@plt+0x70>
  401285:	0f 1f 00             	nopl   (%rax)
  401288:	e9 73 ff ff ff       	jmpq   401200 <close@plt+0x70>
  40128d:	55                   	push   %rbp
  40128e:	48 89 e5             	mov    %rsp,%rbp
  401291:	5d                   	pop    %rbp
  401292:	c3                   	retq   
  401293:	55                   	push   %rbp
  401294:	48 89 e5             	mov    %rsp,%rbp
  401297:	5d                   	pop    %rbp
  401298:	c3                   	retq   
  401299:	55                   	push   %rbp
  40129a:	48 89 e5             	mov    %rsp,%rbp
  40129d:	5d                   	pop    %rbp
  40129e:	c3                   	retq   
  40129f:	55                   	push   %rbp
  4012a0:	48 89 e5             	mov    %rsp,%rbp
  4012a3:	5d                   	pop    %rbp
  4012a4:	c3                   	retq   
  4012a5:	55                   	push   %rbp
  4012a6:	48 89 e5             	mov    %rsp,%rbp
  4012a9:	5d                   	pop    %rbp
  4012aa:	c3                   	retq   
  4012ab:	55                   	push   %rbp
  4012ac:	48 89 e5             	mov    %rsp,%rbp
  4012af:	5d                   	pop    %rbp
  4012b0:	c3                   	retq   
  4012b1:	55                   	push   %rbp
  4012b2:	48 89 e5             	mov    %rsp,%rbp
  4012b5:	5d                   	pop    %rbp
  4012b6:	c3                   	retq   
  4012b7:	55                   	push   %rbp
  4012b8:	48 89 e5             	mov    %rsp,%rbp
  4012bb:	5d                   	pop    %rbp
  4012bc:	c3                   	retq   
  4012bd:	55                   	push   %rbp
  4012be:	48 89 e5             	mov    %rsp,%rbp
  4012c1:	5d                   	pop    %rbp
  4012c2:	c3                   	retq   
  4012c3:	55                   	push   %rbp
  4012c4:	48 89 e5             	mov    %rsp,%rbp
  4012c7:	5d                   	pop    %rbp
  4012c8:	c3                   	retq   
  4012c9:	55                   	push   %rbp
  4012ca:	48 89 e5             	mov    %rsp,%rbp
  4012cd:	5d                   	pop    %rbp
  4012ce:	c3                   	retq   
  4012cf:	55                   	push   %rbp
  4012d0:	48 89 e5             	mov    %rsp,%rbp
  4012d3:	5d                   	pop    %rbp
  4012d4:	c3                   	retq   
  4012d5:	55                   	push   %rbp
  4012d6:	48 89 e5             	mov    %rsp,%rbp
  4012d9:	5d                   	pop    %rbp
  4012da:	c3                   	retq   
  4012db:	55                   	push   %rbp
  4012dc:	48 89 e5             	mov    %rsp,%rbp
  4012df:	5d                   	pop    %rbp
  4012e0:	c3                   	retq   
  4012e1:	55                   	push   %rbp
  4012e2:	48 89 e5             	mov    %rsp,%rbp
  4012e5:	5d                   	pop    %rbp
  4012e6:	c3                   	retq   
  4012e7:	55                   	push   %rbp
  4012e8:	48 89 e5             	mov    %rsp,%rbp
  4012eb:	5d                   	pop    %rbp
  4012ec:	c3                   	retq   
  4012ed:	55                   	push   %rbp
  4012ee:	48 89 e5             	mov    %rsp,%rbp
  4012f1:	5d                   	pop    %rbp
  4012f2:	c3                   	retq   
  4012f3:	55                   	push   %rbp
  4012f4:	48 89 e5             	mov    %rsp,%rbp
  4012f7:	5d                   	pop    %rbp
  4012f8:	c3                   	retq   
  4012f9:	55                   	push   %rbp
  4012fa:	48 89 e5             	mov    %rsp,%rbp
  4012fd:	5d                   	pop    %rbp
  4012fe:	c3                   	retq   
  4012ff:	55                   	push   %rbp
  401300:	48 89 e5             	mov    %rsp,%rbp
  401303:	5d                   	pop    %rbp
  401304:	c3                   	retq   
  401305:	55                   	push   %rbp
  401306:	48 89 e5             	mov    %rsp,%rbp
  401309:	5d                   	pop    %rbp
  40130a:	c3                   	retq   
  40130b:	55                   	push   %rbp
  40130c:	48 89 e5             	mov    %rsp,%rbp
  40130f:	5d                   	pop    %rbp
  401310:	c3                   	retq   
  401311:	55                   	push   %rbp
  401312:	48 89 e5             	mov    %rsp,%rbp
  401315:	5d                   	pop    %rbp
  401316:	c3                   	retq   
  401317:	55                   	push   %rbp
  401318:	48 89 e5             	mov    %rsp,%rbp
  40131b:	5d                   	pop    %rbp
  40131c:	c3                   	retq   
  40131d:	55                   	push   %rbp
  40131e:	48 89 e5             	mov    %rsp,%rbp
  401321:	48 83 ec 30          	sub    $0x30,%rsp
  401325:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  401329:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  40132d:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  401331:	48 89 4d d0          	mov    %rcx,-0x30(%rbp)
  401335:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  401339:	48 0f af 45 d8       	imul   -0x28(%rbp),%rax
  40133e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  401342:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  401346:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  40134a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40134e:	48 8b 50 08          	mov    0x8(%rax),%rdx
  401352:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  401356:	48 8b 40 10          	mov    0x10(%rax),%rax
  40135a:	48 29 c2             	sub    %rax,%rdx
  40135d:	48 89 d0             	mov    %rdx,%rax
  401360:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
  401364:	73 11                	jae    401377 <close@plt+0x1e7>
  401366:	bf 28 27 40 00       	mov    $0x402728,%edi
  40136b:	e8 60 fd ff ff       	callq  4010d0 <puts@plt>
  401370:	b8 00 00 00 00       	mov    $0x0,%eax
  401375:	eb 56                	jmp    4013cd <close@plt+0x23d>
  401377:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40137b:	48 8b 10             	mov    (%rax),%rdx
  40137e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  401382:	48 8b 40 10          	mov    0x10(%rax),%rax
  401386:	48 8d 0c 02          	lea    (%rdx,%rax,1),%rcx
  40138a:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  40138e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401392:	48 89 c6             	mov    %rax,%rsi
  401395:	48 89 cf             	mov    %rcx,%rdi
  401398:	e8 23 fc ff ff       	callq  400fc0 <memcpy@plt>
  40139d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4013a1:	48 8b 50 10          	mov    0x10(%rax),%rdx
  4013a5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4013a9:	48 01 c2             	add    %rax,%rdx
  4013ac:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4013b0:	48 89 50 10          	mov    %rdx,0x10(%rax)
  4013b4:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4013b8:	48 8b 10             	mov    (%rax),%rdx
  4013bb:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4013bf:	48 8b 40 10          	mov    0x10(%rax),%rax
  4013c3:	48 01 d0             	add    %rdx,%rax
  4013c6:	c6 00 00             	movb   $0x0,(%rax)
  4013c9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4013cd:	c9                   	leaveq 
  4013ce:	c3                   	retq   
  4013cf:	55                   	push   %rbp
  4013d0:	48 89 e5             	mov    %rsp,%rbp
  4013d3:	53                   	push   %rbx
  4013d4:	48 81 ec 78 01 00 00 	sub    $0x178,%rsp
  4013db:	89 bd 8c fe ff ff    	mov    %edi,-0x174(%rbp)
  4013e1:	48 89 b5 80 fe ff ff 	mov    %rsi,-0x180(%rbp)
  4013e8:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%rbp)
  4013ef:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)
  4013f6:	c6 85 b0 fe ff ff 6d 	movb   $0x6d,-0x150(%rbp)
  4013fd:	c6 85 b1 fe ff ff 6f 	movb   $0x6f,-0x14f(%rbp)
  401404:	c6 85 b2 fe ff ff 64 	movb   $0x64,-0x14e(%rbp)
  40140b:	c6 85 b3 fe ff ff 75 	movb   $0x75,-0x14d(%rbp)
  401412:	c6 85 b4 fe ff ff 6c 	movb   $0x6c,-0x14c(%rbp)
  401419:	c6 85 b5 fe ff ff 65 	movb   $0x65,-0x14b(%rbp)
  401420:	c6 85 b6 fe ff ff 20 	movb   $0x20,-0x14a(%rbp)
  401427:	c6 85 b7 fe ff ff 6e 	movb   $0x6e,-0x149(%rbp)
  40142e:	c6 85 b8 fe ff ff 6f 	movb   $0x6f,-0x148(%rbp)
  401435:	c6 85 b9 fe ff ff 74 	movb   $0x74,-0x147(%rbp)
  40143c:	c6 85 ba fe ff ff 20 	movb   $0x20,-0x146(%rbp)
  401443:	c6 85 bb fe ff ff 66 	movb   $0x66,-0x145(%rbp)
  40144a:	c6 85 bc fe ff ff 6f 	movb   $0x6f,-0x144(%rbp)
  401451:	c6 85 bd fe ff ff 75 	movb   $0x75,-0x143(%rbp)
  401458:	c6 85 be fe ff ff 6e 	movb   $0x6e,-0x142(%rbp)
  40145f:	c6 85 bf fe ff ff 64 	movb   $0x64,-0x141(%rbp)
  401466:	c6 85 c0 fe ff ff 00 	movb   $0x0,-0x140(%rbp)
  40146d:	c6 85 90 fe ff ff 6d 	movb   $0x6d,-0x170(%rbp)
  401474:	c6 85 91 fe ff ff 70 	movb   $0x70,-0x16f(%rbp)
  40147b:	c6 85 92 fe ff ff 72 	movb   $0x72,-0x16e(%rbp)
  401482:	c6 85 93 fe ff ff 6f 	movb   $0x6f,-0x16d(%rbp)
  401489:	c6 85 94 fe ff ff 74 	movb   $0x74,-0x16c(%rbp)
  401490:	c6 85 95 fe ff ff 65 	movb   $0x65,-0x16b(%rbp)
  401497:	c6 85 96 fe ff ff 63 	movb   $0x63,-0x16a(%rbp)
  40149e:	c6 85 97 fe ff ff 74 	movb   $0x74,-0x169(%rbp)
  4014a5:	c6 85 98 fe ff ff 28 	movb   $0x28,-0x168(%rbp)
  4014ac:	c6 85 99 fe ff ff 29 	movb   $0x29,-0x167(%rbp)
  4014b3:	c6 85 9a fe ff ff 20 	movb   $0x20,-0x166(%rbp)
  4014ba:	c6 85 9b fe ff ff 66 	movb   $0x66,-0x165(%rbp)
  4014c1:	c6 85 9c fe ff ff 61 	movb   $0x61,-0x164(%rbp)
  4014c8:	c6 85 9d fe ff ff 69 	movb   $0x69,-0x163(%rbp)
  4014cf:	c6 85 9e fe ff ff 6c 	movb   $0x6c,-0x162(%rbp)
  4014d6:	c6 85 9f fe ff ff 65 	movb   $0x65,-0x161(%rbp)
  4014dd:	c6 85 a0 fe ff ff 64 	movb   $0x64,-0x160(%rbp)
  4014e4:	c6 85 a1 fe ff ff 00 	movb   $0x0,-0x15f(%rbp)
  4014eb:	48 8d 85 d0 fe ff ff 	lea    -0x130(%rbp),%rax
  4014f2:	48 bb 68 74 74 70 3a 	movabs $0x6c2f2f3a70747468,%rbx
  4014f9:	2f 2f 6c 
  4014fc:	48 89 18             	mov    %rbx,(%rax)
  4014ff:	48 bb 65 6f 5f 33 33 	movabs $0x39326533335f6f65,%rbx
  401506:	65 32 39 
  401509:	48 89 58 08          	mov    %rbx,0x8(%rax)
  40150d:	48 bb 39 63 32 39 65 	movabs $0x6633646539326339,%rbx
  401514:	64 33 66 
  401517:	48 89 58 10          	mov    %rbx,0x10(%rax)
  40151b:	48 bb 30 31 31 33 66 	movabs $0x3539336633313130,%rbx
  401522:	33 39 35 
  401525:	48 89 58 18          	mov    %rbx,0x18(%rax)
  401529:	48 bb 35 61 34 63 36 	movabs $0x3830623663346135,%rbx
  401530:	62 30 38 
  401533:	48 89 58 20          	mov    %rbx,0x20(%rax)
  401537:	48 bb 35 30 30 2e 71 	movabs $0x6c6175712e303035,%rbx
  40153e:	75 61 6c 
  401541:	48 89 58 28          	mov    %rbx,0x28(%rax)
  401545:	48 bb 73 2e 73 68 61 	movabs $0x776c6c6168732e73,%rbx
  40154c:	6c 6c 77 
  40154f:	48 89 58 30          	mov    %rbx,0x30(%rax)
  401553:	48 be 65 70 6c 61 79 	movabs $0x61676179616c7065,%rsi
  40155a:	61 67 61 
  40155d:	48 89 70 38          	mov    %rsi,0x38(%rax)
  401561:	c7 40 40 2e 6d 65 2f 	movl   $0x2f656d2e,0x40(%rax)
  401568:	c6 40 44 00          	movb   $0x0,0x44(%rax)
  40156c:	c7 45 e8 c3 58 00 00 	movl   $0x58c3,-0x18(%rbp)
  401573:	48 8b 85 80 fe ff ff 	mov    -0x180(%rbp),%rax
  40157a:	48 8b 00             	mov    (%rax),%rax
  40157d:	48 89 c7             	mov    %rax,%rdi
  401580:	e8 9b fb ff ff       	callq  401120 <__xpg_basename@plt>
  401585:	ba 08 00 00 00       	mov    $0x8,%edx
  40158a:	be 08 00 00 00       	mov    $0x8,%esi
  40158f:	48 89 c7             	mov    %rax,%rdi
  401592:	e8 49 fa ff ff       	callq  400fe0 <openlog@plt>
  401597:	bf 1e 00 00 00       	mov    $0x1e,%edi
  40159c:	e8 ef f9 ff ff       	callq  400f90 <sysconf@plt>
  4015a1:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
  4015a5:	48 c7 45 d0 d0 0f 40 	movq   $0x400fd0,-0x30(%rbp)
  4015ac:	00 
  4015ad:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  4015b1:	48 01 c0             	add    %rax,%rax
  4015b4:	48 89 c2             	mov    %rax,%rdx
  4015b7:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  4015bb:	48 89 c6             	mov    %rax,%rsi
  4015be:	bf 90 41 60 00       	mov    $0x604190,%edi
  4015c3:	e8 98 f9 ff ff       	callq  400f60 <posix_memalign@plt>
  4015c8:	89 45 e8             	mov    %eax,-0x18(%rbp)
  4015cb:	83 7d e8 00          	cmpl   $0x0,-0x18(%rbp)
  4015cf:	74 0a                	je     4015db <close@plt+0x44b>
  4015d1:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  4015d6:	e8 65 fa ff ff       	callq  401040 <exit@plt>
  4015db:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  4015df:	48 01 c0             	add    %rax,%rax
  4015e2:	48 89 05 af 2b 20 00 	mov    %rax,0x202baf(%rip)        # 604198 <stdout+0x18>
  4015e9:	48 c7 05 ac 2b 20 00 	movq   $0x0,0x202bac(%rip)        # 6041a0 <stdout+0x20>
  4015f0:	00 00 00 00 
  4015f4:	bf 03 00 00 00       	mov    $0x3,%edi
  4015f9:	e8 82 fb ff ff       	callq  401180 <curl_global_init@plt>
  4015fe:	e8 0d fa ff ff       	callq  401010 <curl_easy_init@plt>
  401603:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
  401607:	48 8d 85 d0 fe ff ff 	lea    -0x130(%rbp),%rax
  40160e:	48 c7 c1 ff ff ff ff 	mov    $0xffffffffffffffff,%rcx
  401615:	48 89 c2             	mov    %rax,%rdx
  401618:	b8 00 00 00 00       	mov    $0x0,%eax
  40161d:	48 89 d7             	mov    %rdx,%rdi
  401620:	f2 ae                	repnz scas %es:(%rdi),%al
  401622:	48 89 c8             	mov    %rcx,%rax
  401625:	48 f7 d0             	not    %rax
  401628:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
  40162c:	48 8d 85 d0 fe ff ff 	lea    -0x130(%rbp),%rax
  401633:	48 01 d0             	add    %rdx,%rax
  401636:	48 bb 32 33 66 73 66 	movabs $0x3135326673663332,%rbx
  40163d:	32 35 31 
  401640:	48 89 18             	mov    %rbx,(%rax)
  401643:	48 be 6c 31 30 6f 31 	movabs $0x343132316f30316c,%rsi
  40164a:	32 31 34 
  40164d:	48 89 70 08          	mov    %rsi,0x8(%rax)
  401651:	66 c7 40 10 31 35    	movw   $0x3531,0x10(%rax)
  401657:	c6 40 12 00          	movb   $0x0,0x12(%rax)
  40165b:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
  40165f:	75 26                	jne    401687 <close@plt+0x4f7>
  401661:	c7 45 c4 12 27 00 00 	movl   $0x2712,-0x3c(%rbp)
  401668:	8b 4d c4             	mov    -0x3c(%rbp),%ecx
  40166b:	48 8d 95 d0 fe ff ff 	lea    -0x130(%rbp),%rdx
  401672:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  401676:	89 ce                	mov    %ecx,%esi
  401678:	48 89 c7             	mov    %rax,%rdi
  40167b:	b8 00 00 00 00       	mov    $0x0,%eax
  401680:	e8 eb f9 ff ff       	callq  401070 <curl_easy_setopt@plt>
  401685:	eb 37                	jmp    4016be <close@plt+0x52e>
  401687:	c7 45 c0 12 27 00 00 	movl   $0x2712,-0x40(%rbp)
  40168e:	8b 45 e4             	mov    -0x1c(%rbp),%eax
  401691:	48 98                	cltq   
  401693:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  40169a:	00 
  40169b:	48 8b 85 80 fe ff ff 	mov    -0x180(%rbp),%rax
  4016a2:	48 01 d0             	add    %rdx,%rax
  4016a5:	48 8b 10             	mov    (%rax),%rdx
  4016a8:	8b 4d c0             	mov    -0x40(%rbp),%ecx
  4016ab:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  4016af:	89 ce                	mov    %ecx,%esi
  4016b1:	48 89 c7             	mov    %rax,%rdi
  4016b4:	b8 00 00 00 00       	mov    $0x0,%eax
  4016b9:	e8 b2 f9 ff ff       	callq  401070 <curl_easy_setopt@plt>
  4016be:	c7 45 bc 2b 4e 00 00 	movl   $0x4e2b,-0x44(%rbp)
  4016c5:	8b 4d bc             	mov    -0x44(%rbp),%ecx
  4016c8:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  4016cc:	ba 1d 13 40 00       	mov    $0x40131d,%edx
  4016d1:	89 ce                	mov    %ecx,%esi
  4016d3:	48 89 c7             	mov    %rax,%rdi
  4016d6:	b8 00 00 00 00       	mov    $0x0,%eax
  4016db:	e8 90 f9 ff ff       	callq  401070 <curl_easy_setopt@plt>
  4016e0:	c7 45 b8 11 27 00 00 	movl   $0x2711,-0x48(%rbp)
  4016e7:	8b 4d b8             	mov    -0x48(%rbp),%ecx
  4016ea:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  4016ee:	ba 90 41 60 00       	mov    $0x604190,%edx
  4016f3:	89 ce                	mov    %ecx,%esi
  4016f5:	48 89 c7             	mov    %rax,%rdi
  4016f8:	b8 00 00 00 00       	mov    $0x0,%eax
  4016fd:	e8 6e f9 ff ff       	callq  401070 <curl_easy_setopt@plt>
  401702:	c7 45 b4 22 27 00 00 	movl   $0x2722,-0x4c(%rbp)
  401709:	8b 4d b4             	mov    -0x4c(%rbp),%ecx
  40170c:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  401710:	ba 3d 27 40 00       	mov    $0x40273d,%edx
  401715:	89 ce                	mov    %ecx,%esi
  401717:	48 89 c7             	mov    %rax,%rdi
  40171a:	b8 00 00 00 00       	mov    $0x0,%eax
  40171f:	e8 4c f9 ff ff       	callq  401070 <curl_easy_setopt@plt>
  401724:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  401728:	48 89 c7             	mov    %rax,%rdi
  40172b:	e8 c0 f9 ff ff       	callq  4010f0 <curl_easy_perform@plt>
  401730:	89 45 b0             	mov    %eax,-0x50(%rbp)
  401733:	83 7d b0 00          	cmpl   $0x0,-0x50(%rbp)
  401737:	74 2b                	je     401764 <close@plt+0x5d4>
  401739:	8b 45 b0             	mov    -0x50(%rbp),%eax
  40173c:	89 c7                	mov    %eax,%edi
  40173e:	e8 cd f9 ff ff       	callq  401110 <curl_easy_strerror@plt>
  401743:	48 89 c2             	mov    %rax,%rdx
  401746:	be 50 27 40 00       	mov    $0x402750,%esi
  40174b:	bf 03 00 00 00       	mov    $0x3,%edi
  401750:	b8 00 00 00 00       	mov    $0x0,%eax
  401755:	e8 b6 f7 ff ff       	callq  400f10 <syslog@plt>
  40175a:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  40175f:	e8 dc f8 ff ff       	callq  401040 <exit@plt>
  401764:	c7 45 ac 02 00 20 00 	movl   $0x200002,-0x54(%rbp)
  40176b:	8b 4d ac             	mov    -0x54(%rbp),%ecx
  40176e:	48 8d 55 a0          	lea    -0x60(%rbp),%rdx
  401772:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  401776:	89 ce                	mov    %ecx,%esi
  401778:	48 89 c7             	mov    %rax,%rdi
  40177b:	b8 00 00 00 00       	mov    $0x0,%eax
  401780:	e8 bb f7 ff ff       	callq  400f40 <curl_easy_getinfo@plt>
  401785:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
  401789:	48 3d 94 01 00 00    	cmp    $0x194,%rax
  40178f:	75 23                	jne    4017b4 <close@plt+0x624>
  401791:	48 8d 85 b0 fe ff ff 	lea    -0x150(%rbp),%rax
  401798:	48 89 c6             	mov    %rax,%rsi
  40179b:	bf 03 00 00 00       	mov    $0x3,%edi
  4017a0:	b8 00 00 00 00       	mov    $0x0,%eax
  4017a5:	e8 66 f7 ff ff       	callq  400f10 <syslog@plt>
  4017aa:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  4017af:	e8 8c f8 ff ff       	callq  401040 <exit@plt>
  4017b4:	48 8b 0d dd 29 20 00 	mov    0x2029dd(%rip),%rcx        # 604198 <stdout+0x18>
  4017bb:	48 8b 05 ce 29 20 00 	mov    0x2029ce(%rip),%rax        # 604190 <stdout+0x10>
  4017c2:	ba 07 00 00 00       	mov    $0x7,%edx
  4017c7:	48 89 ce             	mov    %rcx,%rsi
  4017ca:	48 89 c7             	mov    %rax,%rdi
  4017cd:	e8 2e f9 ff ff       	callq  401100 <mprotect@plt>
  4017d2:	89 45 e8             	mov    %eax,-0x18(%rbp)
  4017d5:	83 7d e8 00          	cmpl   $0x0,-0x18(%rbp)
  4017d9:	74 23                	je     4017fe <close@plt+0x66e>
  4017db:	48 8d 85 90 fe ff ff 	lea    -0x170(%rbp),%rax
  4017e2:	48 89 c6             	mov    %rax,%rsi
  4017e5:	bf 03 00 00 00       	mov    $0x3,%edi
  4017ea:	b8 00 00 00 00       	mov    $0x0,%eax
  4017ef:	e8 1c f7 ff ff       	callq  400f10 <syslog@plt>
  4017f4:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  4017f9:	e8 42 f8 ff ff       	callq  401040 <exit@plt>
  4017fe:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)
  401805:	eb 2a                	jmp    401831 <close@plt+0x6a1>
  401807:	48 8b 15 82 29 20 00 	mov    0x202982(%rip),%rdx        # 604190 <stdout+0x10>
  40180e:	8b 45 ec             	mov    -0x14(%rbp),%eax
  401811:	48 98                	cltq   
  401813:	48 01 c2             	add    %rax,%rdx
  401816:	48 8b 0d 73 29 20 00 	mov    0x202973(%rip),%rcx        # 604190 <stdout+0x10>
  40181d:	8b 45 ec             	mov    -0x14(%rbp),%eax
  401820:	48 98                	cltq   
  401822:	48 01 c8             	add    %rcx,%rax
  401825:	0f b6 00             	movzbl (%rax),%eax
  401828:	83 f0 aa             	xor    $0xffffffaa,%eax
  40182b:	88 02                	mov    %al,(%rdx)
  40182d:	83 45 ec 01          	addl   $0x1,-0x14(%rbp)
  401831:	8b 45 ec             	mov    -0x14(%rbp),%eax
  401834:	48 63 d0             	movslq %eax,%rdx
  401837:	48 8b 05 5a 29 20 00 	mov    0x20295a(%rip),%rax        # 604198 <stdout+0x18>
  40183e:	48 39 c2             	cmp    %rax,%rdx
  401841:	72 c4                	jb     401807 <close@plt+0x677>
  401843:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  401847:	48 89 c7             	mov    %rax,%rdi
  40184a:	e8 61 f8 ff ff       	callq  4010b0 <curl_easy_cleanup@plt>
  40184f:	e8 ac f6 ff ff       	callq  400f00 <curl_global_cleanup@plt>
  401854:	48 81 c4 78 01 00 00 	add    $0x178,%rsp
  40185b:	5b                   	pop    %rbx
  40185c:	5d                   	pop    %rbp
  40185d:	c3                   	retq   
  40185e:	55                   	push   %rbp
  40185f:	48 89 e5             	mov    %rsp,%rbp
  401862:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  401866:	89 75 e4             	mov    %esi,-0x1c(%rbp)
  401869:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401870:	e9 34 01 00 00       	jmpq   4019a9 <close@plt+0x819>
  401875:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
  40187c:	e9 0e 01 00 00       	jmpq   40198f <close@plt+0x7ff>
  401881:	8b 45 f8             	mov    -0x8(%rbp),%eax
  401884:	48 98                	cltq   
  401886:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  40188d:	00 
  40188e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401892:	48 01 d0             	add    %rdx,%rax
  401895:	8b 50 04             	mov    0x4(%rax),%edx
  401898:	8b 45 f8             	mov    -0x8(%rbp),%eax
  40189b:	48 98                	cltq   
  40189d:	48 83 c0 01          	add    $0x1,%rax
  4018a1:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  4018a8:	00 
  4018a9:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4018ad:	48 01 c8             	add    %rcx,%rax
  4018b0:	8b 40 04             	mov    0x4(%rax),%eax
  4018b3:	39 c2                	cmp    %eax,%edx
  4018b5:	0f 86 d0 00 00 00    	jbe    40198b <close@plt+0x7fb>
  4018bb:	8b 45 f8             	mov    -0x8(%rbp),%eax
  4018be:	48 98                	cltq   
  4018c0:	48 83 c0 01          	add    $0x1,%rax
  4018c4:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  4018cb:	00 
  4018cc:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4018d0:	48 01 d0             	add    %rdx,%rax
  4018d3:	8b 00                	mov    (%rax),%eax
  4018d5:	89 45 f4             	mov    %eax,-0xc(%rbp)
  4018d8:	8b 45 f8             	mov    -0x8(%rbp),%eax
  4018db:	48 98                	cltq   
  4018dd:	48 83 c0 01          	add    $0x1,%rax
  4018e1:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  4018e8:	00 
  4018e9:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4018ed:	48 01 d0             	add    %rdx,%rax
  4018f0:	8b 40 04             	mov    0x4(%rax),%eax
  4018f3:	89 45 f0             	mov    %eax,-0x10(%rbp)
  4018f6:	8b 45 f8             	mov    -0x8(%rbp),%eax
  4018f9:	48 98                	cltq   
  4018fb:	48 83 c0 01          	add    $0x1,%rax
  4018ff:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  401906:	00 
  401907:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  40190b:	48 01 c2             	add    %rax,%rdx
  40190e:	8b 45 f8             	mov    -0x8(%rbp),%eax
  401911:	48 98                	cltq   
  401913:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  40191a:	00 
  40191b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  40191f:	48 01 c8             	add    %rcx,%rax
  401922:	8b 00                	mov    (%rax),%eax
  401924:	89 02                	mov    %eax,(%rdx)
  401926:	8b 45 f8             	mov    -0x8(%rbp),%eax
  401929:	48 98                	cltq   
  40192b:	48 83 c0 01          	add    $0x1,%rax
  40192f:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  401936:	00 
  401937:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  40193b:	48 01 c2             	add    %rax,%rdx
  40193e:	8b 45 f8             	mov    -0x8(%rbp),%eax
  401941:	48 98                	cltq   
  401943:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  40194a:	00 
  40194b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  40194f:	48 01 c8             	add    %rcx,%rax
  401952:	8b 40 04             	mov    0x4(%rax),%eax
  401955:	89 42 04             	mov    %eax,0x4(%rdx)
  401958:	8b 45 f8             	mov    -0x8(%rbp),%eax
  40195b:	48 98                	cltq   
  40195d:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  401964:	00 
  401965:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401969:	48 01 c2             	add    %rax,%rdx
  40196c:	8b 45 f4             	mov    -0xc(%rbp),%eax
  40196f:	89 02                	mov    %eax,(%rdx)
  401971:	8b 45 f8             	mov    -0x8(%rbp),%eax
  401974:	48 98                	cltq   
  401976:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  40197d:	00 
  40197e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401982:	48 01 c2             	add    %rax,%rdx
  401985:	8b 45 f0             	mov    -0x10(%rbp),%eax
  401988:	89 42 04             	mov    %eax,0x4(%rdx)
  40198b:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
  40198f:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401992:	8b 55 e4             	mov    -0x1c(%rbp),%edx
  401995:	29 c2                	sub    %eax,%edx
  401997:	89 d0                	mov    %edx,%eax
  401999:	83 e8 01             	sub    $0x1,%eax
  40199c:	3b 45 f8             	cmp    -0x8(%rbp),%eax
  40199f:	0f 8f dc fe ff ff    	jg     401881 <close@plt+0x6f1>
  4019a5:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  4019a9:	8b 45 e4             	mov    -0x1c(%rbp),%eax
  4019ac:	83 e8 01             	sub    $0x1,%eax
  4019af:	3b 45 fc             	cmp    -0x4(%rbp),%eax
  4019b2:	0f 8f bd fe ff ff    	jg     401875 <close@plt+0x6e5>
  4019b8:	5d                   	pop    %rbp
  4019b9:	c3                   	retq   
  4019ba:	55                   	push   %rbp
  4019bb:	48 89 e5             	mov    %rsp,%rbp
  4019be:	48 81 ec 30 08 00 00 	sub    $0x830,%rsp
  4019c5:	48 89 bd d8 f7 ff ff 	mov    %rdi,-0x828(%rbp)
  4019cc:	89 b5 d4 f7 ff ff    	mov    %esi,-0x82c(%rbp)
  4019d2:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
  4019d9:	c7 45 f4 ff ff ff ff 	movl   $0xffffffff,-0xc(%rbp)
  4019e0:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%rbp)
  4019e7:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)
  4019ee:	c7 45 e8 ff 01 00 00 	movl   $0x1ff,-0x18(%rbp)
  4019f5:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)
  4019fc:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401a03:	eb 23                	jmp    401a28 <close@plt+0x898>
  401a05:	8b 55 fc             	mov    -0x4(%rbp),%edx
  401a08:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401a0b:	48 98                	cltq   
  401a0d:	89 94 c5 e0 f7 ff ff 	mov    %edx,-0x820(%rbp,%rax,8)
  401a14:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401a17:	48 98                	cltq   
  401a19:	c7 84 c5 e4 f7 ff ff 	movl   $0x0,-0x81c(%rbp,%rax,8)
  401a20:	00 00 00 00 
  401a24:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  401a28:	81 7d fc ff 00 00 00 	cmpl   $0xff,-0x4(%rbp)
  401a2f:	7e d4                	jle    401a05 <close@plt+0x875>
  401a31:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401a38:	eb 30                	jmp    401a6a <close@plt+0x8da>
  401a3a:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401a3d:	48 63 d0             	movslq %eax,%rdx
  401a40:	48 8b 85 d8 f7 ff ff 	mov    -0x828(%rbp),%rax
  401a47:	48 01 d0             	add    %rdx,%rax
  401a4a:	0f b6 00             	movzbl (%rax),%eax
  401a4d:	0f b6 c0             	movzbl %al,%eax
  401a50:	48 63 d0             	movslq %eax,%rdx
  401a53:	8b 94 d5 e4 f7 ff ff 	mov    -0x81c(%rbp,%rdx,8),%edx
  401a5a:	83 c2 01             	add    $0x1,%edx
  401a5d:	48 98                	cltq   
  401a5f:	89 94 c5 e4 f7 ff ff 	mov    %edx,-0x81c(%rbp,%rax,8)
  401a66:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  401a6a:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401a6d:	3b 85 d4 f7 ff ff    	cmp    -0x82c(%rbp),%eax
  401a73:	7c c5                	jl     401a3a <close@plt+0x8aa>
  401a75:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401a7c:	eb 53                	jmp    401ad1 <close@plt+0x941>
  401a7e:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401a81:	48 98                	cltq   
  401a83:	8b 84 c5 e4 f7 ff ff 	mov    -0x81c(%rbp,%rax,8),%eax
  401a8a:	3b 45 f8             	cmp    -0x8(%rbp),%eax
  401a8d:	76 0f                	jbe    401a9e <close@plt+0x90e>
  401a8f:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401a92:	48 98                	cltq   
  401a94:	8b 84 c5 e4 f7 ff ff 	mov    -0x81c(%rbp,%rax,8),%eax
  401a9b:	89 45 f8             	mov    %eax,-0x8(%rbp)
  401a9e:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401aa1:	48 98                	cltq   
  401aa3:	8b 84 c5 e4 f7 ff ff 	mov    -0x81c(%rbp,%rax,8),%eax
  401aaa:	3b 45 f4             	cmp    -0xc(%rbp),%eax
  401aad:	73 0f                	jae    401abe <close@plt+0x92e>
  401aaf:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401ab2:	48 98                	cltq   
  401ab4:	8b 84 c5 e4 f7 ff ff 	mov    -0x81c(%rbp,%rax,8),%eax
  401abb:	89 45 f4             	mov    %eax,-0xc(%rbp)
  401abe:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401ac1:	48 98                	cltq   
  401ac3:	8b 84 c5 e4 f7 ff ff 	mov    -0x81c(%rbp,%rax,8),%eax
  401aca:	01 45 f0             	add    %eax,-0x10(%rbp)
  401acd:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  401ad1:	81 7d fc ff 00 00 00 	cmpl   $0xff,-0x4(%rbp)
  401ad8:	7e a4                	jle    401a7e <close@plt+0x8ee>
  401ada:	8b 45 f0             	mov    -0x10(%rbp),%eax
  401add:	c1 e8 08             	shr    $0x8,%eax
  401ae0:	89 45 f0             	mov    %eax,-0x10(%rbp)
  401ae3:	48 8d 85 e0 f7 ff ff 	lea    -0x820(%rbp),%rax
  401aea:	be 00 01 00 00       	mov    $0x100,%esi
  401aef:	48 89 c7             	mov    %rax,%rdi
  401af2:	e8 67 fd ff ff       	callq  40185e <close@plt+0x6ce>
  401af7:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401afe:	eb 5a                	jmp    401b5a <close@plt+0x9ca>
  401b00:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401b03:	48 98                	cltq   
  401b05:	8b 84 c5 e4 f7 ff ff 	mov    -0x81c(%rbp,%rax,8),%eax
  401b0c:	85 c0                	test   %eax,%eax
  401b0e:	75 06                	jne    401b16 <close@plt+0x986>
  401b10:	83 45 ec 01          	addl   $0x1,-0x14(%rbp)
  401b14:	eb 40                	jmp    401b56 <close@plt+0x9c6>
  401b16:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401b19:	48 98                	cltq   
  401b1b:	8b 84 c5 e0 f7 ff ff 	mov    -0x820(%rbp,%rax,8),%eax
  401b22:	3b 45 e8             	cmp    -0x18(%rbp),%eax
  401b25:	73 0f                	jae    401b36 <close@plt+0x9a6>
  401b27:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401b2a:	48 98                	cltq   
  401b2c:	8b 84 c5 e0 f7 ff ff 	mov    -0x820(%rbp,%rax,8),%eax
  401b33:	89 45 e8             	mov    %eax,-0x18(%rbp)
  401b36:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401b39:	48 98                	cltq   
  401b3b:	8b 84 c5 e0 f7 ff ff 	mov    -0x820(%rbp,%rax,8),%eax
  401b42:	3b 45 e4             	cmp    -0x1c(%rbp),%eax
  401b45:	76 0f                	jbe    401b56 <close@plt+0x9c6>
  401b47:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401b4a:	48 98                	cltq   
  401b4c:	8b 84 c5 e0 f7 ff ff 	mov    -0x820(%rbp,%rax,8),%eax
  401b53:	89 45 e4             	mov    %eax,-0x1c(%rbp)
  401b56:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  401b5a:	81 7d fc ff 00 00 00 	cmpl   $0xff,-0x4(%rbp)
  401b61:	7e 9d                	jle    401b00 <close@plt+0x970>
  401b63:	83 7d ec 04          	cmpl   $0x4,-0x14(%rbp)
  401b67:	77 18                	ja     401b81 <close@plt+0x9f1>
  401b69:	8b 55 f0             	mov    -0x10(%rbp),%edx
  401b6c:	89 d0                	mov    %edx,%eax
  401b6e:	c1 e0 02             	shl    $0x2,%eax
  401b71:	01 d0                	add    %edx,%eax
  401b73:	01 c0                	add    %eax,%eax
  401b75:	3b 45 f8             	cmp    -0x8(%rbp),%eax
  401b78:	76 07                	jbe    401b81 <close@plt+0x9f1>
  401b7a:	b8 02 00 00 00       	mov    $0x2,%eax
  401b7f:	eb 5c                	jmp    401bdd <close@plt+0xa4d>
  401b81:	83 7d e4 7f          	cmpl   $0x7f,-0x1c(%rbp)
  401b85:	77 1c                	ja     401ba3 <close@plt+0xa13>
  401b87:	83 7d e8 08          	cmpl   $0x8,-0x18(%rbp)
  401b8b:	76 16                	jbe    401ba3 <close@plt+0xa13>
  401b8d:	8b 45 d8             	mov    -0x28(%rbp),%eax
  401b90:	83 f8 20             	cmp    $0x20,%eax
  401b93:	75 07                	jne    401b9c <close@plt+0xa0c>
  401b95:	b8 31 00 00 00       	mov    $0x31,%eax
  401b9a:	eb 41                	jmp    401bdd <close@plt+0xa4d>
  401b9c:	b8 32 00 00 00       	mov    $0x32,%eax
  401ba1:	eb 3a                	jmp    401bdd <close@plt+0xa4d>
  401ba3:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
  401ba7:	74 18                	je     401bc1 <close@plt+0xa31>
  401ba9:	8b 55 f0             	mov    -0x10(%rbp),%edx
  401bac:	89 d0                	mov    %edx,%eax
  401bae:	c1 e0 02             	shl    $0x2,%eax
  401bb1:	01 d0                	add    %edx,%eax
  401bb3:	01 c0                	add    %eax,%eax
  401bb5:	3b 45 f8             	cmp    -0x8(%rbp),%eax
  401bb8:	73 07                	jae    401bc1 <close@plt+0xa31>
  401bba:	b8 64 00 00 00       	mov    $0x64,%eax
  401bbf:	eb 1c                	jmp    401bdd <close@plt+0xa4d>
  401bc1:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
  401bc5:	75 11                	jne    401bd8 <close@plt+0xa48>
  401bc7:	8b 45 f0             	mov    -0x10(%rbp),%eax
  401bca:	01 c0                	add    %eax,%eax
  401bcc:	3b 45 f8             	cmp    -0x8(%rbp),%eax
  401bcf:	73 07                	jae    401bd8 <close@plt+0xa48>
  401bd1:	b8 19 00 00 00       	mov    $0x19,%eax
  401bd6:	eb 05                	jmp    401bdd <close@plt+0xa4d>
  401bd8:	b8 16 00 00 00       	mov    $0x16,%eax
  401bdd:	c9                   	leaveq 
  401bde:	c3                   	retq   
  401bdf:	55                   	push   %rbp
  401be0:	48 89 e5             	mov    %rsp,%rbp
  401be3:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  401be7:	89 75 f4             	mov    %esi,-0xc(%rbp)
  401bea:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
  401bee:	75 05                	jne    401bf5 <close@plt+0xa65>
  401bf0:	8b 45 f4             	mov    -0xc(%rbp),%eax
  401bf3:	eb 05                	jmp    401bfa <close@plt+0xa6a>
  401bf5:	b8 01 00 00 00       	mov    $0x1,%eax
  401bfa:	5d                   	pop    %rbp
  401bfb:	c3                   	retq   
  401bfc:	55                   	push   %rbp
  401bfd:	48 89 e5             	mov    %rsp,%rbp
  401c00:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  401c04:	89 75 f4             	mov    %esi,-0xc(%rbp)
  401c07:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
  401c0b:	75 07                	jne    401c14 <close@plt+0xa84>
  401c0d:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  401c12:	eb 03                	jmp    401c17 <close@plt+0xa87>
  401c14:	8b 45 f4             	mov    -0xc(%rbp),%eax
  401c17:	5d                   	pop    %rbp
  401c18:	c3                   	retq   
  401c19:	55                   	push   %rbp
  401c1a:	48 89 e5             	mov    %rsp,%rbp
  401c1d:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  401c21:	89 75 f4             	mov    %esi,-0xc(%rbp)
  401c24:	81 7d f4 cf 07 00 00 	cmpl   $0x7cf,-0xc(%rbp)
  401c2b:	7f 07                	jg     401c34 <close@plt+0xaa4>
  401c2d:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  401c32:	eb 05                	jmp    401c39 <close@plt+0xaa9>
  401c34:	b8 00 00 00 00       	mov    $0x0,%eax
  401c39:	5d                   	pop    %rbp
  401c3a:	c3                   	retq   
  401c3b:	55                   	push   %rbp
  401c3c:	48 89 e5             	mov    %rsp,%rbp
  401c3f:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  401c43:	89 75 e4             	mov    %esi,-0x1c(%rbp)
  401c46:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
  401c4d:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401c54:	eb 1c                	jmp    401c72 <close@plt+0xae2>
  401c56:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401c59:	48 63 d0             	movslq %eax,%rdx
  401c5c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401c60:	48 01 d0             	add    %rdx,%rax
  401c63:	0f b6 00             	movzbl (%rax),%eax
  401c66:	3c 20                	cmp    $0x20,%al
  401c68:	75 04                	jne    401c6e <close@plt+0xade>
  401c6a:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
  401c6e:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  401c72:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401c75:	3b 45 e4             	cmp    -0x1c(%rbp),%eax
  401c78:	7c dc                	jl     401c56 <close@plt+0xac6>
  401c7a:	8b 45 f8             	mov    -0x8(%rbp),%eax
  401c7d:	5d                   	pop    %rbp
  401c7e:	c3                   	retq   
  401c7f:	55                   	push   %rbp
  401c80:	48 89 e5             	mov    %rsp,%rbp
  401c83:	48 81 ec 80 3f 00 00 	sub    $0x3f80,%rsp
  401c8a:	89 bd 8c c0 ff ff    	mov    %edi,-0x3f74(%rbp)
  401c90:	48 89 b5 80 c0 ff ff 	mov    %rsi,-0x3f80(%rbp)
  401c97:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%rbp)
  401c9e:	48 b8 68 74 74 70 3a 	movabs $0x6c2f2f3a70747468,%rax
  401ca5:	2f 2f 6c 
  401ca8:	48 89 85 90 c0 ff ff 	mov    %rax,-0x3f70(%rbp)
  401caf:	48 b8 65 6f 5f 33 33 	movabs $0x39326533335f6f65,%rax
  401cb6:	65 32 39 
  401cb9:	48 89 85 98 c0 ff ff 	mov    %rax,-0x3f68(%rbp)
  401cc0:	48 b8 39 63 32 39 65 	movabs $0x6633646539326339,%rax
  401cc7:	64 33 66 
  401cca:	48 89 85 a0 c0 ff ff 	mov    %rax,-0x3f60(%rbp)
  401cd1:	48 b8 30 31 31 33 66 	movabs $0x3539336633313130,%rax
  401cd8:	33 39 35 
  401cdb:	48 89 85 a8 c0 ff ff 	mov    %rax,-0x3f58(%rbp)
  401ce2:	48 b8 35 61 34 63 36 	movabs $0x3830623663346135,%rax
  401ce9:	62 30 38 
  401cec:	48 89 85 b0 c0 ff ff 	mov    %rax,-0x3f50(%rbp)
  401cf3:	48 b8 35 30 30 2e 71 	movabs $0x6c6175712e303035,%rax
  401cfa:	75 61 6c 
  401cfd:	48 89 85 b8 c0 ff ff 	mov    %rax,-0x3f48(%rbp)
  401d04:	48 b8 73 2e 73 68 61 	movabs $0x776c6c6168732e73,%rax
  401d0b:	6c 6c 77 
  401d0e:	48 89 85 c0 c0 ff ff 	mov    %rax,-0x3f40(%rbp)
  401d15:	48 b8 65 70 6c 61 79 	movabs $0x61676179616c7065,%rax
  401d1c:	61 67 61 
  401d1f:	48 89 85 c8 c0 ff ff 	mov    %rax,-0x3f38(%rbp)
  401d26:	c7 85 d0 c0 ff ff 2e 	movl   $0x2f656d2e,-0x3f30(%rbp)
  401d2d:	6d 65 2f 
  401d30:	c6 85 d4 c0 ff ff 00 	movb   $0x0,-0x3f2c(%rbp)
  401d37:	48 8b 85 80 c0 ff ff 	mov    -0x3f80(%rbp),%rax
  401d3e:	48 8b 00             	mov    (%rax),%rax
  401d41:	ba 08 00 00 00       	mov    $0x8,%edx
  401d46:	be 08 00 00 00       	mov    $0x8,%esi
  401d4b:	48 89 c7             	mov    %rax,%rdi
  401d4e:	e8 8d f2 ff ff       	callq  400fe0 <openlog@plt>
  401d53:	48 8d 85 90 c0 ff ff 	lea    -0x3f70(%rbp),%rax
  401d5a:	48 89 05 4f 24 20 00 	mov    %rax,0x20244f(%rip)        # 6041b0 <stdout+0x30>
  401d61:	83 bd 8c c0 ff ff 02 	cmpl   $0x2,-0x3f74(%rbp)
  401d68:	0f 8e 3a 01 00 00    	jle    401ea8 <close@plt+0xd18>
  401d6e:	83 bd 8c c0 ff ff 03 	cmpl   $0x3,-0x3f74(%rbp)
  401d75:	74 0d                	je     401d84 <close@plt+0xbf4>
  401d77:	83 bd 8c c0 ff ff 05 	cmpl   $0x5,-0x3f74(%rbp)
  401d7e:	0f 85 06 01 00 00    	jne    401e8a <close@plt+0xcfa>
  401d84:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%rbp)
  401d8b:	e9 e6 00 00 00       	jmpq   401e76 <close@plt+0xce6>
  401d90:	8b 45 f4             	mov    -0xc(%rbp),%eax
  401d93:	48 98                	cltq   
  401d95:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  401d9c:	00 
  401d9d:	48 8b 85 80 c0 ff ff 	mov    -0x3f80(%rbp),%rax
  401da4:	48 01 d0             	add    %rdx,%rax
  401da7:	48 8b 00             	mov    (%rax),%rax
  401daa:	be 6f 27 40 00       	mov    $0x40276f,%esi
  401daf:	48 89 c7             	mov    %rax,%rdi
  401db2:	e8 a9 f2 ff ff       	callq  401060 <strcmp@plt>
  401db7:	85 c0                	test   %eax,%eax
  401db9:	75 33                	jne    401dee <close@plt+0xc5e>
  401dbb:	8b 85 8c c0 ff ff    	mov    -0x3f74(%rbp),%eax
  401dc1:	83 e8 01             	sub    $0x1,%eax
  401dc4:	3b 45 f4             	cmp    -0xc(%rbp),%eax
  401dc7:	74 25                	je     401dee <close@plt+0xc5e>
  401dc9:	8b 45 f4             	mov    -0xc(%rbp),%eax
  401dcc:	48 98                	cltq   
  401dce:	48 83 c0 01          	add    $0x1,%rax
  401dd2:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  401dd9:	00 
  401dda:	48 8b 85 80 c0 ff ff 	mov    -0x3f80(%rbp),%rax
  401de1:	48 01 d0             	add    %rdx,%rax
  401de4:	48 8b 00             	mov    (%rax),%rax
  401de7:	48 89 05 c2 23 20 00 	mov    %rax,0x2023c2(%rip)        # 6041b0 <stdout+0x30>
  401dee:	8b 45 f4             	mov    -0xc(%rbp),%eax
  401df1:	48 98                	cltq   
  401df3:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  401dfa:	00 
  401dfb:	48 8b 85 80 c0 ff ff 	mov    -0x3f80(%rbp),%rax
  401e02:	48 01 d0             	add    %rdx,%rax
  401e05:	48 8b 00             	mov    (%rax),%rax
  401e08:	be 72 27 40 00       	mov    $0x402772,%esi
  401e0d:	48 89 c7             	mov    %rax,%rdi
  401e10:	e8 4b f2 ff ff       	callq  401060 <strcmp@plt>
  401e15:	85 c0                	test   %eax,%eax
  401e17:	75 59                	jne    401e72 <close@plt+0xce2>
  401e19:	8b 85 8c c0 ff ff    	mov    -0x3f74(%rbp),%eax
  401e1f:	83 e8 01             	sub    $0x1,%eax
  401e22:	3b 45 f4             	cmp    -0xc(%rbp),%eax
  401e25:	74 4b                	je     401e72 <close@plt+0xce2>
  401e27:	8b 45 f4             	mov    -0xc(%rbp),%eax
  401e2a:	48 98                	cltq   
  401e2c:	48 83 c0 01          	add    $0x1,%rax
  401e30:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  401e37:	00 
  401e38:	48 8b 85 80 c0 ff ff 	mov    -0x3f80(%rbp),%rax
  401e3f:	48 01 d0             	add    %rdx,%rax
  401e42:	48 8b 00             	mov    (%rax),%rax
  401e45:	48 89 c7             	mov    %rax,%rdi
  401e48:	e8 83 f2 ff ff       	callq  4010d0 <puts@plt>
  401e4d:	8b 45 f4             	mov    -0xc(%rbp),%eax
  401e50:	48 98                	cltq   
  401e52:	48 83 c0 01          	add    $0x1,%rax
  401e56:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  401e5d:	00 
  401e5e:	48 8b 85 80 c0 ff ff 	mov    -0x3f80(%rbp),%rax
  401e65:	48 01 d0             	add    %rdx,%rax
  401e68:	48 8b 00             	mov    (%rax),%rax
  401e6b:	48 89 05 36 23 20 00 	mov    %rax,0x202336(%rip)        # 6041a8 <stdout+0x28>
  401e72:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
  401e76:	8b 85 8c c0 ff ff    	mov    -0x3f74(%rbp),%eax
  401e7c:	83 e8 01             	sub    $0x1,%eax
  401e7f:	3b 45 f4             	cmp    -0xc(%rbp),%eax
  401e82:	0f 8f 08 ff ff ff    	jg     401d90 <close@plt+0xc00>
  401e88:	eb 1e                	jmp    401ea8 <close@plt+0xd18>
  401e8a:	be 75 27 40 00       	mov    $0x402775,%esi
  401e8f:	bf 03 00 00 00       	mov    $0x3,%edi
  401e94:	b8 00 00 00 00       	mov    $0x0,%eax
  401e99:	e8 72 f0 ff ff       	callq  400f10 <syslog@plt>
  401e9e:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  401ea3:	e8 98 f1 ff ff       	callq  401040 <exit@plt>
  401ea8:	48 8b 05 f9 22 20 00 	mov    0x2022f9(%rip),%rax        # 6041a8 <stdout+0x28>
  401eaf:	48 85 c0             	test   %rax,%rax
  401eb2:	74 36                	je     401eea <close@plt+0xd5a>
  401eb4:	48 8b 05 ed 22 20 00 	mov    0x2022ed(%rip),%rax        # 6041a8 <stdout+0x28>
  401ebb:	48 89 c7             	mov    %rax,%rdi
  401ebe:	e8 dd f1 ff ff       	callq  4010a0 <chdir@plt>
  401ec3:	89 45 ec             	mov    %eax,-0x14(%rbp)
  401ec6:	83 7d ec ff          	cmpl   $0xffffffff,-0x14(%rbp)
  401eca:	75 1e                	jne    401eea <close@plt+0xd5a>
  401ecc:	be 88 27 40 00       	mov    $0x402788,%esi
  401ed1:	bf 03 00 00 00       	mov    $0x3,%edi
  401ed6:	b8 00 00 00 00       	mov    $0x0,%eax
  401edb:	e8 30 f0 ff ff       	callq  400f10 <syslog@plt>
  401ee0:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  401ee5:	e8 56 f1 ff ff       	callq  401040 <exit@plt>
  401eea:	48 8d 85 e0 c0 ff ff 	lea    -0x3f20(%rbp),%rax
  401ef1:	be 64 00 00 00       	mov    $0x64,%esi
  401ef6:	48 89 c7             	mov    %rax,%rdi
  401ef9:	b8 00 00 00 00       	mov    $0x0,%eax
  401efe:	e8 9c 05 00 00       	callq  40249f <close@plt+0x130f>
  401f03:	85 c0                	test   %eax,%eax
  401f05:	75 11                	jne    401f18 <close@plt+0xd88>
  401f07:	48 8d 85 e0 c0 ff ff 	lea    -0x3f20(%rbp),%rax
  401f0e:	48 89 c7             	mov    %rax,%rdi
  401f11:	e8 ba f1 ff ff       	callq  4010d0 <puts@plt>
  401f16:	eb 19                	jmp    401f31 <close@plt+0xda1>
  401f18:	bf a8 27 40 00       	mov    $0x4027a8,%edi
  401f1d:	e8 ae f1 ff ff       	callq  4010d0 <puts@plt>
  401f22:	48 8b 05 57 22 20 00 	mov    0x202257(%rip),%rax        # 604180 <stdout>
  401f29:	48 89 c7             	mov    %rax,%rdi
  401f2c:	e8 ef f0 ff ff       	callq  401020 <fflush@plt>
  401f31:	48 8d 85 50 c1 ff ff 	lea    -0x3eb0(%rbp),%rax
  401f38:	ba 80 3e 00 00       	mov    $0x3e80,%edx
  401f3d:	be 00 00 00 00       	mov    $0x0,%esi
  401f42:	48 89 c7             	mov    %rax,%rdi
  401f45:	e8 36 f0 ff ff       	callq  400f80 <memset@plt>
  401f4a:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
  401f51:	00 
  401f52:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
  401f59:	00 
  401f5a:	b8 80 3e 00 00       	mov    $0x3e80,%eax
  401f5f:	48 2b 45 f8          	sub    -0x8(%rbp),%rax
  401f63:	48 8d 8d 50 c1 ff ff 	lea    -0x3eb0(%rbp),%rcx
  401f6a:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  401f6e:	48 01 d1             	add    %rdx,%rcx
  401f71:	48 89 c2             	mov    %rax,%rdx
  401f74:	48 89 ce             	mov    %rcx,%rsi
  401f77:	bf 00 00 00 00       	mov    $0x0,%edi
  401f7c:	e8 0f f1 ff ff       	callq  401090 <read@plt>
  401f81:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
  401f85:	48 83 7d e0 ff       	cmpq   $0xffffffffffffffff,-0x20(%rbp)
  401f8a:	75 1e                	jne    401faa <close@plt+0xe1a>
  401f8c:	be f0 27 40 00       	mov    $0x4027f0,%esi
  401f91:	bf 03 00 00 00       	mov    $0x3,%edi
  401f96:	b8 00 00 00 00       	mov    $0x0,%eax
  401f9b:	e8 70 ef ff ff       	callq  400f10 <syslog@plt>
  401fa0:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  401fa5:	e8 96 f0 ff ff       	callq  401040 <exit@plt>
  401faa:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
  401faf:	75 02                	jne    401fb3 <close@plt+0xe23>
  401fb1:	eb 16                	jmp    401fc9 <close@plt+0xe39>
  401fb3:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  401fb7:	48 01 45 f8          	add    %rax,-0x8(%rbp)
  401fbb:	48 81 7d f8 80 3e 00 	cmpq   $0x3e80,-0x8(%rbp)
  401fc2:	00 
  401fc3:	75 02                	jne    401fc7 <close@plt+0xe37>
  401fc5:	eb 02                	jmp    401fc9 <close@plt+0xe39>
  401fc7:	eb 91                	jmp    401f5a <close@plt+0xdca>
  401fc9:	48 c7 45 d8 fc 1b 40 	movq   $0x401bfc,-0x28(%rbp)
  401fd0:	00 
  401fd1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401fd5:	89 c1                	mov    %eax,%ecx
  401fd7:	48 8d 95 50 c1 ff ff 	lea    -0x3eb0(%rbp),%rdx
  401fde:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  401fe2:	89 ce                	mov    %ecx,%esi
  401fe4:	48 89 d7             	mov    %rdx,%rdi
  401fe7:	ff d0                	callq  *%rax
  401fe9:	83 f8 ff             	cmp    $0xffffffff,%eax
  401fec:	75 23                	jne    402011 <close@plt+0xe81>
  401fee:	bf 18 28 40 00       	mov    $0x402818,%edi
  401ff3:	e8 d8 f0 ff ff       	callq  4010d0 <puts@plt>
  401ff8:	48 8b 05 81 21 20 00 	mov    0x202181(%rip),%rax        # 604180 <stdout>
  401fff:	48 89 c7             	mov    %rax,%rdi
  402002:	e8 19 f0 ff ff       	callq  401020 <fflush@plt>
  402007:	b8 00 00 00 00       	mov    $0x0,%eax
  40200c:	e9 0e 02 00 00       	jmpq   40221f <close@plt+0x108f>
  402011:	48 c7 45 d8 19 1c 40 	movq   $0x401c19,-0x28(%rbp)
  402018:	00 
  402019:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40201d:	89 c1                	mov    %eax,%ecx
  40201f:	48 8d 95 50 c1 ff ff 	lea    -0x3eb0(%rbp),%rdx
  402026:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  40202a:	89 ce                	mov    %ecx,%esi
  40202c:	48 89 d7             	mov    %rdx,%rdi
  40202f:	ff d0                	callq  *%rax
  402031:	83 f8 ff             	cmp    $0xffffffff,%eax
  402034:	75 23                	jne    402059 <close@plt+0xec9>
  402036:	bf 4b 28 40 00       	mov    $0x40284b,%edi
  40203b:	e8 90 f0 ff ff       	callq  4010d0 <puts@plt>
  402040:	48 8b 05 39 21 20 00 	mov    0x202139(%rip),%rax        # 604180 <stdout>
  402047:	48 89 c7             	mov    %rax,%rdi
  40204a:	e8 d1 ef ff ff       	callq  401020 <fflush@plt>
  40204f:	b8 00 00 00 00       	mov    $0x0,%eax
  402054:	e9 c6 01 00 00       	jmpq   40221f <close@plt+0x108f>
  402059:	48 c7 45 d8 ba 19 40 	movq   $0x4019ba,-0x28(%rbp)
  402060:	00 
  402061:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402065:	89 c1                	mov    %eax,%ecx
  402067:	48 8d 95 50 c1 ff ff 	lea    -0x3eb0(%rbp),%rdx
  40206e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  402072:	89 ce                	mov    %ecx,%esi
  402074:	48 89 d7             	mov    %rdx,%rdi
  402077:	ff d0                	callq  *%rax
  402079:	89 45 f0             	mov    %eax,-0x10(%rbp)
  40207c:	8b 45 f0             	mov    -0x10(%rbp),%eax
  40207f:	83 f8 31             	cmp    $0x31,%eax
  402082:	74 4e                	je     4020d2 <close@plt+0xf42>
  402084:	83 f8 31             	cmp    $0x31,%eax
  402087:	7f 13                	jg     40209c <close@plt+0xf0c>
  402089:	83 f8 02             	cmp    $0x2,%eax
  40208c:	74 21                	je     4020af <close@plt+0xf1f>
  40208e:	83 f8 19             	cmp    $0x19,%eax
  402091:	0f 84 b7 00 00 00    	je     40214e <close@plt+0xfbe>
  402097:	e9 28 01 00 00       	jmpq   4021c4 <close@plt+0x1034>
  40209c:	83 f8 32             	cmp    $0x32,%eax
  40209f:	74 6f                	je     402110 <close@plt+0xf80>
  4020a1:	83 f8 64             	cmp    $0x64,%eax
  4020a4:	0f 84 df 00 00 00    	je     402189 <close@plt+0xff9>
  4020aa:	e9 15 01 00 00       	jmpq   4021c4 <close@plt+0x1034>
  4020af:	bf 68 28 40 00       	mov    $0x402868,%edi
  4020b4:	e8 17 f0 ff ff       	callq  4010d0 <puts@plt>
  4020b9:	48 8b 05 c0 20 20 00 	mov    0x2020c0(%rip),%rax        # 604180 <stdout>
  4020c0:	48 89 c7             	mov    %rax,%rdi
  4020c3:	e8 58 ef ff ff       	callq  401020 <fflush@plt>
  4020c8:	b8 02 00 00 00       	mov    $0x2,%eax
  4020cd:	e9 4d 01 00 00       	jmpq   40221f <close@plt+0x108f>
  4020d2:	bf ad 28 40 00       	mov    $0x4028ad,%edi
  4020d7:	e8 f4 ef ff ff       	callq  4010d0 <puts@plt>
  4020dc:	48 8b 05 9d 20 20 00 	mov    0x20209d(%rip),%rax        # 604180 <stdout>
  4020e3:	48 89 c7             	mov    %rax,%rdi
  4020e6:	e8 35 ef ff ff       	callq  401020 <fflush@plt>
  4020eb:	48 c7 45 d8 3b 1c 40 	movq   $0x401c3b,-0x28(%rbp)
  4020f2:	00 
  4020f3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4020f7:	89 c1                	mov    %eax,%ecx
  4020f9:	48 8d 95 50 c1 ff ff 	lea    -0x3eb0(%rbp),%rdx
  402100:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  402104:	89 ce                	mov    %ecx,%esi
  402106:	48 89 d7             	mov    %rdx,%rdi
  402109:	ff d0                	callq  *%rax
  40210b:	e9 f1 00 00 00       	jmpq   402201 <close@plt+0x1071>
  402110:	bf c1 28 40 00       	mov    $0x4028c1,%edi
  402115:	e8 b6 ef ff ff       	callq  4010d0 <puts@plt>
  40211a:	48 8b 05 5f 20 20 00 	mov    0x20205f(%rip),%rax        # 604180 <stdout>
  402121:	48 89 c7             	mov    %rax,%rdi
  402124:	e8 f7 ee ff ff       	callq  401020 <fflush@plt>
  402129:	48 c7 45 d8 19 1c 40 	movq   $0x401c19,-0x28(%rbp)
  402130:	00 
  402131:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402135:	89 c1                	mov    %eax,%ecx
  402137:	48 8d 95 50 c1 ff ff 	lea    -0x3eb0(%rbp),%rdx
  40213e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  402142:	89 ce                	mov    %ecx,%esi
  402144:	48 89 d7             	mov    %rdx,%rdi
  402147:	ff d0                	callq  *%rax
  402149:	e9 b3 00 00 00       	jmpq   402201 <close@plt+0x1071>
  40214e:	bf d8 28 40 00       	mov    $0x4028d8,%edi
  402153:	e8 78 ef ff ff       	callq  4010d0 <puts@plt>
  402158:	48 8b 05 21 20 20 00 	mov    0x202021(%rip),%rax        # 604180 <stdout>
  40215f:	48 89 c7             	mov    %rax,%rdi
  402162:	e8 b9 ee ff ff       	callq  401020 <fflush@plt>
  402167:	48 c7 45 d8 21 22 40 	movq   $0x402221,-0x28(%rbp)
  40216e:	00 
  40216f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402173:	89 c1                	mov    %eax,%ecx
  402175:	48 8d 95 50 c1 ff ff 	lea    -0x3eb0(%rbp),%rdx
  40217c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  402180:	89 ce                	mov    %ecx,%esi
  402182:	48 89 d7             	mov    %rdx,%rdi
  402185:	ff d0                	callq  *%rax
  402187:	eb 78                	jmp    402201 <close@plt+0x1071>
  402189:	bf 10 29 40 00       	mov    $0x402910,%edi
  40218e:	e8 3d ef ff ff       	callq  4010d0 <puts@plt>
  402193:	48 8b 05 e6 1f 20 00 	mov    0x201fe6(%rip),%rax        # 604180 <stdout>
  40219a:	48 89 c7             	mov    %rax,%rdi
  40219d:	e8 7e ee ff ff       	callq  401020 <fflush@plt>
  4021a2:	48 c7 45 d8 21 22 40 	movq   $0x402221,-0x28(%rbp)
  4021a9:	00 
  4021aa:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4021ae:	89 c1                	mov    %eax,%ecx
  4021b0:	48 8d 95 50 c1 ff ff 	lea    -0x3eb0(%rbp),%rdx
  4021b7:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  4021bb:	89 ce                	mov    %ecx,%esi
  4021bd:	48 89 d7             	mov    %rdx,%rdi
  4021c0:	ff d0                	callq  *%rax
  4021c2:	eb 3d                	jmp    402201 <close@plt+0x1071>
  4021c4:	bf 48 29 40 00       	mov    $0x402948,%edi
  4021c9:	e8 02 ef ff ff       	callq  4010d0 <puts@plt>
  4021ce:	48 8b 05 ab 1f 20 00 	mov    0x201fab(%rip),%rax        # 604180 <stdout>
  4021d5:	48 89 c7             	mov    %rax,%rdi
  4021d8:	e8 43 ee ff ff       	callq  401020 <fflush@plt>
  4021dd:	48 8b 05 ac 1f 20 00 	mov    0x201fac(%rip),%rax        # 604190 <stdout+0x10>
  4021e4:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
  4021e8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4021ec:	89 c1                	mov    %eax,%ecx
  4021ee:	48 8d 95 50 c1 ff ff 	lea    -0x3eb0(%rbp),%rdx
  4021f5:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  4021f9:	89 ce                	mov    %ecx,%esi
  4021fb:	48 89 d7             	mov    %rdx,%rdi
  4021fe:	ff d0                	callq  *%rax
  402200:	90                   	nop
  402201:	e8 fa ed ff ff       	callq  401000 <closelog@plt>
  402206:	48 8b 05 73 1f 20 00 	mov    0x201f73(%rip),%rax        # 604180 <stdout>
  40220d:	48 89 c7             	mov    %rax,%rdi
  402210:	e8 0b ee ff ff       	callq  401020 <fflush@plt>
  402215:	bf 01 00 00 00       	mov    $0x1,%edi
  40221a:	e8 91 ed ff ff       	callq  400fb0 <sleep@plt>
  40221f:	c9                   	leaveq 
  402220:	c3                   	retq   
  402221:	55                   	push   %rbp
  402222:	48 89 e5             	mov    %rsp,%rbp
  402225:	53                   	push   %rbx
  402226:	48 81 ec 28 0a 00 00 	sub    $0xa28,%rsp
  40222d:	48 89 bd d8 f5 ff ff 	mov    %rdi,-0xa28(%rbp)
  402234:	89 b5 d4 f5 ff ff    	mov    %esi,-0xa2c(%rbp)
  40223a:	48 b8 2f 74 6d 70 2f 	movabs $0x6d65742f706d742f,%rax
  402241:	74 65 6d 
  402244:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
  402248:	48 b8 70 58 58 58 58 	movabs $0x58585858585870,%rax
  40224f:	58 58 00 
  402252:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
  402256:	48 8d 85 e0 f9 ff ff 	lea    -0x620(%rbp),%rax
  40225d:	ba dc 05 00 00       	mov    $0x5dc,%edx
  402262:	be 00 00 00 00       	mov    $0x0,%esi
  402267:	48 89 c7             	mov    %rax,%rdi
  40226a:	e8 11 ed ff ff       	callq  400f80 <memset@plt>
  40226f:	48 8d 45 c0          	lea    -0x40(%rbp),%rax
  402273:	48 89 c7             	mov    %rax,%rdi
  402276:	e8 e5 ee ff ff       	callq  401160 <mktemp@plt>
  40227b:	48 8d 45 c0          	lea    -0x40(%rbp),%rax
  40227f:	48 83 c0 09          	add    $0x9,%rax
  402283:	be 75 29 40 00       	mov    $0x402975,%esi
  402288:	48 89 c7             	mov    %rax,%rdi
  40228b:	e8 d0 ed ff ff       	callq  401060 <strcmp@plt>
  402290:	85 c0                	test   %eax,%eax
  402292:	75 1e                	jne    4022b2 <close@plt+0x1122>
  402294:	be 80 29 40 00       	mov    $0x402980,%esi
  402299:	bf 03 00 00 00       	mov    $0x3,%edi
  40229e:	b8 00 00 00 00       	mov    $0x0,%eax
  4022a3:	e8 68 ec ff ff       	callq  400f10 <syslog@plt>
  4022a8:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  4022ad:	e8 8e ed ff ff       	callq  401040 <exit@plt>
  4022b2:	bf 00 00 00 00       	mov    $0x0,%edi
  4022b7:	e8 84 ee ff ff       	callq  401140 <umask@plt>
  4022bc:	48 8d 45 c0          	lea    -0x40(%rbp),%rax
  4022c0:	be f8 01 00 00       	mov    $0x1f8,%esi
  4022c5:	48 89 c7             	mov    %rax,%rdi
  4022c8:	e8 d3 ec ff ff       	callq  400fa0 <creat@plt>
  4022cd:	89 45 e8             	mov    %eax,-0x18(%rbp)
  4022d0:	83 7d e8 00          	cmpl   $0x0,-0x18(%rbp)
  4022d4:	79 1e                	jns    4022f4 <close@plt+0x1164>
  4022d6:	be a8 29 40 00       	mov    $0x4029a8,%esi
  4022db:	bf 03 00 00 00       	mov    $0x3,%edi
  4022e0:	b8 00 00 00 00       	mov    $0x0,%eax
  4022e5:	e8 26 ec ff ff       	callq  400f10 <syslog@plt>
  4022ea:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  4022ef:	e8 4c ed ff ff       	callq  401040 <exit@plt>
  4022f4:	8b 85 d4 f5 ff ff    	mov    -0xa2c(%rbp),%eax
  4022fa:	48 63 d0             	movslq %eax,%rdx
  4022fd:	48 8b 8d d8 f5 ff ff 	mov    -0xa28(%rbp),%rcx
  402304:	8b 45 e8             	mov    -0x18(%rbp),%eax
  402307:	48 89 ce             	mov    %rcx,%rsi
  40230a:	89 c7                	mov    %eax,%edi
  40230c:	e8 1f ec ff ff       	callq  400f30 <write@plt>
  402311:	8b 45 e8             	mov    -0x18(%rbp),%eax
  402314:	89 c7                	mov    %eax,%edi
  402316:	e8 75 ee ff ff       	callq  401190 <close@plt>
  40231b:	48 8b 85 d8 f5 ff ff 	mov    -0xa28(%rbp),%rax
  402322:	ba 80 3e 00 00       	mov    $0x3e80,%edx
  402327:	be 00 00 00 00       	mov    $0x0,%esi
  40232c:	48 89 c7             	mov    %rax,%rdi
  40232f:	e8 4c ec ff ff       	callq  400f80 <memset@plt>
  402334:	48 8d 85 e0 f9 ff ff 	lea    -0x620(%rbp),%rax
  40233b:	48 c7 c1 ff ff ff ff 	mov    $0xffffffffffffffff,%rcx
  402342:	48 89 c2             	mov    %rax,%rdx
  402345:	b8 00 00 00 00       	mov    $0x0,%eax
  40234a:	48 89 d7             	mov    %rdx,%rdi
  40234d:	f2 ae                	repnz scas %es:(%rdi),%al
  40234f:	48 89 c8             	mov    %rcx,%rax
  402352:	48 f7 d0             	not    %rax
  402355:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
  402359:	48 8d 85 e0 f9 ff ff 	lea    -0x620(%rbp),%rax
  402360:	48 01 d0             	add    %rdx,%rax
  402363:	48 bb 2f 75 73 72 2f 	movabs $0x6e69622f7273752f,%rbx
  40236a:	62 69 6e 
  40236d:	48 89 18             	mov    %rbx,(%rax)
  402370:	48 bb 2f 66 69 6c 65 	movabs $0x622d20656c69662f,%rbx
  402377:	20 2d 62 
  40237a:	48 89 58 08          	mov    %rbx,0x8(%rax)
  40237e:	66 c7 40 10 20 00    	movw   $0x20,0x10(%rax)
  402384:	48 8d 55 c0          	lea    -0x40(%rbp),%rdx
  402388:	48 8d 85 e0 f9 ff ff 	lea    -0x620(%rbp),%rax
  40238f:	48 89 d6             	mov    %rdx,%rsi
  402392:	48 89 c7             	mov    %rax,%rdi
  402395:	e8 96 ed ff ff       	callq  401130 <strcat@plt>
  40239a:	48 8d 85 e0 f9 ff ff 	lea    -0x620(%rbp),%rax
  4023a1:	be c9 29 40 00       	mov    $0x4029c9,%esi
  4023a6:	48 89 c7             	mov    %rax,%rdi
  4023a9:	e8 72 eb ff ff       	callq  400f20 <popen@plt>
  4023ae:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
  4023b2:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
  4023b7:	75 1e                	jne    4023d7 <close@plt+0x1247>
  4023b9:	be cb 29 40 00       	mov    $0x4029cb,%esi
  4023be:	bf 03 00 00 00       	mov    $0x3,%edi
  4023c3:	b8 00 00 00 00       	mov    $0x0,%eax
  4023c8:	e8 43 eb ff ff       	callq  400f10 <syslog@plt>
  4023cd:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  4023d2:	e8 69 ec ff ff       	callq  401040 <exit@plt>
  4023d7:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)
  4023de:	eb 43                	jmp    402423 <close@plt+0x1293>
  4023e0:	b8 80 3e 00 00       	mov    $0x3e80,%eax
  4023e5:	2b 45 ec             	sub    -0x14(%rbp),%eax
  4023e8:	48 98                	cltq   
  4023ea:	8b 55 ec             	mov    -0x14(%rbp),%edx
  4023ed:	48 63 d2             	movslq %edx,%rdx
  4023f0:	48 8d 8d e0 f5 ff ff 	lea    -0xa20(%rbp),%rcx
  4023f7:	48 8d 3c 11          	lea    (%rcx,%rdx,1),%rdi
  4023fb:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
  4023ff:	48 89 d1             	mov    %rdx,%rcx
  402402:	ba 01 00 00 00       	mov    $0x1,%edx
  402407:	48 89 c6             	mov    %rax,%rsi
  40240a:	e8 b1 ec ff ff       	callq  4010c0 <fread@plt>
  40240f:	89 45 dc             	mov    %eax,-0x24(%rbp)
  402412:	8b 45 dc             	mov    -0x24(%rbp),%eax
  402415:	01 45 ec             	add    %eax,-0x14(%rbp)
  402418:	81 7d ec 80 3e 00 00 	cmpl   $0x3e80,-0x14(%rbp)
  40241f:	75 02                	jne    402423 <close@plt+0x1293>
  402421:	eb 10                	jmp    402433 <close@plt+0x12a3>
  402423:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  402427:	48 89 c7             	mov    %rax,%rdi
  40242a:	e8 b1 ec ff ff       	callq  4010e0 <feof@plt>
  40242f:	85 c0                	test   %eax,%eax
  402431:	74 ad                	je     4023e0 <close@plt+0x1250>
  402433:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  402437:	48 89 c7             	mov    %rax,%rdi
  40243a:	e8 41 ec ff ff       	callq  401080 <pclose@plt>
  40243f:	48 8d 45 c0          	lea    -0x40(%rbp),%rax
  402443:	48 89 c7             	mov    %rax,%rdi
  402446:	e8 05 eb ff ff       	callq  400f50 <unlink@plt>
  40244b:	89 45 d8             	mov    %eax,-0x28(%rbp)
  40244e:	83 7d d8 ff          	cmpl   $0xffffffff,-0x28(%rbp)
  402452:	75 1e                	jne    402472 <close@plt+0x12e2>
  402454:	be e8 29 40 00       	mov    $0x4029e8,%esi
  402459:	bf 03 00 00 00       	mov    $0x3,%edi
  40245e:	b8 00 00 00 00       	mov    $0x0,%eax
  402463:	e8 a8 ea ff ff       	callq  400f10 <syslog@plt>
  402468:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  40246d:	e8 ce eb ff ff       	callq  401040 <exit@plt>
  402472:	48 8d 85 e0 f5 ff ff 	lea    -0xa20(%rbp),%rax
  402479:	48 89 c7             	mov    %rax,%rdi
  40247c:	e8 4f ec ff ff       	callq  4010d0 <puts@plt>
  402481:	48 8b 05 f8 1c 20 00 	mov    0x201cf8(%rip),%rax        # 604180 <stdout>
  402488:	48 89 c7             	mov    %rax,%rdi
  40248b:	e8 90 eb ff ff       	callq  401020 <fflush@plt>
  402490:	b8 00 00 00 00       	mov    $0x0,%eax
  402495:	48 81 c4 28 0a 00 00 	add    $0xa28,%rsp
  40249c:	5b                   	pop    %rbx
  40249d:	5d                   	pop    %rbp
  40249e:	c3                   	retq   
  40249f:	55                   	push   %rbp
  4024a0:	48 89 e5             	mov    %rsp,%rbp
  4024a3:	53                   	push   %rbx
  4024a4:	48 81 ec 38 01 00 00 	sub    $0x138,%rsp
  4024ab:	48 89 bd c8 fe ff ff 	mov    %rdi,-0x138(%rbp)
  4024b2:	89 b5 c4 fe ff ff    	mov    %esi,-0x13c(%rbp)
  4024b8:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)
  4024bf:	48 8b 15 ea 1c 20 00 	mov    0x201cea(%rip),%rdx        # 6041b0 <stdout+0x30>
  4024c6:	48 8d 85 d0 fe ff ff 	lea    -0x130(%rbp),%rax
  4024cd:	48 89 d6             	mov    %rdx,%rsi
  4024d0:	48 89 c7             	mov    %rax,%rdi
  4024d3:	e8 18 eb ff ff       	callq  400ff0 <strcpy@plt>
  4024d8:	48 8d 85 d0 fe ff ff 	lea    -0x130(%rbp),%rax
  4024df:	48 c7 c1 ff ff ff ff 	mov    $0xffffffffffffffff,%rcx
  4024e6:	48 89 c2             	mov    %rax,%rdx
  4024e9:	b8 00 00 00 00       	mov    $0x0,%eax
  4024ee:	48 89 d7             	mov    %rdx,%rdi
  4024f1:	f2 ae                	repnz scas %es:(%rdi),%al
  4024f3:	48 89 c8             	mov    %rcx,%rax
  4024f6:	48 f7 d0             	not    %rax
  4024f9:	48 8d 50 ff          	lea    -0x1(%rax),%rdx
  4024fd:	48 8d 85 d0 fe ff ff 	lea    -0x130(%rbp),%rax
  402504:	48 01 d0             	add    %rdx,%rax
  402507:	48 bb 77 65 6c 63 6f 	movabs $0x2e656d6f636c6577,%rbx
  40250e:	6d 65 2e 
  402511:	48 89 18             	mov    %rbx,(%rax)
  402514:	c7 40 08 74 78 74 00 	movl   $0x747874,0x8(%rax)
  40251b:	48 c7 45 a0 00 00 00 	movq   $0x0,-0x60(%rbp)
  402522:	00 
  402523:	bf 00 10 00 00       	mov    $0x1000,%edi
  402528:	e8 23 eb ff ff       	callq  401050 <malloc@plt>
  40252d:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
  402531:	48 c7 45 a8 00 10 00 	movq   $0x1000,-0x58(%rbp)
  402538:	00 
  402539:	48 c7 45 b0 00 00 00 	movq   $0x0,-0x50(%rbp)
  402540:	00 
  402541:	bf 03 00 00 00       	mov    $0x3,%edi
  402546:	e8 35 ec ff ff       	callq  401180 <curl_global_init@plt>
  40254b:	e8 c0 ea ff ff       	callq  401010 <curl_easy_init@plt>
  402550:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
  402554:	c7 45 dc 12 27 00 00 	movl   $0x2712,-0x24(%rbp)
  40255b:	8b 4d dc             	mov    -0x24(%rbp),%ecx
  40255e:	48 8d 95 d0 fe ff ff 	lea    -0x130(%rbp),%rdx
  402565:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  402569:	89 ce                	mov    %ecx,%esi
  40256b:	48 89 c7             	mov    %rax,%rdi
  40256e:	b8 00 00 00 00       	mov    $0x0,%eax
  402573:	e8 f8 ea ff ff       	callq  401070 <curl_easy_setopt@plt>
  402578:	c7 45 d8 2b 4e 00 00 	movl   $0x4e2b,-0x28(%rbp)
  40257f:	8b 4d d8             	mov    -0x28(%rbp),%ecx
  402582:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  402586:	ba 1d 13 40 00       	mov    $0x40131d,%edx
  40258b:	89 ce                	mov    %ecx,%esi
  40258d:	48 89 c7             	mov    %rax,%rdi
  402590:	b8 00 00 00 00       	mov    $0x0,%eax
  402595:	e8 d6 ea ff ff       	callq  401070 <curl_easy_setopt@plt>
  40259a:	c7 45 d4 11 27 00 00 	movl   $0x2711,-0x2c(%rbp)
  4025a1:	8b 4d d4             	mov    -0x2c(%rbp),%ecx
  4025a4:	48 8d 55 a0          	lea    -0x60(%rbp),%rdx
  4025a8:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  4025ac:	89 ce                	mov    %ecx,%esi
  4025ae:	48 89 c7             	mov    %rax,%rdi
  4025b1:	b8 00 00 00 00       	mov    $0x0,%eax
  4025b6:	e8 b5 ea ff ff       	callq  401070 <curl_easy_setopt@plt>
  4025bb:	c7 45 d0 22 27 00 00 	movl   $0x2722,-0x30(%rbp)
  4025c2:	8b 4d d0             	mov    -0x30(%rbp),%ecx
  4025c5:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  4025c9:	ba 3d 27 40 00       	mov    $0x40273d,%edx
  4025ce:	89 ce                	mov    %ecx,%esi
  4025d0:	48 89 c7             	mov    %rax,%rdi
  4025d3:	b8 00 00 00 00       	mov    $0x0,%eax
  4025d8:	e8 93 ea ff ff       	callq  401070 <curl_easy_setopt@plt>
  4025dd:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  4025e1:	48 89 c7             	mov    %rax,%rdi
  4025e4:	e8 07 eb ff ff       	callq  4010f0 <curl_easy_perform@plt>
  4025e9:	89 45 cc             	mov    %eax,-0x34(%rbp)
  4025ec:	83 7d cc 00          	cmpl   $0x0,-0x34(%rbp)
  4025f0:	74 2b                	je     40261d <close@plt+0x148d>
  4025f2:	8b 45 cc             	mov    -0x34(%rbp),%eax
  4025f5:	89 c7                	mov    %eax,%edi
  4025f7:	e8 14 eb ff ff       	callq  401110 <curl_easy_strerror@plt>
  4025fc:	48 89 c2             	mov    %rax,%rdx
  4025ff:	be 50 27 40 00       	mov    $0x402750,%esi
  402604:	bf 03 00 00 00       	mov    $0x3,%edi
  402609:	b8 00 00 00 00       	mov    $0x0,%eax
  40260e:	e8 fd e8 ff ff       	callq  400f10 <syslog@plt>
  402613:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  402618:	e8 23 ea ff ff       	callq  401040 <exit@plt>
  40261d:	c7 45 c8 02 00 20 00 	movl   $0x200002,-0x38(%rbp)
  402624:	8b 4d c8             	mov    -0x38(%rbp),%ecx
  402627:	48 8d 55 c0          	lea    -0x40(%rbp),%rdx
  40262b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  40262f:	89 ce                	mov    %ecx,%esi
  402631:	48 89 c7             	mov    %rax,%rdi
  402634:	b8 00 00 00 00       	mov    $0x0,%eax
  402639:	e8 02 e9 ff ff       	callq  400f40 <curl_easy_getinfo@plt>
  40263e:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
  402642:	48 3d 94 01 00 00    	cmp    $0x194,%rax
  402648:	75 07                	jne    402651 <close@plt+0x14c1>
  40264a:	c7 45 ec ff ff ff ff 	movl   $0xffffffff,-0x14(%rbp)
  402651:	8b 85 c4 fe ff ff    	mov    -0x13c(%rbp),%eax
  402657:	48 63 d0             	movslq %eax,%rdx
  40265a:	48 8b 4d a0          	mov    -0x60(%rbp),%rcx
  40265e:	48 8b 85 c8 fe ff ff 	mov    -0x138(%rbp),%rax
  402665:	48 89 ce             	mov    %rcx,%rsi
  402668:	48 89 c7             	mov    %rax,%rdi
  40266b:	e8 00 e9 ff ff       	callq  400f70 <strncpy@plt>
  402670:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
  402674:	48 89 c7             	mov    %rax,%rdi
  402677:	e8 b4 e9 ff ff       	callq  401030 <free@plt>
  40267c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  402680:	48 89 c7             	mov    %rax,%rdi
  402683:	e8 28 ea ff ff       	callq  4010b0 <curl_easy_cleanup@plt>
  402688:	e8 73 e8 ff ff       	callq  400f00 <curl_global_cleanup@plt>
  40268d:	8b 45 ec             	mov    -0x14(%rbp),%eax
  402690:	48 81 c4 38 01 00 00 	add    $0x138,%rsp
  402697:	5b                   	pop    %rbx
  402698:	5d                   	pop    %rbp
  402699:	c3                   	retq   
  40269a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  4026a0:	41 57                	push   %r15
  4026a2:	41 89 ff             	mov    %edi,%r15d
  4026a5:	41 56                	push   %r14
  4026a7:	49 89 f6             	mov    %rsi,%r14
  4026aa:	41 55                	push   %r13
  4026ac:	49 89 d5             	mov    %rdx,%r13
  4026af:	41 54                	push   %r12
  4026b1:	4c 8d 25 40 17 20 00 	lea    0x201740(%rip),%r12        # 603df8 <_fini+0x2016e4>
  4026b8:	55                   	push   %rbp
  4026b9:	48 8d 2d 48 17 20 00 	lea    0x201748(%rip),%rbp        # 603e08 <_fini+0x2016f4>
  4026c0:	53                   	push   %rbx
  4026c1:	4c 29 e5             	sub    %r12,%rbp
  4026c4:	31 db                	xor    %ebx,%ebx
  4026c6:	48 c1 fd 03          	sar    $0x3,%rbp
  4026ca:	48 83 ec 08          	sub    $0x8,%rsp
  4026ce:	e8 f5 e7 ff ff       	callq  400ec8 <_init>
  4026d3:	48 85 ed             	test   %rbp,%rbp
  4026d6:	74 1e                	je     4026f6 <close@plt+0x1566>
  4026d8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4026df:	00 
  4026e0:	4c 89 ea             	mov    %r13,%rdx
  4026e3:	4c 89 f6             	mov    %r14,%rsi
  4026e6:	44 89 ff             	mov    %r15d,%edi
  4026e9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  4026ed:	48 83 c3 01          	add    $0x1,%rbx
  4026f1:	48 39 eb             	cmp    %rbp,%rbx
  4026f4:	75 ea                	jne    4026e0 <close@plt+0x1550>
  4026f6:	48 83 c4 08          	add    $0x8,%rsp
  4026fa:	5b                   	pop    %rbx
  4026fb:	5d                   	pop    %rbp
  4026fc:	41 5c                	pop    %r12
  4026fe:	41 5d                	pop    %r13
  402700:	41 5e                	pop    %r14
  402702:	41 5f                	pop    %r15
  402704:	c3                   	retq   
  402705:	66 66 2e 0f 1f 84 00 	data32 nopw %cs:0x0(%rax,%rax,1)
  40270c:	00 00 00 00 
  402710:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000402714 <_fini>:
  402714:	48 83 ec 08          	sub    $0x8,%rsp
  402718:	48 83 c4 08          	add    $0x8,%rsp
  40271c:	c3                   	retq   
