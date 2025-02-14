---
title:  Go calling conventions
categories: [RE, Go]
tags: [go, cgo, cgo_callback, go_internals, go_calling_conventions]     # TAG names should always be lowercase
---

Few notes on Go calling conventions, setting the custom calling convention in IDA Pro \_\_usercall and GO internals.  In the malware trainings related to analysis of Go internals, Go dlls are not always covered. Personally ive rarely enconuntered any malware incorporating reflective loaders in Go, thats why i decided to write this quick guide for myself to refer to while reversing Go. 
## Go calling conventions
The official GO documentation says the following on the go calling convention.
Example:
```go
func f(a1 uint8, a2 [2]uintptr, a3 uint8) (r1 struct { x uintptr; y [2]uintptr }, r2 string) 
// on a 64-bit architecture with hypothetical integer registers R0–R9.
```

```
On entry:
  a1 goes to R0
  a3 goes to R1 
Stack frame is laid out in the following sequence:
— — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — —  lower address
  a2      [2]uintptr    <— stack-assigned arguments
  r1.x    uintptr       <— stack-assigned results 
  r1.y    [2]uintptr    <
  a1Spill uint8         <— arg spill area
  a3Spill uint8         <— arg spill area
  _       [6]uint8      <— alignment padding
— — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — —  higher address
[!] In the stack frame, only the a2 field is initialized on entry, the rest of the frame is left uninitialized.
[!] Only arguments, not results, are assigned a spill area on the stack.
On exit:
	r2.base goes to R0  	<-- Result r2 is decomposed into its components, which are individually register-assigned. 
	r2.len goes to R1
	r1.x and r1.y are initialized in the stack frame.
[!] a2 and r1 are stack-assigned because they contain arrays.
```

## Go ABI
The other problem ive stumbled upon is numerous calling conventions, that really make debugging hard especially in Go where many of them are fused in a single binary. To end this mess ive wrote this small cheat sheet:

**gcc ABI**: Used by gcc for C/C++ code.
**x64_86 (64-bit)**
- **Linux**:
    - **Arguments**: First : `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`.
    - **Additional arguments**:  `stack`.
    - **Return value**:  `rax`.
- **Windows**:
    - **Arguments**: `rcx`, `rdx`, `r8`, `r9`.
    - **Additional arguments**:  `stack`
    - **Return value**:  `rax`.  
**x86 (32-bit)**
- **Linux and Windows**:
    - **Arguments**: `stack`.
    - **Return value**:  `eax`.

**Go ABI**: A general term for Go’s calling conventions (includes ABI0 and ABIInternal).
- **Platform-specific**:
    - When Go interacts with external code (e.g., C or assembly), it uses the platform’s native ABI (e.g., gcc ABI on Linux).
    - For example:
        - On Linux x86-64, Go uses `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` for arguments (matching the gcc ABI).
        - On Windows x86-64, Go uses `rcx`, `rdx`, `r8`, `r9` for arguments (matching the Windows ABI).

**ABI0**: The old, stack-based Go ABI (deprecated).

**ABIInternal**: The current, register-based Go ABI.
- **Registers used for arguments**:
    - Go’s ABI uses a **custom set of registers** to pass arguments, which may include `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`, `r9`, `r10`, `r11`, etc.
    - The exact registers used depend on the function signature and the Go compiler’s optimization decisions.

**ABI Platform**: The platform-specific ABI used for interfacing with external code (also used by Go when calling C code )
## Go entitites
This causes a lot of confusion so i had to make a quick rundown on common go structures.

- `g` - Goroutine, lightweight thread in Go, has a `user stack` associated with it
- `p` - Processor, a logical entity that manages scheduling of goroutines onto threads.
- `m` -  Machine, OS-level thread, has a `system stack` associated with it, also known as `g0` (on Unix platforms, a `signal stack`).
- `p.GoF` - Go Function associated with a processor.
- `m.g0` - system goroutine associated with an OS thread.

All `g`, `m`, and `p` objects are heap allocated, but are never freed, so their memory remains type stable. As a result, the runtime can avoid write barriers in the depths of the scheduler.

- `getg().m.curg` - to get the current user `g`
- `getg()` - returns the current `g`, but when executing on the system or signal stacks, this will return the current M’s “g0” or “gsignal”, respectively
- `getg() == getg().m.curg` - to determine if you’re running on the user stack or the system stack.

![figure](/assets/img/2025-02-15-Go-calling-conventions/1_ts4May4b6Oqt_N2JAEBXCQ 1.webp)

## CGO callback / Go —> C

If gcc compiled function f callling back to Go this is what happens next. To make it possible for gcc-compiled C code to call a Go function `p.GoF`,  cgo writes a gcc-compiled function named `GoF`  (not `p.GoF`, since gcc doesn't know about packages) which acts like a bridge.  This `GoF` function is written in C and is an intermediary between the C code and the Go runtime. The gcc-compiled C function f calls `GoF`. `GoF` initializes "frame", a structure containing all of its arguments and slots for `p.GoF`'s results. It calls `crosscall2 (_cgoexp_GoF, frame, framesize, ctxt)` using the `gcc ABI`.

### crosscall2
`crosscall2` is a four-argument adapter from the `gcc function call ABI` to the `gc function call ABI`. Code of this function is running in the Go runtime, but  it still executing on `m.g0`'s stack and outside the $GOMAXPROCS limit. `crosscall2` saves C callee-saved registers and calls `cgocallback (_cgoexp_GoF, frame, ctxt)` using the `gc ABI`.
```c
// C syntax
void crosscall2 (void (*_cgoexp_GoF)(void *), void * frame, __int32 framesize , __int64 ctxt);
```

```go
// Go syntax
func crosscall2(_cgoexp_GoF, frame unsafe.Pointer, framesize int32, ctxt uintptr)
// gcc ABI.
// _cgoexp_GoF is the PC of frame func(frame unsafe.Pointer) function.
```

crosscall2 is a low-level function and it varies from arch to arch, for the sake of brevity only `amd64` architecture is  examined here.
```nasm
; ASM syntax
crosscall2:
    push rdi ; Save registers (PUSH_REGS_HOST_TO_ABI0)
    push rsi
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0x18 
#ifndef GOOS_windows
    ; Store arguments on the stack (non-Windows)
    mov [rsp], rdi        ; fn
    mov [rsp + 0x8], rsi  ; arg
    ; Skip n in DX
    mov [rsp + 0x10], rcx ; ctxt
#else
    ; Store arguments on the stack (Windows)
    mov [rsp], rcx        ; fn
    mov [rsp + 0x8], rdx  ; arg
						  ; Skip n in R8
    mov [rsp + 0x10], r9  ; ctxt
#endif
    call runtime_cgocallback ; Call runtime·cgocallback    
    add rsp, 0x18			 ; Restore stack
    pop r15 				 ; Restore registers (POP_REGS_HOST_TO_ABI0)
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop rsi
    pop rdi
    ret 
```

Parameters for `crosscall2` function call passed via `rcx`, `rdx`, `r8d`, `r9`. This matches platform ABI - Windows.  

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250213204813.png)


Moving futher inside the crosscall2, we see call to `cgocallback` which uses the same arguments we passed before into `crosscall2` but this time `gc ABI `is used.  

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250213205845.png)

The problem here is that IDA by default cant recognize `gc ABI` so custom calling convention `__usercall` must be set.
```c
void __usercall runtime_cgocallback (
  __int64 *cgoexp_GoF@<0:^0.8>, 
  void *frame@<0:^8.8>,
  __int64 *ctxt@<0:^16.8>
 );
```

We are all set!

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250213204948c.png)

### cgocallback
Switches from `m.g0`'s stack to the original g (`m.curg`)'s stack, on which it calls `cgocallbackg(_cgoexp_GoF, frame, ctxt)`. cgocallback saves the current stack pointer `SP` as `m.g0.sched.sp`, so that any use of `m.g0`'s stack during the execution of the callback will be done below the existing stack frames. Before overwriting `m.g0.sched.sp`, it pushes the old value on the `m.g0` stack, so that it can be restored later.

```c
void __usercall runtime_cgocallbackg_0 (
  __int64 *cgoexp_GoF@<0:^0.8>, 
  void *frame@<0:^8.8>, 
  __int64 *ctxt@<0:^16.8>
  );
```
[!] Quick note: Parsing golang metadata couldnt help a bit as most of the metadata was stripped from the binary. Thats why golang plugin failed miserably. But can try any way (Edit>Other>golang:detect_and_parse)

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250213214830.png)

### cgocallbackg
Now code of this function is executed on a real goroutine stack (not `m.g0`). This function mostly responsible for ensuring stack unwindling ( `m.g0.sched.sp`) if panic occurs. Also it calls `runtime.entersyscall` function that  ensures that $GOMAXPROCS is not exceeded by blocking execution.
Then it calls `_cgoexp_GoF(frame)`.
```c
void __usercall runtime_cgocallbackg(
  void (*fn)(void *)@<rax>, 
  void *frame@<rbx>, 
  unsigned __int64 ctxt@<rcx>
  );
```
 For some reason IDA refuses to recognize `__golang` convention. Setting `__golang` does not automatically comment argumetns passed into function. Thats why again we set custom defined `__usercall` 

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250214220607.png)

[!] Quick note: the `ctxt` variable is of type `uintptr`  that  is "an integer type that is large enough to contain the bit pattern of any pointer" in Go . Despite its confusing name `uintptr` is not a pointer but an integer, thats why `ctxt` vairable is  of type `unsigned __int64` and not `unsigned __int64 *`.

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250214220710.png)

### cgocallbackg1
The last frontier of our journey  `cgocallbackg1` 

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250215000439.png)

Now here is another trick, we see a register based call, its not the same as a call to constant function address. Sometimes IDA can be a little buggy while setting call and value types. Here we examine 2 ways, in which proper function argument recognition may be achieved, they are somewhat different.
Initially we a presented with this state, `cgocallbackg1` eventually calls function `fn` with the  `void* frame` variable, but it is nowhere to be seen inside the `fn` brackets. Clearly it was passed via `rax`.
![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250215001721.png)
One might say we can just set `__golang`, but it just wont work, simply because in `ABIInternal` is not standartized way of passing arguments to function. We might stumble upon function where arguments passed via `rsi`, `rdi` and setting `__golang` will not help in any way to make IDA recognize arguments. 
By pressing `Y` we set value type to the following signature.
```c
void (__usercall *) (void *@<rax>); // value type
```
Then select `force call type`

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250214234943.png)

Now function arguments recognized correctly.

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250215000921.png)

Ot the other way by setting `call type`:
```c
void __usercall fn(void *frame@<rax>); // call type
```
Now IDA properly recognized function call and arguments:

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250215004447.png)

This matches the official documentation of the Go :
```go
func cgocallbackg1(fn, frame unsafe.Pointer, ctxt uintptr) {
	// code ...
	// Invoke callback. This function is generated by cmd/cgo and
	// will unpack the argument frame and call the Go function.
	var cb func(frame unsafe.Pointer)
	cbFV := funcval{uintptr(fn)}
	*(*unsafe.Pointer)(unsafe.Pointer(&cb)) = noescape(unsafe.Pointer(&cbFV))
	cb(frame)    // fn is the same as cb, cb stand for callback
	// code ...
}
```

Upon examination of the function to be invoked  we see that it has no return value so we set return type to `void` This is our long waited callback function, this is the exact function that was meant to be called from the very beginning. Here callback invoked via `rsi` with an `rax` being passed as an argument. `rax` takes its value from `rbx` which in turn takes its value from stack at 0x78 offset.

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250215010349.png)

### \_cgoexp_GoF(frame) aka cb(frame)
unpacks the arguments from frame, calls `p.GoF`, writes the results back to frame, and returns. Now we start unwinding this whole process. Indeed this function that accepted parameter via `rax` uses it to perform unpacking into registers.

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250213233506.png)

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250213233638.png)

### Unwindling.
Now the execution is returned back to `cgocallbackg`. `cgocallbackg` calls `entersyscall` and returns `cgocallback`. `cgocallback` switches stack back to `m.g0`'s stack.  restores the old stack pointer `m.g0.sched.sp` value from the stack and returns to `crosscall2` .`crosscall2` restores the callee-save registers for gcc and returns to `GoF`, which unpacks any result values and returns to `f`. So the end chain of called functions looks like this:

runtime.crosscall2()	
	runtime.cgocallback()	
		runtime.cgocallbackg()	
			\_cgoexp_GoF()

## CGO / C —> Go
Before you read this section, check out this cool [article](https://leandrofroes.github.io/posts/An-in-depth-look-at-Golang-Windows-calls/) related to CGO internals, that covers topic on WinAPI functions' address resolution. The author also explains cgocalls and asmcgocall function internal structure. I've started reversing Go internal without knowing inbeforehand about this article, so some things might overlap, anyways feel free to add your remarks and comments. Whenever GO calls C functions it invokes `stdcall` function from the runtime package. `stdcall` function itself has internal mechanisms. Internal it includes the following chain of functions that is called in consecutive order.

[package] runtime.
stdcall
	asmcgocall
		asmstdcall

`stdcall` function has 9 implementations (stdcall0 ... stdcall8), depending on the amount of arguments. Inside the binary it is common to the these names among functions' list:

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250213003853.png)

### Case study - initHighResTimer

We will look inside Go function from the runtime package - runtime.initHighResTimer. 

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250209164838.png)

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250215022513.png)

Right from the start we can see that IDA ncorrectly determined calling convention `__fastcall` along with number of arguments.  stdcall4 has only 5 parameters. The Go `stdcall4` prototype defined as follows:
```go
func stdcall4(fn stdFunction, a0, a1, a2, a3 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 4
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}
```
 So we change that a little to make conform to the `gcc ABI` by setting `__stdcall` and removing unnecessary trailing parameter.

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250209173329.png)

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250215022248.png)

Here we see how in `rax` passed offset to other offset that points to WinAPi `CreateWaitTableTimerExW` . But because second argument if of type float, it was passed via `xmm15` register takes 16 bytes in size, this means variable will take place of 2 args in stack, thats why total count of arguments passed is 4 and not 5. Also function uses platform ABI as it is about to call Windows specific function written in C (stdcall). 
![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250214181425.png)
Thats why the right calling convention is as follows:
```c
__int64 __stdcall runtime_stdcall4(__int64 fn, __m128  a0, __int64 a1, __int64 a2)
```

This is equivalent to customly set `__usercall` convention.
```c
void __usercall runtime_stdcall4(
	__int64 fn@<^0.8>,  //  __int64, offset 0x0, size 8 bytes 
	__m128 a0@<^8.16>,  //  __m128, offset 0x8, size 16 bytes
	__int64 a1@<^18.8>, //  __int64, offset 0x18, size 8 bytes 
	__int64 a2@<^20.8>  //  __int64, offset 0x20, size 8 bytes
	);
```

Nex there is `stdcall` function call takes place, `stdcall` structure looks like this:
```go 
func stdcall(fn stdFunction) uintptr {
	gp := getg()
	mp := gp.m
	mp.libcall.fn = uintptr(unsafe.Pointer(fn))
	resetLibcall := false
	if mp.profilehz != 0 && mp.libcallsp == 0 {
		// leave pc/sp for cpu profiler
		mp.libcallg.set(gp)
		mp.libcallpc = getcallerpc()
		// sp must be the last, because once async cpu profiler finds
		// all three values to be non-zero, it will use them
		mp.libcallsp = getcallersp()
		resetLibcall = true // See comment in sys_darwin.go:libcCall
	}
	asmcgocall(asmstdcallAddr, unsafe.Pointer(&mp.libcall))
	if resetLibcall {
		mp.libcallsp = 0
	}
	return mp.libcall.r1
}
```

asmcgocall function signature
```go
func asmcgocall(fn, arg unsafe.Pointer) int32
```

asmcgocall internal structure
```nasm
asmcgocall:
    ; Load arguments from stack (Go ABI)
    mov rax, [rsp + 8]        ; fn 
    mov rbx, [rsp + 16]       ; arg 
    mov rdx, rsp              ; Save SP

    ; Check if we need to switch to m->g0 stack
    mov rcx, gs:[0]           ; get_tls(CX)
    mov rdi, [rcx]            ; g = tls->g
    test rdi, rdi
    jz nosave                 ; Skip if g == nil

    ; Check if already on gsignal or g0 stack
    mov r8, [rdi + 8]         ; g.m (offset of m in g struct)
    mov rsi, [r8 + 0x10]      ; m->gsignal
    cmp rdi, rsi
    je nosave                 ; Already on gsignal stack
    mov rsi, [r8 + 0x18]      ; m->g0
    cmp rdi, rsi
    je nosave                 ; Already on g0 stack
	
    call gosave_systemstack_switch	; Switch to system stack (m->g0)
    mov [rcx], rsi            ; tls->g = m->g0
    mov rsp, [rsi + 0x28]     ; Restore SP from g0.sched.sp

    ; Prepare stack for C ABI (16-byte aligned)
    sub rsp, 16
    and rsp, -16              ; Align to 16 bytes
    mov [rsp + 8], rdi        ; Save original g
    mov rdi, [rdi + 0x30]     ; g->stack.hi
    sub rdi, rdx              ; Calculate stack depth
    mov [rsp], rdi            
    call runtime.asmcgocall_landingpad     
    ; Restore stack and registers
    mov rcx, gs:[0]           ; get_tls(CX)
    mov rdi, [rsp + 8]        ; Restore original g
    mov rsi, [rdi + 0x30]     ; g->stack.hi
    sub rsi, [rsp]            ; Calculate new SP
    mov [rcx], rdi            ; tls->g = original g
    mov rsp, rsi              ; Restore SP
    mov [rsp + 24], eax       ; Store return value
    ret

nosave:
    ; Already on a system stack (m->g0 or m->gsignal). No g to save.
    sub rsp, 16                ; Allocate 16 bytes for alignment
    and rsp, -15               ; Align stack to 16 bytes (~15 = 0xFFFFFFFFFFFFFFF0)
    
	; Prepare stack for debugging (even though no g is saved)
    mov qword [rsp + 8], 0     ; Store 0 where g would normally be saved (for debuggers)
    mov [rsp], rdx             ; Save original SP (from DX) at [rsp + 0]
    call runtime.asmcgocall_landingpad 
    mov rsi, [rsp]             ; Restore original stack pointer
    mov rsp, rsi               
    mov dword [rsp + 24], eax  ; Store 32-bit return value
    ret
```

asmcgocall IDA view

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250213002503.png)

## A few more examples

By default IDA cant recognize GO function arguments so it just skips them. For  example , decompiled go functionby Ida:
```c
__int64 __fastcall fn_1() // no parameters
```

But if we look at the dissassembly, we there are actually a few arguments passed to function. Diasassembly:
```nasm
mov     rax, [rsp+88h]
mov     rbx, [rsp+40h]
call    fn_1
mov     [rsp+0B8h], rax
mov     [rsp+70h], rbx
```

Now, after applying out custom calling convention, our function prototypes look like this:
```c
struct go_str __usercall fn_1@<rax,rbx>(struct go_str s@<rax,rbx>);

void __usercall fn_2( __int64 a1@<rdi>, __int64 a2@<rsi>);

void __usercall fn_3(__int64 r1@<rax>,__int64 r2@<rbx>, __int64 r3@<rcx>, __int64 r4@<rdi>);
```

#### Example 1
How it looks in IDA:

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250131165919.png)

IDA function prototype for setting custom calling convention:
``` c
 __void __usercall fn (__mm128 a@<xmm15>, __int64 a@<rdi>)
```

The function disassembly:
```nasm
movups  xmmword ptr [rsp+60h], xmm15
lea     rdi, [rsp+68h]
lea     rdi, [rdi-30h]
nop     word ptr [rax+rax+00000000h]
nop     dword ptr [rax+rax+00000000h]
mov     [rsp-10h], rbp
lea     rbp, [rsp-10h]
call    fn
```

#### Example 2
How it looks in IDA:

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250131173741.png)

Function actually just copies 80 bytes ( 5 x 16 )from rsi to rdi pointers:

![figure](/assets/img/2025-02-15-Go-calling-conventions/Pasted image 20250131173930.png)

## Resources
- https://go.dev/src/runtime/HACKING
- https://go.dev/src/runtime/os_windows.go
- https://go.dev/src/runtime/cgo/asm_386.s
- https://go.dev/src/runtime/cgo/asm_amd64.s
- https://medium.com/@aditimishra_541/what-are-go-processors-bfc13b38095e
- https://leandrofroes.github.io/posts/An-in-depth-look-at-Golang-Windows-calls/
- https://hex-rays.com/blog/igors-tip-of-the-week-51-custom-calling-conventions
