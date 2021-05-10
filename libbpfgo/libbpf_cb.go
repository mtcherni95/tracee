package libbpfgo


/*
#cgo LDFLAGS: -lelf -lz -lbpf
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

#include <asm-generic/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <string.h>
#include <unistd.h>
typedef struct A {
	int size;
	__u32 ctx;
	void* ptr;
} MyData;
 */
import "C"

import (
	"fmt"
	"unsafe"
)

// This callback definition needs to be in a different file from where it is declared in C
// Otherwise, multiple definition compilation error will occur

//export perfCallback
func perfCallback(ctx unsafe.Pointer, cpu C.int, data unsafe.Pointer, size C.int) {
	eventChannels[uintptr(ctx)] <- C.GoBytes(data, size)
}

//export perfCallbackv2
func perfCallbackv2(data unsafe.Pointer, size C.int) {

	//sl	:= []C.struct_A{}
	//k := C.struct_A{}
	//fmt.Printf("%+v", k)
	sl := (*[1 << 30]C.MyData)(data)[:size:size]
	//fmt.Printf("%+v \n", sl[0])
	for _, a := range sl {
		fmt.Printf("ctx is: %d\n", a.ctx)

		eventChannels[uintptr(a.ctx)] <- C.GoBytes(a.ptr, a.size)
	}
}

//export perfLostCallback
func perfLostCallback(ctx unsafe.Pointer, cpu C.int, cnt C.ulonglong) {
	lostChan := lostChannels[uintptr(ctx)]
	if lostChan != nil {
		lostChan <- uint64(cnt)
	}
}

//export ringbufferCallback
func ringbufferCallback(ctx unsafe.Pointer, data unsafe.Pointer, size C.int) C.int {
	eventChannels[uintptr(ctx)] <- C.GoBytes(data, size)
	return C.int(0)
}
