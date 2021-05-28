package magicsock

// #cgo LDFLAGS: -luring
// #include "io_uring.c"
import "C"

import "errors"
import "unsafe"
import "inet.af/netaddr"

type uring struct {
	ptr *C.go_uring
}

func newURing() *uring {
	r := new(C.go_uring)
	C.initializeRing(r)
	return &uring{ptr: r}
}

func (u *uring) submitURingRequest(fd int) error {
	errno := C.submit_recvmsg_request(C.int(fd), u.ptr)
	if errno != 0 {
		return errors.New("oops")
	}
	return nil
}

func (u *uring) receiveFromURing(buf []byte) (int, netaddr.IPPort, error) {
	a := new([4]byte)
	var port C.uint16_t
	n := C.receive_into(u.ptr, (*C.char)(unsafe.Pointer(&buf[0])), (*C.char)(unsafe.Pointer(a)), &port)
	if n < 0 {
		return 0, netaddr.IPPort{}, errors.New("something wrong")
	}
	ipp := netaddr.IPPortFrom(netaddr.IPFrom4(*a), uint16(port))
	return int(n), ipp, nil
}

// TODO: io_uring_queue_exit(&ring);
