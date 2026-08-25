package main

import (
	"bridgewatch/internal/httpapi"
	"bridgewatch/internal/store"
	"bridgewatch/internal/workflow"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", configuredAddress(), "监听地址")
	self := flag.Bool("self-check", false, "执行自检")
	flag.Parse()
	if !validAddr(*addr) {
		fmt.Fprintln(os.Stderr, "监听地址必须是回环地址")
		os.Exit(2)
	}
	st := store.New("")
	api := httpapi.New(workflow.New(st))
	if *self {
		ln, e := net.Listen("tcp", *addr)
		if e != nil {
			panic(e)
		}
		srv := &http.Server{Handler: api.Mux}
		go srv.Serve(ln)
		time.Sleep(30 * time.Millisecond)
		resp, e := http.Get("http://" + *addr + "/")
		if e == nil && resp.StatusCode == 200 {
			fmt.Println("自检通过", *addr)
		} else {
			fmt.Println("自检失败", e)
			os.Exit(1)
		}
		if resp != nil {
			resp.Body.Close()
		}
		srv.Close()
		return
	}
	srv := &http.Server{Addr: *addr, Handler: api.Mux, ReadHeaderTimeout: 5 * time.Second}
	fmt.Println("桥梁振动告警服务监听", *addr)
	if e := srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		panic(e)
	}
}
