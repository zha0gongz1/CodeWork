/* 可控线程并发探测主机端口，并返回[]string类型的端口开放结果
PS C:\Users\xx\Code\demo1> go run .\main.go
[{192.168.233.11 22} {192.168.233.90 445} {192.168.233.11 21} {192.168.233.90 135}]
Open host ports:[{192.168.233.11 22} {192.168.233.90 445} {192.168.233.11 21} {192.168.233.90 135}]
[192.168.233.11:22 192.168.233.90:445 192.168.233.11:21 192.168.233.90:135]
cost= 3.0203363s
*/
package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type HostPort struct {
	Host string
	Port int
}

func main() {
	start := time.Now()
	defer func() {
		cost := time.Since(start)
		fmt.Println("cost=", cost)
	}()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100) // 控制并发数量
	hostdict := []string{"192.168.233.1", "192.168.233.2", "192.168.233.3", "192.168.233.11", "192.168.233.90", "192.168.233.176", "192.168.233.231"}
	portdict := []int{21, 22, 80, 135, 445, 3389}
	temp := []HostPort{}
	//for port := 10; port < 80; port++ {
	for _, port := range portdict {
		for _, host := range hostdict {
			//fmt.Println(port)
			//fmt.Println(host)
			wg.Add(1)
			go PortScan(&wg, sem, host, port, &temp)
		}
	}
	wg.Wait()
	fmt.Println(temp)
	fmt.Printf("Open host ports:%v\n", temp)
	var openValue []string
	for _, openHostPorts := range temp { //将自定义结构体转换为字符串数组
		openValue = append(openValue, fmt.Sprintf("%s:%d", openHostPorts.Host, openHostPorts.Port))
	}
	fmt.Println(openValue)
}

// 端口扫描方式：1.多线程 2.根据端口跑Host
func PortScan(wg *sync.WaitGroup, sem chan struct{}, hostname string, port int, openHostPorts *[]HostPort) {
	defer wg.Done()
	sem <- struct{}{}
	timeout := time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", hostname, port), timeout*3)
	if err != nil {
		//fmt.Printf("%s:%d is closed\n", hostname, port)
		<-sem
		return
	}
	conn.Close()
	//fmt.Printf("%s:%d is open\n", hostname, port)
	*openHostPorts = append(*openHostPorts, HostPort{hostname, port})
	<-sem
}
