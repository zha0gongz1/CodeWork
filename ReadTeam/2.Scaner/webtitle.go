//多线程且互斥输出
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"sync"
	"time"
)


func main() {
	start := time.Now()
	defer func() {
		cost := time.Since(start)
		fmt.Println("\ncost=", cost)
	}()
	urls := []string{
		"https://www.google.com",
		"https://www.example.net",
		"https://github.com/",
		"https://github.com/zha0gongz1",
		"https://shopee.sg/",
		"https://www.baidu.com",
		"https://www.cnblogs.com/H4ck3R-XiX",
	}

	var wg sync.WaitGroup
	var mutex sync.Mutex
	ch := make(chan struct{}, 100) // 最多允许 2 个并发 goroutine
	for _, url := range urls {
		wg.Add(1)
		go func(url string) {

			defer wg.Done()
			ch <- struct{}{}        // 获取令牌
			defer func() { <-ch }() // 释放令牌
			resp, err := http.Get(url)
			if err != nil {
				fmt.Printf("Error fetching: %s\n", url)
				return
			}
			defer resp.Body.Close()
			mutex.Lock()
			re := regexp.MustCompile(`<title>(.*?)</title>`)
			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			//if err != nil {
			//	fmt.Printf("Error reading body: %s\n", url)
			//	return
			//}
			bodyString := string(bodyBytes)
			bodyLen := len(bodyString)
			match := re.FindStringSubmatch(bodyString)
			if len(match) != 0 {
				//fmt.Printf("Title: %s", match[1])
				fmt.Printf("[%d] %s [%d]\tTitle:%s", resp.StatusCode, url, bodyLen, match[1])
			} else {
				fmt.Printf("[%d] %s [%d]\tTitle:NULL", resp.StatusCode, url, bodyLen)
			}

			//fmt.Printf("[%d] %s\t[%d]Title:%s", resp.StatusCode, url, bodyLen,match[1])

			fmt.Print("\n")
			mutex.Unlock()
		}(url)
	}
	wg.Wait()
}
