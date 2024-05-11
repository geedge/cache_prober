package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	_ "net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"flag"

	"github.com/miekg/dns"
)

type Data struct {
	target string
	dict   map[int]map[string]bool
}

var dataset map[string]map[int][]string
var input_file string
var save_file string
var id_stamp string

func send_query(addr string, dn string) (*dns.Msg, error) {
	var domain string
	if dn == "timestamp" {
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		domain = strings.Join([]string{timestamp, "-scan.echodns.xyz."}, "")
	} else {
		domain = strings.Join([]string{dn, ".echodns.xyz."}, "")
	}
	//fmt.Println(domain)
	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeA)
	m.RecursionDesired = true

	res, err := dns.Exchange(m, addr)
	return res, err
}

func retrieve_ip(pool chan string, file_name string) {
	cnt := 0
	f, err := os.Open(file_name)
	if err != nil {
		fmt.Println("cannot open file")
		return
	}
	defer f.Close()

	fmt.Println("sending msg ...")
	reader := bufio.NewReader(f)
	for {
		s, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		s = s[:(len(s) - 1)] //remove \n in linux | remove \r\n in windows
		//fmt.Println(s)
		pool <- s
		cnt++
		if cnt%1000 == 0 {
			fmt.Println(cnt)
		}
	}
	close(pool)
}

func store_data(pool chan Data, wg *sync.WaitGroup) {
	wg.Add(1)
	for {
		temp := make(map[int][]string)
		if data, ok := <-pool; ok {
			if len(data.dict) > 0 {
				for tp := range data.dict {
					for rdns := range data.dict[tp] {
						temp[tp] = append(temp[tp], rdns)
					}
				}
				dataset[data.target] = temp
			}
		} else {
			break
		}
	}
	wg.Done()
}

func create_threads(n int, ip_pool chan string, data_pool chan Data, wg1 *sync.WaitGroup) {
	for i := 0; i < n; i++ {
		wg1.Add(1)
		go dns_query(ip_pool, data_pool, wg1)
	}
}

func active_probe(n int, addr string) Data {
	var (
		rdns_ip string
		tp      int
	)
	target_ip := addr[:len(addr)-3]
	data := Data{target_ip, make(map[int]map[string]bool)}
	stop := 0
	for i := 0; i < n; i++ {
		//fmt.Println(target_ip)
		subdomain := strings.Join([]string{strings.Replace(target_ip, ".", "-", -1), "fwd", strconv.Itoa(i), "240209"}, "-")
		res, err := send_query(addr, subdomain)
		//fmt.Println(err)
		if err == nil {
			if len(res.Answer) == 3 {
				if cname, ok := res.Answer[0].(*dns.CNAME); ok {
					rdns_ip = strings.Join(strings.Split(strings.Split(cname.Target, ".")[0], "-")[1:], ".")
					if a, ok := res.Answer[2].(*dns.A); ok {
						tp = int(binary.BigEndian.Uint32(a.A))
						//fmt.Println(rdns_ip)
						//fmt.Println(tp)
						if data.dict[tp] == nil {
							data.dict[tp] = make(map[string]bool)
						}
						data.dict[tp][rdns_ip] = true
						stop = 0
					} else {
						stop += 1
					}
				} else {
					stop += 1
				}
			} else {
				stop += 1
			}
		} else {
			stop += 1
			//fmt.Println(err)
		}
		if stop == 3 {
			return data
		}
	}
	return data
}

func dns_query(pool chan string, data_pool chan Data, wg *sync.WaitGroup) {
	for {
		if s, ok := <-pool; ok {
			addr := s + ":53"
			//fmt.Println(addr)
			data := active_probe(20, addr)
			if data.dict != nil {
				data_pool <- data
			}
		} else {
			break
		}
	}
	wg.Done()
}

func save_to_file(filename string) {
	jsonstr, _ := json.Marshal(dataset)
	save_file, _ := os.Create(filename)
	if _, err := save_file.Write(jsonstr); err != nil {
		panic(err)
	}
	save_file.Close()
}

func main() {
	ip_pool := make(chan string, 1000)
	data_pool := make(chan Data, 400)
	var probe_tasks sync.WaitGroup
	var store_task sync.WaitGroup
	dataset = make(map[string]map[int][]string)
	//save_file := "output/global-cache-240209.json"

	flag.StringVar(&input_file, "input", "", "input file")
	flag.StringVar(&save_file, "output", "", "output file")
	flag.StringVar(&id_stamp, "salt", "", "salt in domain")
	flag.Parse()
	if input_file == "" || save_file == "" || id_stamp == "" {
		panic("Please configure the task!\n")
	}

	fmt.Println(time.Now())
	go retrieve_ip(ip_pool, input_file)
	create_threads(500, ip_pool, data_pool, &probe_tasks)
	go store_data(data_pool, &store_task)
	probe_tasks.Wait()
	close(data_pool)
	store_task.Wait()
	save_to_file(save_file)
	fmt.Println("All done!")
	fmt.Println(time.Now())
}
