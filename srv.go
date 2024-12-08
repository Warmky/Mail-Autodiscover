package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// 并发限制的信号量
var semaphore_srv = make(chan struct{}, 2000)

func processDomain(domain string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	semaphore_srv <- struct{}{}
	defer func() { <-semaphore_srv }()

	result := querySRV(domain, 15*time.Second) // 设置超时时间为5秒
	if result != "" {
		results <- result
	}
}

type SRVRecord struct {
	Service  string
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

func querySRV(domain string, timeout time.Duration) string {
	// 定义要查询的服务标签
	services := []string{
		"_imap._tcp." + domain,
		"_imaps._tcp." + domain,
		"_pop3._tcp." + domain,
		"_pop3s._tcp." + domain,
		"_submission._tcp." + domain,
		"_submissions._tcp." + domain,
	}

	// 创建一个字典来存储结果
	results := make(map[string][][]SRVRecord)
	results[domain] = make([][]SRVRecord, 2) // 行0为IMAP/POP3，行1为SMTP

	for _, service := range services {
		// 使用上下文来设置超时
		_, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// 查询SRV记录
		_, records, err := net.LookupSRV("", "", service)
		if err != nil {
			fmt.Printf("Failed to query SRV for %s: %v\n", service, err)
			continue
		}

		// 将结果添加到相应的行中
		for _, record := range records {
			if strings.HasPrefix(service, "_submission") || strings.HasPrefix(service, "_smtps") {
				results[domain][1] = append(results[domain][1], SRVRecord{
					Service:  service,
					Priority: record.Priority,
					Weight:   record.Weight,
					Port:     record.Port,
					Target:   record.Target,
				})
			} else {
				results[domain][0] = append(results[domain][0], SRVRecord{
					Service:  service,
					Priority: record.Priority,
					Weight:   record.Weight,
					Port:     record.Port,
					Target:   record.Target,
				})
			}
		}
	}

	// 按照Priority排序IMAP/POP3和SMTP结果
	sort.Slice(results[domain][0], func(i, j int) bool {
		return results[domain][0][i].Priority < results[domain][0][j].Priority
	})
	sort.Slice(results[domain][1], func(i, j int) bool {
		return results[domain][1][i].Priority < results[domain][1][j].Priority
	})

	// 将结果编码为JSON并写入文件
	if len(results[domain][0]) > 0 || len(results[domain][1]) > 0 {
		// 以域名命名文件并放入result文件夹中
		fileName := fmt.Sprintf("result/%s_srv_records.json", domain)
		file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return ""
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		err = encoder.Encode(results)
		if err != nil {
			fmt.Println("Error writing JSON to file:", err)
			return ""
		}
	} else {
		fmt.Println("No results to write for domain:", domain)
	}

	//fmt.Printf("SRV records for %s have been written to %s\n", domain, fileName)
	return ""
}

func srv() {
	//domains, err := fetchDomainsFromCSV_srv("tranco_V9KQN.csv", 520000, 540000) //感觉速度慢了
	domains, err := fetchDomainsFromCSV_srv("tranco_V9KQN.csv", 800000, 900000) //160000-400000
	if err != nil {
		fmt.Printf("Failed to fetch domains: %v\n", err)
		return
	}

	results := make(chan string)
	var wg sync.WaitGroup

	for _, domain := range domains {
		wg.Add(1)
		go processDomain(domain, results, &wg)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		fmt.Println(result)
	}
}

func fetchDomainsFromCSV_srv(filename string, start int, end int) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	var domains []string
	for i := 0; i < end; i++ {
		record, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to read CSV file: %v", err)
		}

		if i >= start {
			domain := strings.TrimSpace(record[1])
			if domain != "" {
				domains = append(domains, domain)
			}
		}
	}
	return domains, nil
}
