package main

import (
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

var fileMutex sync.Mutex

var (
	msg       = new(dns.Msg)
	dnsServer = "8.8.8.8:53"
	client    = new(dns.Client)
)

type AutoconfigResponse struct {
	XMLName xml.Name `xml:"clientConfig"`
}

// 并发限制的信号量
var semaphore_autoconfig = make(chan struct{}, 2000) // 限制最大并发数

func fetchDomainsFromCSV_autoconfig(filename string, start int, end int) ([]string, error) {
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

func processDomain_autoconfig(domain string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	semaphore_autoconfig <- struct{}{}
	defer func() { <-semaphore_autoconfig }()

	config, err := Directurl(domain)
	if err != nil {
		results <- fmt.Sprintf("Error fetching %s: %v", domain, err)
	}
	if config != "" {
		results <- fmt.Sprintf("Config for %s: %s", domain, config)
		//err = saveXMLToFile("valid_autoconfig_Direct2.xml", config, domain)
		err = saveXMLToFile("valid_autoconfig.xml", config, domain)
		if err != nil {
			results <- fmt.Sprintf("Failed to save XML for %s: %v", domain, err)
		} else {
			results <- fmt.Sprintf("XML saved for %s", domain)
			return //
		}
	}

	ISPDB := "https://autoconfig.thunderbird.net/v1.1/" //TODO:只有这一个DB吗
	config, err = ISPDBget(ISPDB, domain)
	if err != nil {
		results <- fmt.Sprintf("Error fetching %s in %s: %v", domain, ISPDB, err)
	}
	if config != "" {
		results <- fmt.Sprintf("Config for %s in %s: %s", domain, ISPDB, config)
		//err = saveXMLToFile2("valid_autoconfig_DB2.xml", config, domain, ISPDB)
		err = saveXMLToFile("valid_autoconfig.xml", config, domain)
		if err != nil {
			results <- fmt.Sprintf("Failed to save XML for %s: %v", domain, err)
		} else {
			results <- fmt.Sprintf("XML saved for %s", domain)
			return //
		}
	}

	email := fmt.Sprintf("info@"+"%s", domain)
	config, err = fetchAutoconfigByMX(ISPDB, domain, email)
	if err != nil {
		results <- fmt.Sprintf("Error fetching %s by DNS MX: %v", domain, err)
	}
	if config != "" {
		results <- fmt.Sprintf("Config for %s by DNS MX: %s", domain, config)
		//err = saveXMLToFile3("valid_autoconfig_MX2.xml", config, domain)
		err = saveXMLToFile("valid_autoconfig.xml", config, domain)
		if err != nil {
			results <- fmt.Sprintf("Failed to save XML for %s: %v", domain, err)
		} else {
			results <- fmt.Sprintf("XML saved for %s", domain)
			return //
		}
	}

}

// 直接通过url发送get请求得到config
func Directurl(domain string) (string, error) {
	email := fmt.Sprintf("info@%s", domain) //由domain得到email_address
	base_url := fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml", domain)
	url1, _ := url.ParseRequestURI(base_url)
	data := url.Values{}
	data.Set("emailaddress", email)
	url1.RawQuery = data.Encode()
	urls := []string{
		url1.String(),
		fmt.Sprintf("https://%s/.well-known/autoconfig/mail/config-v1.1.xml", domain),
		fmt.Sprintf("http://autoconfig.%s/mail/config-v1.1.xml", domain),
	}
	for _, url := range urls {
		client := &http.Client{
			Timeout: 15 * time.Second, //设置超时时间
		}
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return "", err
		}

		resp, err := client.Do(req)
		//resp, err := http.Get(url)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		//if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		//fmt.Println(string(body))
		if err != nil {
			return "", fmt.Errorf("failed to read response body: %v", err)
		}
		var autoconfigResp AutoconfigResponse
		err = xml.Unmarshal(body, &autoconfigResp)
		if err != nil { //TODO:后面也可以打印出来这类，可能也有可用的配置信息
			return "", fmt.Errorf("failed to unmarshal XML: %v", err)
		} else {
			return string(body), nil
		}
		//}

	}
	return "", fmt.Errorf("unexpected status") //其实没有用
}

// 2.1 ISPDB
func ISPDBget(ISPdb string, domain string) (string, error) {
	mitigrated_url := ISPdb + domain
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	req, err := http.NewRequest("GET", mitigrated_url, nil)

	if err != nil {
		return "", err
	}
	//resp, err := http.Get(mitigrated_url)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	//if resp.StatusCode == http.StatusOK {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}
	var autoconfigResp AutoconfigResponse
	err = xml.Unmarshal(body, &autoconfigResp)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal XML: %v", err)
	} else {
		return string(body), nil
	}
	//}
	//return "", fmt.Errorf("unexpected status")

}

//3.通过DNS MX查询

// 提取%MXFULLDOMAIN%和%MXMAINDOMAIN%
func extractDomains(mxHost string) (string, string, error) {
	mxHost = strings.TrimSuffix(mxHost, ".")

	// 获取%MXFULLDOMAIN%
	parts := strings.Split(mxHost, ".")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid MX Host name: %s", mxHost)
	}
	mxFullDomain := strings.Join(parts[1:], ".")
	fmt.Println("fulldomain:", mxFullDomain)

	// 获取%MXMAINDOMAIN%（提取第二级域名）
	mxMainDomain, err := publicsuffix.EffectiveTLDPlusOne(mxHost)
	if err != nil {
		return "", "", fmt.Errorf("cannot extract maindomain: %v", err)
	}
	fmt.Println("maindomain:", mxMainDomain)

	return mxFullDomain, mxMainDomain, nil
}

func fetchAutoconfigByMX(ISPdb string, domain string, email string) (string, error) {
	// 执行MX查询
	mxHost, err := ResolveMXRecord(domain)
	if err != nil {
		return "", fmt.Errorf("failed in looking up MX: %v", err)
	}

	mxFullDomain, mxMainDomain, err := extractDomains(mxHost)
	if err != nil {
		return "", fmt.Errorf("failed to extract domain: %v", err)
	}

	mitistr1 := ISPdb + mxFullDomain
	mitistr2 := ISPdb + mxMainDomain
	// 构建URL并进行请求
	urls := []string{
		fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", mxFullDomain, email),
		fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", mxMainDomain, email),
		mitistr1,
		mitistr2,
	}

	for _, u := range urls {

		client := &http.Client{
			Timeout: 15 * time.Second, //设置超时时间
		}
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return "", err
		}

		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read response body: %v", err)
		}
		var autoconfigResp AutoconfigResponse
		err = xml.Unmarshal(body, &autoconfigResp)
		if err != nil { //
			return "", fmt.Errorf("failed to unmarshal XML: %v", err)
		} else {
			return string(body), nil
		}

	}

	return "", nil
}

func autoconfig() {
	domains, err := fetchDomainsFromCSV_autoconfig("tranco_V9KQN.csv", 800000, 1000000) //9.8test 9.11 test_over
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

func saveXMLToFile(filename, data string, email_add string) error {
	fileMutex.Lock()
	defer fileMutex.Unlock() //8.12

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	separator := fmt.Sprintf("\n\n<!-- Config for email address: %s -->\n", email_add)
	if _, err := file.WriteString(separator); err != nil {
		return err
	}

	if _, err := file.WriteString(data); err != nil {
		return err
	}

	return nil
}

func saveXMLToFile2(filename, data string, email_add string, ISPDB string) error {
	fileMutex.Lock()
	defer fileMutex.Unlock() //8.12

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	separator := fmt.Sprintf("\n\n<!-- Config for email address in %s: %s -->\n", ISPDB, email_add)
	if _, err := file.WriteString(separator); err != nil {
		return err
	}

	if _, err := file.WriteString(data); err != nil {
		return err
	}

	return nil
}

func saveXMLToFile3(filename, data string, email_add string) error {
	fileMutex.Lock()
	defer fileMutex.Unlock() //8.12

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	separator := fmt.Sprintf("\n\n<!-- Config for email address by MX: %s -->\n", email_add)
	if _, err := file.WriteString(separator); err != nil {
		return err
	}

	if _, err := file.WriteString(data); err != nil {
		return err
	}

	return nil
}

// 获取MX记录
func ResolveMXRecord(domain string) (string, error) {
	//创建DNS客户端并设置超时时间
	client := &dns.Client{
		Timeout: 20 * time.Second, // 设置超时时间
	}

	// 创建DNS消息
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	//发送DNS查询
	response, _, err := client.Exchange(msg, dnsServer)
	if err != nil {
		fmt.Printf("Failed to query DNS for %s: %v\n", domain, err)
		return "", err
	}

	//处理响应
	if response.Rcode != dns.RcodeSuccess {
		fmt.Printf("DNS query failed with Rcode %d\n", response.Rcode)
		return "", fmt.Errorf("DNS query failed with Rcode %d", response.Rcode)
	}

	var mxRecords []*dns.MX
	for _, ans := range response.Answer {
		if mxRecord, ok := ans.(*dns.MX); ok {
			fmt.Printf("MX record for %s: %s, the priority is %d\n", domain, mxRecord.Mx, mxRecord.Preference)
			mxRecords = append(mxRecords, mxRecord)
		}
	}
	if len(mxRecords) == 0 {
		return "", fmt.Errorf("no MX Record")
	}

	// 根据Preference字段排序，Preference值越小优先级越高
	sort.Slice(mxRecords, func(i, j int) bool {
		return mxRecords[i].Preference < mxRecords[j].Preference
	})
	highestMX := mxRecords[0]
	return highestMX.Mx, nil

}
