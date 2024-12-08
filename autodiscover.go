package main

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var fileMutex_autodiscover sync.Mutex

type AutodiscoverResponse struct {
	XMLName  xml.Name `xml:"Autodiscover"`
	Response Response `xml:"Response"`
}

type Response struct {
	XMLName xml.Name `xml:"Response"`
	User    User     `xml:"User"`
	Account Account  `xml:"Account"`
	Error   *Error   `xml:"Error,omitempty"`
}

type User struct {
	AutoDiscoverSMTPAddress string `xml:"AutoDiscoverSMTPAddress"`
	DisplayName             string `xml:"DisplayName"`
	LegacyDN                string `xml:"LegacyDN"`
	DeploymentId            string `xml:"DeploymentId"`
}

type Account struct {
	XMLName         xml.Name `xml:"Account"`
	AccountType     string   `xml:"AccountType"`
	Action          string   `xml:"Action"`
	MicrosoftOnline string   `xml:"MicrosoftOnline"`
	ConsumerMailbox string   `xml:"ConsumerMailbox"`
	Protocol        Protocol `xml:"Protocol"`
	RedirectAddr    string   `xml:"RedirectAddr"`
	RedirectUrl     string   `xml:"RedirectUrl"`
}

type Protocol struct{}

type Error struct {
	XMLName   xml.Name `xml:"Error"`
	Time      string   `xml:"Time,attr"`
	Id        string   `xml:"Id,attr"`
	DebugData string   `xml:"DebugData"`
	ErrorCode int      `xml:"ErrorCode"`
	Message   string   `xml:"Message"`
}

// 并发限制的信号量
var semaphore_autodiscover = make(chan struct{}, 2000) // 限制最大并发数 8.10

// 从top1M域名.csv中读取域名
func fetchDomainsFromCSV_autodiscover(filename string, start int, end int) ([]string, error) {
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

func processDomain_autodiscover(domain string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	semaphore_autodiscover <- struct{}{}        //获取信号量 8.10
	defer func() { <-semaphore_autodiscover }() //释放信号量  8.10

	email := fmt.Sprintf("info@%s", domain) //TODO后面可以修改邮件用户名
	//method1:直接通过text manipulation，直接发出post请求
	uris := []string{
		fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", domain),               //uri1
		fmt.Sprintf("https://autodiscover.%s/autodiscover/autodiscover.xml", domain), //2
		fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain),  //3
		fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", domain),              //4
	}

	for i, uri := range uris { //用序号i来区分source
		index := i + 1
		config, err := getAutodiscoverConfig(uri, email, "post", index) //getAutodiscoverConfig照常
		if err != nil {
			results <- fmt.Sprintf("Error fetching %s: %v", uri, err)
			continue
		}
		results <- fmt.Sprintf("Config for %s: %s", uri, config)

		// if config != "" {
		// 	savefile_name := fmt.Sprintf("autodiscover_config_post_%d.xml", i)
		// 	err = saveXMLToFile_autodiscover(savefile_name, config, email)
		// 	if err != nil {
		// 		results <- fmt.Sprintf("Failed to save XML for %s: %v", uri, err)
		// 	} else {
		// 		results <- fmt.Sprintf("XML saved for %s", uri) //不用在这里return了
		// 	}
		// }  //11.19

	}
	//method2:通过dns找到server,再post请求
	service := "_autodiscover._tcp." + domain
	_, srvs, err := net.LookupSRV("autodiscover", "tcp", domain) //没有指定DNS解析器，是使用默认的
	if err == nil {
		var urisDNS []string
		for _, srv := range srvs {
			host := strings.Trim(srv.Target, ".")                                   //这里其实没有检查是否是<host>就直接使用了 10.26
			uriDNS := fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", host) //改成小写
			urisDNS = append(urisDNS, uriDNS)
		}

		if len(urisDNS) != 0 {
			for _, uriDNS := range urisDNS {
				config, err1 := getAutodiscoverConfig(uriDNS, email, "srv_post", 0) //这里应该没有必要区分，统一写成0了
				if err1 != nil {
					results <- fmt.Sprintf("Error fetching %s: %v", uriDNS, err1)
					continue
				}
				if config != "" {
					results <- fmt.Sprintf("Config for %s: %s", uriDNS, config)
					// err2 := saveXMLToFile_autodiscover("autodiscover_config_srv.xml", config, email)
					// if err2 != nil {
					// 	results <- fmt.Sprintf("Failed to save XML for %s: %v", uriDNS, err2)
					// } else {
					// 	results <- fmt.Sprintf("XML saved for %s", uriDNS)
					// }
				}

			}
		}

	} else {
		results <- fmt.Sprintf("Failed to lookup SRV records for %s: %v", service, err)
	}
	//method3：先GET找到server，再post请求
	getURI := fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain) //是通过这个getURI得到server的uri，然后再进行post请求10.26
	err = GET_AutodiscoverConfig(getURI, email)
	if err != nil {
		results <- fmt.Sprintf("GET method error for %s: %v", getURI, err)
	} else {
		results <- fmt.Sprintf("GET method config for %s saved", getURI)
	}

	//method4:增加几条直接GET请求的路径
	direct_getURIs := []string{
		fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", domain),               //uri1
		fmt.Sprintf("https://autodiscover.%s/autodiscover/autodiscover.xml", domain), //2
		fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain),  //3
		fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", domain),              //4
	}
	for i, direct_getURI := range direct_getURIs {
		index := i + 1
		config, err := direct_GET_AutodiscoverConfig(direct_getURI, email, "get", index)
		if err != nil {
			results <- fmt.Sprintf("Error fetching %s: %v", direct_getURI, err)
			continue
		}
		results <- fmt.Sprintf("Config for %s: %s", direct_getURI, config)
		// if config != "" {
		// 	savefile_name := fmt.Sprintf("autodiscover_config_directget_%d.xml", i)
		// 	err = saveXMLToFile_autodiscover(savefile_name, config, email)
		// 	if err != nil {
		// 		results <- fmt.Sprintf("Failed to save XML for %s: %v", direct_getURI, err)
		// 	} else {
		// 		results <- fmt.Sprintf("XML saved for %s", direct_getURI)
		// 	}
		// } //11.19

	}
}

func autodiscover() {
	domains, err := fetchDomainsFromCSV_autodiscover("tranco_V9KQN.csv", 0, 20000) //9.8test 9.11 test_over
	if err != nil {
		fmt.Printf("Failed to fetch domains: %v\n", err)
		return
	}

	results := make(chan string)
	var wg sync.WaitGroup

	for _, domain := range domains {
		wg.Add(1)
		go processDomain_autodiscover(domain, results, &wg)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		fmt.Println(result)
	}
}

func getAutodiscoverConfig(uri string, email_add string, method string, index int) (string, error) { //post 11.19想直接在这个函数里实现保存配置的逻辑
	xmlRequest := fmt.Sprintf(`
			<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
	            <Request>
	                <EMailAddress>%s</EMailAddress>
	                <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
	            </Request>
	        </Autodiscover>`, email_add)

	req, err := http.NewRequest("POST", uri, bytes.NewBufferString(xmlRequest))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "text/xml")
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	//resp, err := http.Post(uri, "text/xml", bytes.NewBufferString(xmlRequest))
	// if err != nil {
	// 	return "", err
	// }
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound { //post请求返回的状态码是302
		redirect_uri := resp.Header.Get("Location")                          //post请求重定向后还是post
		return getAutodiscoverConfig(redirect_uri, email_add, method, index) //method和index都不变
	} else if resp.StatusCode == http.StatusOK { //post请求返回的状态码是200
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read response body: %v", err)
		}
		var autodiscoverResp AutodiscoverResponse
		err = xml.Unmarshal(body, &autodiscoverResp)
		if err != nil { //TODO 11.19
			//saveno_XMLToFile("no_config.xml", string(body), email_add) //9.8
			// if (strings.HasPrefix(strings.TrimSpace(string(body)), `<?xml version="1.0"`) || strings.HasPrefix(strings.TrimSpace(string(body)), `<Autodiscover`)) && !strings.Contains(strings.TrimSpace(string(body)), `<html`) && !strings.Contains(strings.TrimSpace(string(body)), `<item`) && !strings.Contains(strings.TrimSpace(string(body)), `lastmod`) && !strings.Contains(strings.TrimSpace(string(body)), `lt`) {
			// 	saveno_XMLToFile("no_config.xml", string(body), email_add)
			// } //9.9
			return "", fmt.Errorf("failed to unmarshal XML: %v", err)
		}

		if autodiscoverResp.Response.Account.Action == "redirectAddr" {
			newEmail := autodiscoverResp.Response.Account.RedirectAddr
			if newEmail != "" {
				return getAutodiscoverConfig(uri, newEmail, method, index)
			}
		} else if autodiscoverResp.Response.Account.Action == "redirectUrl" {
			newUri := autodiscoverResp.Response.Account.RedirectUrl
			if newUri != "" {
				return getAutodiscoverConfig(newUri, email_add, method, index)
			}
		} else if autodiscoverResp.Response.Error != nil { //有错误的话可以直接返回了
			Errorconfig := fmt.Sprintf("Errorcode:%d-%s\n", autodiscoverResp.Response.Error.ErrorCode, autodiscoverResp.Response.Error.Message)
			outputfile := fmt.Sprintf("autodiscover_%s_%d_Errorconfig.txt", method, index)
			saveXMLToFile_autodiscover(outputfile, Errorconfig, email_add) //直接保存了
			return Errorconfig, nil                                        //待修改
		} else { //一般是返回含Account的配置信息
			outputfile := fmt.Sprintf("autodiscover_%s_%d_config.xml", method, index)
			saveXMLToFile_autodiscover(outputfile, string(body), email_add)
			return string(body), nil
		}
	}
	outputfile := fmt.Sprintf("autodiscover_%s_%d_badresponse.txt", method, index)
	bad_response := fmt.Sprintf("Bad response for %s:%d\n", email_add, resp.StatusCode)
	saveXMLToFile_autodiscover(outputfile, bad_response, email_add)
	return bad_response, fmt.Errorf("unexpected status code: %d", resp.StatusCode) //同时也想记录请求发送失败时的状态码
}

func GET_AutodiscoverConfig(uri string, email_add string) error { //使用先get后post方法
	client := &http.Client{
		Timeout: 15 * time.Second, // 设置请求超时时间
	} //8.10
	resp, err := client.Get(uri) //8.10
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		redirect_uri := resp.Header.Get("Location")
		if redirect_uri != "" {
			// config, err :=
			getAutodiscoverConfig(redirect_uri, email_add, "get_post", 0) //不需要区分
			// if err != nil {
			// 	saveXMLToFile_autodiscover("autodiscover_config_getpost_1.xml", config, email_add) //区分source
			// }
		}
		return nil
	} else if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		var autodiscoverResp AutodiscoverResponse
		err = xml.Unmarshal(body, &autodiscoverResp)
		if err != nil { //TODO
			return fmt.Errorf("failed to unmarshal XML: %v", err)
		}
		if autodiscoverResp.Response.Account.Action == "redirectAddr" {
			newEmail := autodiscoverResp.Response.Account.RedirectAddr
			if newEmail != "" {
				//config, err :=
				getAutodiscoverConfig(uri, newEmail, "get_post", 0)
				// if err != nil {
				// 	saveXMLToFile_autodiscover("autodiscover_config_getpost_2_reAdd.xml", config, email_add)
				// }  //11.19
			}
			return nil
		} else if autodiscoverResp.Response.Account.Action == "redirectUrl" {
			newUri := autodiscoverResp.Response.Account.RedirectUrl
			if newUri != "" {
				// config, err :=
				getAutodiscoverConfig(newUri, email_add, "get_post", 0)
				// if err != nil {
				// 	saveXMLToFile_autodiscover("autodiscover_config_getpost_2_reUrl.xml", config, email_add)
				// }  //11.19
			}
			return nil //11.19
		} else if autodiscoverResp.Response.Error != nil { //有错误的话可以直接返回了
			Errorconfig := fmt.Sprintf("Errorcode:%d-%s\n", autodiscoverResp.Response.Error.ErrorCode, autodiscoverResp.Response.Error.Message)
			outputfile := fmt.Sprintf("autodiscover_%s_%d_Errorconfig.txt", "get_post", 0)
			saveXMLToFile_autodiscover(outputfile, Errorconfig, email_add) //直接保存了
			return nil                                                     //待修改
		} else { //也可能不需要再post了
			saveXMLToFile_autodiscover("autodiscover_getpost_getonly_config.xml", string(body), email_add)
			return nil
		}

	}
	outputfile := "autodiscover_getpost_badresponse.txt"
	bad_response := fmt.Sprintf("Bad response for %s:%d\n", email_add, resp.StatusCode)
	saveXMLToFile_autodiscover(outputfile, bad_response, email_add)
	return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

func direct_GET_AutodiscoverConfig(uri string, email_add string, method string, index int) (string, error) { //一路get请求
	client := &http.Client{
		Timeout: 15 * time.Second, // 设置请求超时时间
	} //8.10
	resp, err := client.Get(uri) //8.10
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		redirect_uri := resp.Header.Get("Location")
		return direct_GET_AutodiscoverConfig(redirect_uri, email_add, "get", index)
	} else if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read response body: %v", err)
		}
		var autodiscoverResp AutodiscoverResponse
		err = xml.Unmarshal(body, &autodiscoverResp)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal XML: %v", err)
		}

		// 	if err != nil {
		// 		//saveno_XMLToFile("no_config.xml", string(body), email_add) //9.8
		// 		// if (strings.HasPrefix(strings.TrimSpace(string(body)), `<?xml version="1.0"`) || strings.HasPrefix(strings.TrimSpace(string(body)), `<Autodiscover`)) && !strings.Contains(strings.TrimSpace(string(body)), `<html`) && !strings.Contains(strings.TrimSpace(string(body)), `<item`) && !strings.Contains(strings.TrimSpace(string(body)), `lastmod`) && !strings.Contains(strings.TrimSpace(string(body)), `lt`) {
		// 		// 	saveno_XMLToFile("no_config.xml", string(body), email_add)
		// 		// } //9.9
		// 		return "", fmt.Errorf("failed to unmarshal XML: %v", err)
		// 	}

		if autodiscoverResp.Response.Account.Action == "redirectAddr" {
			newEmail := autodiscoverResp.Response.Account.RedirectAddr
			if newEmail != "" {
				fmt.Print("&&&&&&&&&&&&&&&&&&&&&&&&&\n")
				outputfile := fmt.Sprintf("autodiscover_%s_%d_redirectAddr_config.xml", method, index)
				saveXMLToFile_autodiscover(outputfile, string(body), email_add)
				return string(body), nil //TODO, 这里直接返回带redirect_email了
				//return direct_GET_AutodiscoverConfig(uri, method, index)//??????11.19限制次数？？
			}
		} else if autodiscoverResp.Response.Account.Action == "redirectUrl" {
			newUri := autodiscoverResp.Response.Account.RedirectUrl
			if newUri != "" {
				return direct_GET_AutodiscoverConfig(newUri, email_add, method, index)
			}
		} else if autodiscoverResp.Response.Error != nil {
			Errorconfig := fmt.Sprintf("Errorcode:%d-%s\n", autodiscoverResp.Response.Error.ErrorCode, autodiscoverResp.Response.Error.Message)
			outputfile := fmt.Sprintf("autodiscover_%s_%d_Errorconfig.txt", method, index)
			saveXMLToFile_autodiscover(outputfile, Errorconfig, email_add) //直接保存了
			return Errorconfig, nil
		} else {
			outputfile := fmt.Sprintf("autodiscover_%s_%d_config.xml", method, index)
			saveXMLToFile_autodiscover(outputfile, string(body), email_add)
			return string(body), nil
		}
	}
	outputfile := fmt.Sprintf("autodiscover_%s_%d_badresponse.txt", method, index)
	bad_response := fmt.Sprintf("Bad response for %s:%d\n", email_add, resp.StatusCode)
	saveXMLToFile_autodiscover(outputfile, bad_response, email_add)
	return bad_response, fmt.Errorf("unexpected status code: %d", resp.StatusCode) //同时也想记录请求发送失败时的状态码

}

func saveXMLToFile_autodiscover(filename, data string, email_add string) error {
	fileMutex_autodiscover.Lock()
	defer fileMutex_autodiscover.Unlock() //8.12

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if data != "" { //
		separator := fmt.Sprintf("\n\n<!-- Config for email address: %s -->\n", email_add)
		if _, err := file.WriteString(separator); err != nil {
			return err
		}

		if _, err := file.WriteString(data); err != nil {
			return err
		}
	}

	return nil
}

// 10.27
func record_get_redirectToFile(filename, data string, email_add string) error {
	fileMutex_autodiscover.Lock()
	defer fileMutex_autodiscover.Unlock() //8.12

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if data != "" { //
		separator := fmt.Sprintf("\n\n<!-- Redirect_uri for email address: %s -->\n", email_add)
		if _, err := file.WriteString(separator); err != nil {
			return err
		}

		if _, err := file.WriteString(data); err != nil {
			return err
		}
	}

	return nil
}
