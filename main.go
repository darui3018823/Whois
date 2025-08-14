package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
)

var rawFlag = flag.Bool("raw", false, "Output raw whois text")
var versionFlag = flag.Bool("version", false, "Show version information")
var helpFlag = flag.Bool("help", false, "Show help message")
var outFile = flag.String("o", "", "Output to file")

type Config struct {
	Lang       string `json:"lang"`
	DefaultRaw bool   `json:"defaultRaw"`
	Color      bool   `json:"color"`
}

func loadConfig(path string) Config {
	file, err := os.Open(path)
	if err != nil {
		return Config{Lang: "en", DefaultRaw: false, Color: true}
	}
	defer file.Close()

	var config Config
	json.NewDecoder(file).Decode(&config)
	return config
}

var labels = map[string]string{
	"Registrar":                     "レジストラ",
	"Registrar WHOIS Server":        "レジストラWhoisサーバ",
	"Registrar URL":                 "レジストラURL",
	"Creation Date":                 "登録日",
	"Registry Expiry Date":          "有効期限",
	"Name Server":                   "ネームサーバ",
	"Registrar IANA ID":             "IANA ID",
	"Registrar Abuse Contact Email": "不正通報先メール",
	"Registrar Abuse Contact Phone": "不正通報先電話",
}

func translateLabel(label, lang string) string {
	if lang == "ja" {
		if ja, ok := labels[label]; ok {
			return ja
		}
	}
	return label
}

func colorize(s string, color string, enable bool) string {
	if !enable {
		return s
	}
	switch color {
	case "label":
		return "\033[1;34m" + s + "\033[0m" // 青太字
	case "value":
		return "\033[1;37m" + s + "\033[0m" // 白太字
	}
	return s
}

func getWhoisServer(domain string) string {
	domain = strings.ToLower(domain)

	switch {
	case strings.HasSuffix(domain, ".jp"):
		return "whois.jprs.jp:43"
	case strings.HasSuffix(domain, ".com"), strings.HasSuffix(domain, ".net"):
		return "whois.verisign-grs.com:43"
	case strings.HasSuffix(domain, ".org"):
		return "whois.pir.org:43"
	case strings.HasSuffix(domain, ".info"):
		return "whois.afilias.net:43"
	case strings.HasSuffix(domain, ".biz"):
		return "whois.neulevel.biz:43"
	case strings.HasSuffix(domain, ".us"):
		return "whois.nic.us:43"
	case strings.HasSuffix(domain, ".co"):
		return "whois.nic.co:43"
	case strings.HasSuffix(domain, ".io"):
		return "whois.nic.io:43"
	case strings.HasSuffix(domain, ".dev"):
		return "whois.nic.google:43"
	case strings.HasSuffix(domain, ".xyz"):
		return "whois.nic.xyz:43"
	case strings.HasSuffix(domain, ".me"):
		return "whois.nic.me:43"
	case strings.HasSuffix(domain, ".top"):
		return "whois.nic.top:43"
	case strings.HasSuffix(domain, ".su"):
		return "whois.tcinet.ru:43"
	// 必要に応じてここに追加
	default:
		return "whois.iana.org:43"
	}
}

func main() {
	flag.Parse()
	args := flag.Args()

	if *versionFlag {
		fmt.Println("Copyright (c) 2025 darui3018823, All rights reserved.")
		fmt.Println("WhoisCLIApp v1.3.0")
		fmt.Println("A simple command-line whois client")
		fmt.Println("This software is released under the BSD 2-Clause License.")
		return
	}

	if *helpFlag {
		fmt.Println("Usage: whois [options] <domain>")
		flag.PrintDefaults()
		return
	}

	if len(args) != 1 {
		fmt.Println("Usage: whois [-raw] [-o <file>] <domain>")
		return
	}
	domain := args[0]

	config := loadConfig("config.json")
	useRaw := *rawFlag || config.DefaultRaw

	if *outFile != "" {
		config.Color = false // ファイル出力時はカラー無効化
	}

	server := getWhoisServer(domain)

	conn, err := net.Dial("tcp", server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error connecting to whois server:", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s\r\n", domain)

	scanner := bufio.NewScanner(conn)
	var outputLines []string

	if useRaw {
		for scanner.Scan() {
			outputLines = append(outputLines, scanner.Text())
		}
	} else {
		for scanner.Scan() {
			line := scanner.Text()
			for key := range labels {
				if strings.Contains(line, key) {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						label := translateLabel(strings.TrimSpace(parts[0]), config.Lang)
						value := strings.TrimSpace(parts[1])
						outputLines = append(outputLines, fmt.Sprintf("%s: %s",
							colorize(label, "label", config.Color),
							colorize(value, "value", config.Color)))
					}
				}
			}
		}
	}

	if *outFile != "" {
		err := os.WriteFile(*outFile, []byte(strings.Join(outputLines, "\n")+"\n"), 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to write to file:", err)
			os.Exit(1)
		}
	} else {
		for _, line := range outputLines {
			fmt.Println(line)
		}
	}
}
