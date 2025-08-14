package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

var rawFlag = flag.Bool("raw", false, "Output raw whois text")
var versionFlag = flag.Bool("version", false, "Show version information")
var helpFlag = flag.Bool("help", false, "Show help message")
var outFile = flag.String("o", "", "Output to file")
var serverFlag = flag.String("server", "", "Override WHOIS server host[:port]")
var timeoutFlag = flag.Duration("timeout", 8*time.Second, "Network timeout (e.g. 5s, 2m)")
var followFlag = flag.Bool("follow", true, "Follow referral WHOIS server if present")
var noColorFlag = flag.Bool("nocolor", false, "Disable colored output")

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
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		// 破損している場合は安全なデフォルト
		return Config{Lang: "en", DefaultRaw: false, Color: true}
	}
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
	case strings.HasSuffix(domain, ".moe"):
		return "whois.nic.moe:43"
	default:
		return "whois.iana.org:43"
	}
}

func normalizeServer(s string) string {
	if s == "" {
		return s
	}
	if strings.Contains(s, ":") {
		return s
	}
	return s + ":43"
}

func queryWhois(server, query string, timeout time.Duration) (string, error) {
	addr := normalizeServer(server)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	// 読み書きの締切を設定
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}
	b, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func extractReferral(raw string) string {
	// 代表的なフィールドを探索
	keys := []string{"Registrar WHOIS Server:", "Whois Server:", "WHOIS Server:"}
	for _, line := range strings.Split(raw, "\n") {
		l := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if l == "" {
			continue
		}
		for _, k := range keys {
			if strings.HasPrefix(strings.ToLower(l), strings.ToLower(k)) {
				parts := strings.SplitN(l, ":", 2)
				if len(parts) != 2 {
					continue
				}
				v := strings.TrimSpace(parts[1])
				if v == "" {
					continue
				}
				// URL 形式や "None" のような無効値をスキップ
				low := strings.ToLower(v)
				if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
					continue
				}
				if low == "none" || strings.Contains(low, "not available") {
					continue
				}
				return v
			}
		}
	}
	return ""
}

func formatPretty(raw string, lang string, color bool) []string {
	lines := strings.Split(raw, "\n")
	out := []string{}
	seen := map[string]bool{}
	for _, line := range lines {
		l := strings.TrimRight(line, "\r")
		if l == "" {
			continue
		}
		for key := range labels {
			if strings.Contains(l, key) {
				parts := strings.SplitN(l, ":", 2)
				if len(parts) == 2 {
					label := translateLabel(strings.TrimSpace(parts[0]), lang)
					value := strings.TrimSpace(parts[1])
					formatted := fmt.Sprintf("%s: %s",
						colorize(label, "label", color),
						colorize(value, "value", color))
					if !seen[formatted] {
						out = append(out, formatted)
						seen[formatted] = true
					}
				}
			}
		}
	}
	// 何も拾えなかった場合は生テキストにフォールバック
	if len(out) == 0 {
		for _, line := range lines {
			out = append(out, strings.TrimRight(line, "\r"))
		}
	}
	return out
}

func main() {
	flag.Parse()
	args := flag.Args()

	if *versionFlag {
		fmt.Println("Copyright (c) 2025 darui3018823, All rights reserved.")
		fmt.Println("WhoisCLIApp v1.5.0")
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
		fmt.Println("Usage: whois [options] <domain>")
		flag.PrintDefaults()
		return
	}
	inputDomain := args[0]
	// IDN を ASCII (punycode) に正規化
	asciiDomain, errIDN := idna.Lookup.ToASCII(strings.TrimSpace(inputDomain))
	domain := inputDomain
	if errIDN == nil && asciiDomain != "" {
		domain = asciiDomain
	}
	domain = strings.ToLower(domain)

	config := loadConfig("config.json")
	useRaw := *rawFlag || config.DefaultRaw

	if *noColorFlag {
		config.Color = false
	}

	if *outFile != "" {
		config.Color = false // ファイル出力時はカラー無効化
	}

	// WHOIS サーバー決定（オーバーライド可能）
	server := *serverFlag
	if server == "" {
		server = getWhoisServer(domain)
	}

	// 1回目のクエリ
	raw1, err := queryWhois(server, domain, *timeoutFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error connecting to whois server:", err)
		os.Exit(1)
	}

	finalRaw := raw1

	// リファラ追跡（例: .com/.net でレジストラ側へ）
	if *followFlag {
		if ref := extractReferral(raw1); ref != "" {
			if !strings.EqualFold(normalizeServer(ref), normalizeServer(server)) {
				if raw2, err := queryWhois(ref, domain, *timeoutFlag); err == nil && raw2 != "" {
					finalRaw = raw2
				}
			}
		}
	}

	// 出力整形
	var outputLines []string
	if useRaw {
		// 改行統一
		scanner := bufio.NewScanner(strings.NewReader(finalRaw))
		for scanner.Scan() {
			outputLines = append(outputLines, scanner.Text())
		}
	} else {
		outputLines = formatPretty(finalRaw, config.Lang, config.Color)
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
