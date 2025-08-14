// 2025 Whois_CLIApp: darui3018823 All rights reserved.
// All works created by darui3018823 associated with this repository are the intellectual property of darui3018823.
// Packages and other third-party materials used in this repository are subject to their respective licenses and copyrights.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/mattn/go-runewidth"
	"golang.org/x/net/idna"
)

const Version = "2.0.0"

var rawFlag = flag.Bool("raw", false, "Output raw whois text")
var versionFlag = flag.Bool("version", false, "Show version information")
var helpFlag = flag.Bool("help", false, "Show help message")
var outFile = flag.String("o", "", "Output to file")
var serverFlag = flag.String("server", "", "Override WHOIS server host[:port]")
var timeoutFlag = flag.Duration("timeout", 8*time.Second, "Network timeout (e.g. 5s, 2m)")
var followFlag = flag.Bool("follow", true, "Follow referral WHOIS server if present")
var noColorFlag = flag.Bool("nocolor", false, "Disable colored output")
var tableFlag = flag.Bool("table", false, "Render output as a box-drawn table")

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string {
	return ansiRe.ReplaceAllString(s, "")
}

func dispWidth(s string) int {
	return runewidth.StringWidth(stripANSI(s))
}

func padRightByWidth(s string, width int) string {
	w := dispWidth(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

func wrapByWidth(s string, width int) []string {
	var out []string
	s = strings.TrimSpace(s)
	if s == "" {
		return []string{""}
	}

	cur := ""
	for _, word := range strings.Fields(s) {
		if cur == "" {
			if dispWidth(word) <= width {
				cur = word
				continue
			}
			out = append(out, hardWrap(word, width)...)
			cur = ""
			continue
		}
		cand := cur + " " + word
		if dispWidth(cand) <= width {
			cur = cand
		} else {
			out = append(out, padRightByWidth(cur, width))
			if dispWidth(word) <= width {
				cur = word
			} else {
				out = append(out, hardWrap(word, width)...)
				cur = ""
			}
		}
	}
	if cur != "" {
		out = append(out, padRightByWidth(cur, width))
	}
	return out
}

func hardWrap(s string, width int) []string {
	var out []string
	var buf string
	for _, r := range s {
		buf += string(r)
		if dispWidth(buf) >= width {
			out = append(out, padRightByWidth(buf, width))
			buf = ""
		}
	}
	if buf != "" {
		out = append(out, padRightByWidth(buf, width))
	}
	return out
}

func renderTable(title string, kvs []KV, width int, color bool) []string {
	if width < 40 {
		width = 40
	}

	maxKey := 0
	for _, kv := range kvs {
		if w := dispWidth(kv.Key); w > maxKey {
			maxKey = w
		}
	}
	innerWidth := width - 2
	valueWidth := innerWidth - 2 - maxKey - 3
	if valueWidth < 16 {
		valueWidth = 16
		maxKey = innerWidth - 2 - 3 - valueWidth
		if maxKey < 8 {
			maxKey = 8
		}
	}

	top := "┏" + strings.Repeat("━", width-2) + "┓"
	mid := "┣" + strings.Repeat("━", width-2) + "┫"
	bot := "┗" + strings.Repeat("━", width-2) + "┛"

	tspace := width - 2 - dispWidth(title)
	if tspace < 0 {
		tspace = 0
	}
	l := tspace / 2
	r := tspace - l
	titleLine := "┃" + strings.Repeat(" ", l) + title + strings.Repeat(" ", r) + "┃"

	out := []string{
		colorize(top, "title", color),
		colorize(titleLine, "title", color),
		colorize(mid, "title", color),
	}

	for _, kv := range kvs {
		keyCell := padRightByWidth(kv.Key, maxKey)
		wrapped := wrapByWidth(kv.Val, valueWidth)
		for i, w := range wrapped {
			if i == 0 {
				line := "┃ " +
					colorize(keyCell, "label", color) +
					" : " +
					colorize(w, "value", color) +
					" ┃"
				out = append(out, line)
			} else {
				line := "┃ " +
					strings.Repeat(" ", maxKey) +
					" : " +
					colorize(w, "value", color) +
					" ┃"
				out = append(out, line)
			}
		}
	}
	out = append(out, colorize(bot, "title", color))
	return out
}

type KV struct{ Key, Val string }

type Config struct {
	Lang          string `json:"lang"`
	DefaultOutput string `json:"default_output"`
	Color         bool   `json:"color"`
}

var jprsKeys = map[string]string{
	"ドメイン名":  "Domain Name",
	"登録者名":   "Registrant",
	"登録年月日":  "Creation Date",
	"有効期限":   "Registry Expiry Date",
	"最終更新":   "Updated Date",
	"状態":     "Status",
	"公開連絡窓口": "Registrant Contact",
	"名前":     "Name",
	"郵便番号":   "Postal Code",
	"住所":     "Postal Address",
	"電話番号":   "Phone",
	"FAX番号":  "Fax",
}

func extractKVs(raw, lang string) []KV {
	var kvs []KV
	lines := strings.Split(raw, "\n")
	seen := make(map[string]bool)

	for i := 0; i < len(lines); i++ {
		l := strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
		if len(l) == 0 {
			continue
		}

		if strings.HasPrefix(l, "[") && strings.Contains(l, "]") {
			right := strings.TrimPrefix(l, "[")
			parts := strings.SplitN(right, "]", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				if val == "" && i+1 < len(lines) {
					next := strings.TrimSpace(strings.TrimRight(lines[i+1], "\r"))
					if next != "" && !strings.HasPrefix(next, "[") {
						val = next
						i++
					}
				}
				if en, ok := jprsKeys[key]; ok {
					key = en
				}
				keyLabel := translateLabel(key, lang)
				if val != "" && !seen[keyLabel+":"+val] {
					kvs = append(kvs, KV{Key: keyLabel, Val: val})
					seen[keyLabel+":"+val] = true
				}
			}
			continue
		}

		if strings.Contains(l, ":") {
			parts := strings.SplitN(l, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			if key == "" || val == "" || strings.HasPrefix(key, "%") || strings.HasPrefix(key, "#") {
				continue
			}

			keyLower := strings.ToLower(key)
			isKnownKey := false

			if _, ok := labels[key]; ok {
				isKnownKey = true
			}

			commonPatterns := []string{
				"domain", "registrar", "registrant", "admin", "tech", "billing",
				"created", "updated", "expires", "expiry", "status", "server", "name",
				"organization", "organisation", "email", "phone", "fax", "address",
				"city", "state", "country", "postal", "whois", "url", "iana",
			}

			for _, pattern := range commonPatterns {
				if strings.Contains(keyLower, pattern) {
					isKnownKey = true
					break
				}
			}

			if isKnownKey {
				keyLabel := translateLabel(key, lang)
				if !seen[keyLabel+":"+val] {
					kvs = append(kvs, KV{Key: keyLabel, Val: val})
					seen[keyLabel+":"+val] = true
				}
			}
		}
	}
	return kvs
}

func loadConfig(path string) Config {
	file, err := os.Open(path)
	if err != nil {
		return Config{Lang: "en", DefaultOutput: "conventional", Color: true}
	}
	defer file.Close()

	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return Config{Lang: "en", DefaultOutput: "conventional", Color: true}
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
	case "title":
		return "\033[1;32m" + s + "\033[0m" // 緑太字
	case "version":
		return "\033[1;36m" + s + "\033[0m" // シアン太字
	case "copyright":
		return "\033[0;33m" + s + "\033[0m" // 黄色
	case "usage":
		return "\033[1;35m" + s + "\033[0m" // マゼンタ太字
	case "option":
		return "\033[0;32m" + s + "\033[0m" // 緑
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
	if len(out) == 0 {
		for _, line := range lines {
			out = append(out, strings.TrimRight(line, "\r"))
		}
	}
	return out
}

func output(lines []string, filename string) {
	if filename != "" {
		err := os.WriteFile(filename, []byte(strings.Join(lines, "\n")+"\n"), 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to write to file:", err)
			os.Exit(1)
		}
	} else {
		for _, line := range lines {
			fmt.Println(line)
		}
	}
}

func centerLine(leftBorder, text, rightBorder string, totalWidth int, colorLeft, colorText, colorRight string, enableColor bool) string {
	visibleLen := len(text)
	spaceTotal := totalWidth - visibleLen - 2
	leftSpaces := spaceTotal / 2
	rightSpaces := spaceTotal - leftSpaces
	return colorize(leftBorder+strings.Repeat(" ", leftSpaces), colorLeft, enableColor) +
		colorize(text, colorText, enableColor) +
		colorize(strings.Repeat(" ", rightSpaces)+rightBorder, colorLeft, enableColor)
}

func main() {
	flag.Parse()
	args := flag.Args()

	if *versionFlag {
		// カラー出力を有効化（ファイル出力でない限り）
		enableColor := !*noColorFlag
		fmt.Println(colorize("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓", "title", enableColor))
		fmt.Println(centerLine("┃", "Whois CLI App", "┃", 79, "title", "version", "title", enableColor))
		fmt.Println(colorize("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛", "title", enableColor))
		fmt.Println()
		fmt.Printf("%s %s\n",
			colorize("Version:", "label", enableColor),
			colorize("v"+Version, "version", enableColor))
		fmt.Printf("%s %s\n",
			colorize("Description:", "label", enableColor),
			colorize("A simple command-line whois client with IDN support", "value", enableColor))
		fmt.Printf("%s %s\n",
			colorize("License:", "label", enableColor),
			colorize("BSD 2-Clause License", "value", enableColor))
		fmt.Printf("%s %s\n",
			colorize("Copyright:", "label", enableColor),
			colorize("(c) 2025 darui3018823, All rights reserved.", "copyright", enableColor))
		return
	}

	if *helpFlag {
		enableColor := !*noColorFlag
		fmt.Println(colorize("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓", "title", enableColor))
		fmt.Println(colorize("┃                            ", "title", enableColor) + colorize("Whois CLI Help", "usage", enableColor) + colorize("                             ┃", "title", enableColor))
		fmt.Println(colorize("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛", "title", enableColor))
		fmt.Println()
		fmt.Printf("%s %s\n",
			colorize("Usage:", "label", enableColor),
			colorize("whois [options] <domain>", "usage", enableColor))
		fmt.Println()
		fmt.Printf("%s\n", colorize("Options:", "label", enableColor))

		options := []struct {
			flag string
			desc string
		}{
			{"-raw", "Output raw whois text without formatting"},
			{"-table", "Render output as a box-drawn table"},
			{"-o <file>", "Output to file (automatically disables colors)"},
			{"-server <host[:port]>", "Override WHOIS server (e.g., whois.verisign-grs.com:43)"},
			{"-timeout <duration>", "Network timeout (e.g., 5s, 2m)"},
			{"-follow", "Follow referral WHOIS server if present (default: true)"},
			{"-nocolor", "Disable colored output"},
			{"-version", "Show version information"},
			{"-help", "Show this help message"},
		}

		for _, opt := range options {
			fmt.Printf("  %s  %s\n",
				colorize(fmt.Sprintf("%-25s", opt.flag), "option", enableColor),
				colorize(opt.desc, "value", enableColor))
		}

		fmt.Println()
		fmt.Printf("%s\n", colorize("Examples:", "label", enableColor))
		examples := []string{
			"whois daruks.com",
			"whois -table minecraft.net",
			"whois -raw example.org",
			"whois -o ./output.txt wikipedia.org",
			"whois -server whois.verisign-grs.com:43 daruks.com",
			"whois アググン.jp",
		}
		for _, ex := range examples {
			fmt.Printf("  %s\n", colorize(ex, "usage", enableColor))
		}

		fmt.Println()
		fmt.Printf("%s %s\n",
			colorize("Config file:", "label", enableColor),
			colorize("config.json (lang, defaultRaw, color settings)", "value", enableColor))
		return
	}

	if len(args) != 1 {
		fmt.Println("Usage: whois [options] <domain>")
		flag.PrintDefaults()
		return
	}

	fmt.Println("Whois_CLIApp (c) 2025 darui3018823, All rights reserved.")
	fmt.Println()

	inputDomain := args[0]
	asciiDomain, errIDN := idna.Lookup.ToASCII(strings.TrimSpace(inputDomain))
	domain := inputDomain
	if errIDN == nil && asciiDomain != "" {
		domain = asciiDomain
	}
	domain = strings.ToLower(domain)

	config := loadConfig("config.json")

	if *noColorFlag {
		config.Color = false
	}

	if *outFile != "" {
		config.Color = false
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

	if *outFile != "" {
		config.Color = false
	}

	if *rawFlag {
		scanner := bufio.NewScanner(strings.NewReader(finalRaw))
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		output(lines, *outFile)
		return
	}

	if *tableFlag {
		kvs := extractKVs(finalRaw, config.Lang)
		if len(kvs) > 0 {
			lines := renderTable("Whois Result", kvs, 120, config.Color)
			output(lines, *outFile)
			return
		}
	}

	// フラグが指定されていない場合は設定ファイルに従う
	switch strings.ToLower(config.DefaultOutput) {
	case "raw":
		scanner := bufio.NewScanner(strings.NewReader(finalRaw))
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		output(lines, *outFile)
		return
	case "table":
		kvs := extractKVs(finalRaw, config.Lang)
		if len(kvs) > 0 {
			lines := renderTable("Whois Result", kvs, 120, config.Color)
			output(lines, *outFile)
			return
		}
		// テーブル抽出失敗時はconventionalにフォールバック
		fallthrough
	case "conventional":
		fallthrough
	default:
		lines := formatPretty(finalRaw, config.Lang, config.Color)
		output(lines, *outFile)
	}
}
