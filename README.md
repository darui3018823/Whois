# Whois CLI

Windows コマンドラインで手軽に WHOIS を実行できるシンプルな CLI ツールです。

## 使い方

whois [options] <domain>

主なオプション:

- -raw: 生の WHOIS テキストを出力
- -o <file>: 出力をファイル保存（自動でカラー無効）
- -server <host[:port]>: WHOIS サーバを明示指定（例: whois.verisign-grs.com:43）
- -timeout <dur>: タイムアウト（例: 5s, 2m）
- -follow: レジストラのリファラ WHOIS を追跡（デフォルト: 有効）
- -nocolor: カラー出力を無効化
- -version: バージョン情報表示
- -help: ヘルプ表示

例:

```powershell
whois example.com
whois -raw example.net
whois -o .\out.txt example.org
whois -server whois.verisign-grs.com:43 example.com
```

## 設定ファイル `config.json`

```json
{
	"lang": "ja",
	"defaultRaw": false,
	"color": true
}
```

- lang: "ja" で一部ラベルを日本語化
- defaultRaw: true で既定を生テキストに
- color: true でカラー表示（-o 使用時は自動無効）

## ビルド（Windows）

PowerShell から:

```powershell
./win_build_amd64.ps1
```

成果物は `./dist/win/whois.exe` に出力されます。

## ライセンス

[BSD 2-Clause License](./LICENSE)
