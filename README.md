# NEC IX / Route 53 DDNS

NEC IXの標準DDNSクライアントからHTTPSでIPアドレスを通知し、AWS LambdaでRoute 53のAまたはAAAAレコードを更新します。AWSアクセスキーをIXに保存する必要はありません。

```text
NEC IX → Function URL または WAF + REST API → Lambda → Route 53
                                              ↕
                                       Secrets Manager（共有トークン）
```

1レコード（DNS名・種別）ごとに独立したスタック（Lambda・IAMロール・Secrets Manager）として安全に分離デプロイされます。単一レコードの運用でも、複数拠点・複数レコード（IPv4/IPv6併用など）の運用でも、構造化設定ファイル（`sites.yaml`）を**唯一の定義元（Single Source of Truth）**として一元管理します。

## 導入

### 1. 環境を準備する

- AWS CLI v2と、対象AWSアカウントへの認証。
- Python 3.14、GNU Make、`sh`、cfn-guard 3.2.1。WindowsではMSYS2のMakeと`sh`を利用できます。
- 同じAWSアカウントのRoute 53パブリックホストゾーンと、そのゾーンへのドメイン委任。
- IXのWAN接続・ルーティング・DNS名前解決。登録対象はインタフェースに付いたグローバルIPです。CGNAT・DS-Lite・MAP-Eなどの到達性は別途確認してください。

`make init`でPython仮想環境（`.venv`）の作成、依存ツールの導入、`.env`および`sites.yaml`の初期作成をまとめて行えます。

```sh
make init
```

手動で準備する場合は次のように実行します（PowerShellの例）。

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
Copy-Item sites.yaml.example sites.yaml
```

Linux/macOSでは`.venv/bin/python`を使います。cfn-guardは別途用意し、Makefileの既定パス以外に配置した場合は`CFN_GUARD`で指定してください。

### 2. 設定ファイル（sites.yaml）を編集する

DNSレコード・ホストゾーン・IXインタフェース・ASN制限等のインフラ定義は、すべて `sites.yaml` に記述します。

```yaml
# 全サイト共通のデフォルト設定
defaults:
  hosted_zone_id: Z0123456789EXAMPLE
  region: ap-northeast-1
  aws_profile: ""
  record_ttl: 60
  asn_restriction_enabled: false

# サイト・レコードごとの設定一覧
sites:
  # 単一拠点のIPv4更新の例
  tokyo-v4:
    record_name: router.example.com
    record_type: A
    ix_wan_if: GigaEthernet0.1

  # IPv6も更新する場合は別サイトとして定義
  tokyo-v6:
    record_name: router.example.com
    record_type: AAAA
    ix_source_if: GigaEthernet0.1
    ix_notify_if: GigaEthernet1.0
```

ローカルのAWS実行環境（使用するAWS CLIプロファイルなど）は、必要に応じて `.env` に設定します。レコード定義を `.env` に重複して記述する必要はありません。

```dotenv
AWS_PROFILE=my-profile
REGION=ap-northeast-1
```

定義を検証するには `make check` または `make list` を実行します。

```sh
# 定義されているサイト一覧と状態を表示
make list

# 設定内容の検証
make check
```

### 3. AWS側をデプロイする

```sh
# 全サイトを一括デプロイ
make deploy

# または特定サイトのみをデプロイ
make deploy SITE=tokyo-v4
```

設定・テスト・Ruff・CloudFormationスキーマ・安全性ルールの検証後にデプロイします。各サイトの `stack_name`（既定値: `ixddns-<サイト名>`）ごとに独立したCloudFormationスタックが作成・更新されます。初回の正常な通知でDNSレコードを作成し、既存レコードがある場合は値とTTLを置き換えます。更新対象はDDNS用の単純なA/AAAAレコードにしてください。

Lambdaの更新権限は、自スタックの指定ホストゾーン・DNS名・レコード種別の`UPSERT`に限定されています。

### 4. IXのコンフィグを生成・投入する

```sh
# 全サイトのコンフィグを一括生成
make ix-config

# または特定サイトのみ生成
make ix-config SITE=tokyo-v4
```

デプロイ済みスタックのURLと共有トークンを取得し、`examples/nec-ix-ddns-<サイト名>.cfg`を生成します。実行するAWS認証には`cloudformation:DescribeStacks`と対象シークレットの`secretsmanager:GetSecretValue`が必要です。

生成ファイルを確認し、Administrator権限のオペレーションモードからIXへ投入します。グローバルコンフィグモードから投入する場合は先頭の`configure`を省いてください。

- 生成ファイルには平文の共有トークンが含まれます。既定の保存先（`examples/*.cfg`）はGit除外対象です。`ix_config_output`で変更する場合も除外対象のパスを使ってください。再生成時は上書きします。
- サンプルの`service ssl-protocol`は他のHTTPSクライアント機能にも影響します。`service password-encryption`で暗号化したパスワードは平文表示へ戻せません。
- `<IP4>`・`<IP6>`・`<PW>`はIXが置換するマクロなので、そのまま残してください。

サンプルはIX2000/IX3000のVer.10.11-1.1のマニュアルに基づきます。実機への投入・接続試験は未実施です。[IPv4サンプル](examples/nec-ix-ddns-ipv4.cfg.example)、[IPv6サンプル](examples/nec-ix-ddns-ipv6.cfg.example)も参照してください。

### 5. 更新を確認する

生成コンフィグの`ddns update`で初回通知を行い、`show ddns`、AWS側のログ、実際のDNSレコードを確認します。確認後、グローバルコンフィグモードで`write memory`を実行して保存してください。

```powershell
Resolve-DnsName router.example.com -Type A
```

**IXはサーバから応答があれば成功と判断するため、`show ddns`だけではDNS更新の成否を確認できません。** HTTP `200 / accepted`もRoute 53の受理を示すもので、DNSへの反映完了を示しません。DNSキャッシュはTTLまで残る場合があります。

通知は監視対象インタフェースのIP変更から約10秒後、変更がなくてもサンプル設定では1時間ごとに実行します。`ddns update`なら即時通知できます。IPが変わらないリンク復旧時の即時通知は、参照資料では確認できません。

### 6. 出力とトークンの確認

```sh
# スタック出力（URLやリソースARN等）の確認
make outputs SITE=tokyo-v4

# 共有トークン（半角英数字）のみの取得・表示
make token SITE=tokyo-v4
```

## 複数拠点・複数回線の管理

複数拠点で異なる契約回線（ISP/プロバイダ）を使う場合、拠点ごとに接続元ASNが変わります。
`sites.yaml` では、サイトごとに `allowed_asns` を指定することで、**「東京拠点は東京の回線ASNからのみ許可、大阪拠点は大阪の回線ASNからのみ許可」** という拠点ごとの厳格なアクセス制御が可能です。

```yaml
defaults:
  hosted_zone_id: Z0123456789EXAMPLE
  asn_restriction_enabled: true
  asn_restriction_method: static

sites:
  tokyo:
    record_name: tokyo.example.com
    ix_wan_if: GigaEthernet0.1
    allowed_asns: [64496] # 東京拠点のISPのASN

  osaka:
    record_name: osaka.example.com
    ix_wan_if: GigaEthernet0.1
    allowed_asns: [64500, 64501] # 大阪拠点の主回線・予備回線のASN
```

- `allowed_asns` はリスト形式 `[64496, 64500]`、単一値 `64496`、文字列 `"64496,64500"` のいずれも指定可能です。
- `static` 方式での一括デプロイ時（`make deploy`）、複数拠点で同一のASNが使われていてもビルドキャッシュによりRIPEstatへの重複アクセスを自動抑止します。

### スタック分離によるセキュリティ上の利点

手元の設定は `sites.yaml` 1ファイルで管理しつつ、AWS側はサイトごとに独立したスタック（Lambda・IAMロール・Secrets Manager）として展開されます。
各LambdaのIAMロールは自サイトのレコード名に対する更新権限しか持たないため、万一ある拠点のルータ設定や共有トークンが漏洩しても、他拠点のレコードやドメイン内の別レコードを改ざんされるリスクはありません。

## 送信元ASNによる制限（任意）

共有トークン認証は全方式で必要です。送信元制限を追加する場合は `sites.yaml` で次のように設定します。

```yaml
defaults:
  asn_restriction_enabled: true
  asn_restriction_method: static
  allowed_asns: [64496, 64500]
```

ASNは例示用です。実際のHTTPS送信回線のASNに置き換えてください。`AS`接頭辞を付けず、重複や0を含まない1〜100個の整数を指定します。

| 設定 | 送信元判定 | 追加サービスの料金 |
| --- | --- | --- |
| `asn_restriction_enabled: false`（標準） | 制限なし、Function URLを使用 | Function URL自体の追加料金なし |
| `true` / `static`（推奨） | デプロイ時のASNの起点CIDRをLambdaで照合 | Function URL自体の追加料金なし |
| `true` / `waf` | REST APIとAWS WAFでASN・送信元IPごとの流量を検査 | API Gateway・WAFの料金が追加 |

全方式でLambda・Secrets Manager・CloudWatch Logs・Route 53等の利用料金が発生します。[AWS料金](https://aws.amazon.com/pricing/)、[WAF料金](https://aws.amazon.com/waf/pricing/)、[API Gateway料金](https://aws.amazon.com/api-gateway/pricing/)を確認してください。

### static方式の運用

ビルド時にRIPEstatから起点CIDRを取得し、Lambdaへ埋め込みます。一覧は`.build/asn-prefixes-<サイト名>.json`にも保存します。取得失敗、空・不正・欠落した経路、48時間より古い観測、テンプレートの容量超過ではビルドを停止し、古い一覧へ自動フォールバックしません。

**CIDR一覧は次のデプロイまで更新されません。** 経路変更に追従するため定期的に`make deploy`を実行してください。48時間の検査はビルド時だけで、稼働中のLambdaを停止する期限ではありません。通常は`asn_prefixes_file`を空欄にして新しく取得します。取得済みJSONを指定する場合も、ASNの一致と取得・観測から48時間以内であることを検証します。

判定には通信の送信元IPを使い、転送ヘッダーや登録対象の`ip`は使いません。RIPEstatの観測経路はASNの全保有アドレスやWAFの判定との一致を保証せず、広いCIDRに含まれる別ASNの経路や同じASNの他の利用者も許可範囲に入ります。

### waf方式・既存構成からの移行

`waf`方式はAWS管理のASN判定を使い、CIDR一覧の更新は不要です。送信元IPごとのレート制限も適用します。Function URL方式は予約済み同時実行数（既定1）で流量を抑えますが、送信元ごとの制限や課金上限ではなく、拒否したリクエストにもLambda実行料金がかかります。予約可能な同時実行枠がAWSアカウントに必要です。

**waf方式との切り替え、または旧HTTP API構成からFunction URLへの移行では更新URLが変わります。** `make deploy`後に`make ix-config`を再実行してIXへ投入し、更新を確認してください。制限なしとstatic間の切り替えでは同じURLを使います。共有トークンは移行で変更しません。

方式指定がなかった従来のASN制限付き設定は、未指定のままでは`static`になります。WAFを維持する場合は`asn_restriction_method: waf`を明示してください。旧HTTP APIのアクセスログは移行後も残り、不要なら個別に削除します。

## エラーの確認

窓口は`GET /update`で、`ip`と`token`を各1つ受け付けます。不正なトークン、レコード種別に合わないIP、非グローバルIP、余分なパラメータは拒否します。

| HTTP応答 | 意味 |
| --- | --- |
| `200 / accepted` | Route 53が変更を受理 |
| `400` | IPまたはクエリが不正 |
| `401` | トークンが未指定・不一致 |
| `403` | staticの許可範囲外、またはWAFのASN・流量制限 |
| `404 / 405` | パスまたはメソッドが不正 |
| `429` | 流量・同時実行数の制限 |
| `503` | シークレット取得・Route 53更新の失敗、またはstatic一覧の不備 |

Lambdaログの`ddns_update_accepted`、`ddns_update_failed`、`ddns_source_rejected`で確認します。WAFの遮断理由は`make outputs`の`WafLogGroup`を参照してください。APIアクセスログは作成せず、Lambdaログ・メトリクスとWAFログを使います。トークンやクエリ全体はログに記録しません。
