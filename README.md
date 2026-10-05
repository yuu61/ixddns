# NEC IX / Route 53 DDNS

NEC IXの標準DDNSクライアントからHTTPSでIPアドレスを通知し、AWS LambdaでRoute 53のAまたはAAAAレコードを更新します。AWSアクセスキーをIXに保存する必要はありません。

```text
NEC IX → Function URL または WAF + REST API → Lambda → Route 53
                                              ↕
                                       Secrets Manager（共有トークン）
```

1スタックにつき1つのDNS名・レコード種別を扱います。AとAAAAを両方更新する場合は、スタックとIXのDDNSプロファイルを分けてください。

## 導入

### 1. 環境を準備する

- AWS CLI v2と、対象AWSアカウントへの認証。
- Python 3.14、GNU Make、`sh`、cfn-guard 3.2.1。WindowsではMSYS2のMakeと`sh`を利用できます。
- 同じAWSアカウントのRoute 53パブリックホストゾーンと、そのゾーンへのドメイン委任。
- IXのWAN接続・ルーティング・DNS名前解決。登録対象はインタフェースに付いたグローバルIPです。CGNAT・DS-Lite・MAP-Eなどの到達性は別途確認してください。

開発用依存を導入し、設定ファイルを作成します。以下はPowerShellの例です。

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
```

Linux/macOSでは`.venv/bin/python`を使います。cfn-guardは別途用意し、Makefileの既定パス以外に配置した場合は`CFN_GUARD`で指定してください。

### 2. AWS側をデプロイする

`.env`にホストゾーンIDとDNS名を設定します。DNS名は小文字で、末尾の`.`を付けません。値のクォートは不要です。

```dotenv
AWS_PROFILE=my-profile
HOSTED_ZONE_ID=Z0123456789EXAMPLE
RECORD_NAME=router.example.com
```

`AWS_PROFILE`は空欄なら既定の認証設定を使います。主な既定値は、リージョン`ap-northeast-1`、スタック名`ixddns-ipv4`、レコード種別`A`、TTL 60秒、ログ保存30日です。その他の設定は[.env.example](.env.example)を参照してください。

```sh
make deploy
```

設定・テスト・Ruff・CloudFormationスキーマ・安全性ルールの検証後にデプロイします。同じ`STACK_NAME`で再実行すると更新になります。初回の正常な通知でDNSレコードを作成し、既存レコードがある場合は値とTTLを置き換えます。更新対象はDDNS用の単純なA/AAAAレコードにしてください。

Lambdaの更新権限は、指定ホストゾーン・DNS名・レコード種別の`UPSERT`に限定しています。

### 3. IXのコンフィグを生成・投入する

`.env`の`IX_WAN_IF`に、登録するグローバルIPv4を持つインタフェースを指定します。名前は実機の接続方式に合わせてください。

```dotenv
IX_WAN_IF=GigaEthernet0.1
```

```sh
make ix-config
```

デプロイ済みスタックのURLと共有トークンを取得し、`examples/nec-ix-ddns-ipv4.cfg`を生成します。実行するAWS認証には`cloudformation:DescribeStacks`と対象シークレットの`secretsmanager:GetSecretValue`が必要です。`.env`とスタックの設定が一致しない場合は生成を停止するため、AWS側の設定変更は先にデプロイしてください。

生成ファイルを確認し、Administrator権限のオペレーションモードからIXへ投入します。グローバルコンフィグモードから投入する場合は先頭の`configure`を省いてください。

- 生成ファイルには平文の共有トークンが含まれます。既定の保存先はGit除外対象です。`IX_CONFIG_OUTPUT`で変更する場合も除外対象のパスを使ってください。再生成時は上書きします。
- サンプルの`service ssl-protocol`は他のHTTPSクライアント機能にも影響します。`service password-encryption`で暗号化したパスワードは平文表示へ戻せません。
- `<IP4>`・`<IP6>`・`<PW>`はIXが置換するマクロなので、そのまま残してください。

サンプルはIX2000/IX3000のVer.10.11-1.1のマニュアルに基づきます。実機への投入・接続試験は未実施です。[IPv4サンプル](examples/nec-ix-ddns-ipv4.cfg.example)、[IPv6サンプル](examples/nec-ix-ddns-ipv6.cfg.example)も参照してください。

### 4. 更新を確認する

生成コンフィグの`ddns update`で初回通知を行い、`show ddns`、AWS側のログ、実際のDNSレコードを確認します。確認後、グローバルコンフィグモードで`write memory`を実行して保存してください。

```powershell
Resolve-DnsName router.example.com -Type A
```

**IXはサーバから応答があれば成功と判断するため、`show ddns`だけではDNS更新の成否を確認できません。** HTTP `200 / accepted`もRoute 53の受理を示すもので、DNSへの反映完了を示しません。DNSキャッシュはTTLまで残る場合があります。

通知は監視対象インタフェースのIP変更から約10秒後、変更がなくてもサンプル設定では1時間ごとに実行します。`ddns update`なら即時通知できます。IPが変わらないリンク復旧時の即時通知は、参照資料では確認できません。

## IPv6を更新する場合

別の設定ファイル（例：`.env.ipv6`）で、スタック名とレコード種別を変更します。

```dotenv
STACK_NAME=ixddns-ipv6
RECORD_TYPE=AAAA
IX_SOURCE_IF=GigaEthernet0.1
IX_NOTIFY_IF=GigaEthernet1.0
```

`IX_SOURCE_IF`はHTTPSのIPv4送信元、`IX_NOTIFY_IF`は登録するグローバルIPv6を持つインタフェースです。同じインタフェースでも構いません。通知時に`<IP6>`は監視対象の先頭のグローバルIPv6へ置換されます。

```sh
make deploy ENV_FILE=.env.ipv6
make ix-config ENV_FILE=.env.ipv6
```

`examples/nec-ix-ddns-ipv6.cfg`を生成します。A/AAAAとも、HTTPS通信はIPv4を使います。

## 送信元ASNによる制限（任意）

共有トークン認証は全方式で必要です。ASN制限を追加する場合は次のように設定します。

```dotenv
ASN_RESTRICTION_ENABLED=true
ASN_RESTRICTION_METHOD=static
ALLOWED_ASNS=64496,64500
```

ASNは例示用です。実際のHTTPS送信回線のASNに置き換えてください。`AS`接頭辞を付けず、重複や0を含まない1〜100個の整数を指定します。

| 設定 | 送信元判定 | 追加サービスの料金 |
| --- | --- | --- |
| `ASN_RESTRICTION_ENABLED=false`（標準） | 制限なし、Function URLを使用 | Function URL自体の追加料金なし |
| `true` / `static`（推奨） | デプロイ時のASNの起点CIDRをLambdaで照合 | Function URL自体の追加料金なし |
| `true` / `waf` | REST APIとAWS WAFでASN・送信元IPごとの流量を検査 | API Gateway・WAFの料金が追加 |

全方式でLambda・Secrets Manager・CloudWatch Logs・Route 53等の利用料金が発生します。[AWS料金](https://aws.amazon.com/pricing/)、[WAF料金](https://aws.amazon.com/waf/pricing/)、[API Gateway料金](https://aws.amazon.com/api-gateway/pricing/)を確認してください。

### static方式の運用

ビルド時にRIPEstatから起点CIDRを取得し、Lambdaへ埋め込みます。一覧は`.build/asn-prefixes.json`にも保存します。取得失敗、空・不正・欠落した経路、48時間より古い観測、テンプレートの容量超過ではビルドを停止し、古い一覧へ自動フォールバックしません。

**CIDR一覧は次のデプロイまで更新されません。** 経路変更に追従するため定期的に`make deploy`を実行してください。48時間の検査はビルド時だけで、稼働中のLambdaを停止する期限ではありません。通常は`ASN_PREFIXES_FILE`を空欄にして新しく取得します。取得済みJSONを指定する場合も、ASNの一致と取得・観測から48時間以内であることを検証します。

判定には通信の送信元IPを使い、転送ヘッダーや登録対象の`ip`は使いません。RIPEstatの観測経路はASNの全保有アドレスやWAFの判定との一致を保証せず、広いCIDRに含まれる別ASNの経路や同じASNの他の利用者も許可範囲に入ります。

### waf方式・既存構成からの移行

`waf`方式はAWS管理のASN判定を使い、CIDR一覧の更新は不要です。送信元IPごとのレート制限も適用します。Function URL方式は予約済み同時実行数（既定1）で流量を抑えますが、送信元ごとの制限や課金上限ではなく、拒否したリクエストにもLambda実行料金がかかります。予約可能な同時実行枠がAWSアカウントに必要です。

**waf方式との切り替え、または旧HTTP API構成からFunction URLへの移行では更新URLが変わります。** `make deploy`後に`make ix-config`を再実行してIXへ投入し、更新を確認してください。制限なしとstatic間の切り替えでは同じURLを使います。共有トークンは移行で変更しません。

方式指定がなかった従来のASN制限付き設定は、未指定のままでは`static`になります。WAFを維持する場合は`ASN_RESTRICTION_METHOD=waf`を明示してください。旧HTTP APIのアクセスログは移行後も残り、不要なら個別に削除します。

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

`make outputs`で更新URLとシークレットのARN、`make token`でトークンを取得できます。`make token`は秘密情報を画面に表示するため、出力を共有ログに保存しないでください。トークンを変更した場合はIXのパスワードも更新します。

## 開発・検証

CloudFormation定義は[cloudformation.yaml](cloudformation.yaml)と[infrastructure/](infrastructure/)に分割し、[ビルドスクリプト](scripts/build_template.py)で[Lambdaコード](lambda/index.py)とCIDR一覧を埋め込んだ`.build/template.json`に結合します。デプロイはこの1テンプレートを使い、S3へのコード配置・SAM・CDK・npmは不要です。

| コマンド | 内容 |
| --- | --- |
| `make` / `make validate` | テスト・Ruff・スキーマ・安全性ルールの検証 |
| `make test` | AWS・RIPEstatへの通信なしで単体テスト |
| `make build` | テンプレート生成 |
| `make ruff` / `make format` | Pythonの検査 / 自動修正・整形 |
| `make lint` / `make guard` | スキーマ検証 / 安全性ルールも検証 |
| `make install-dev` | 既存の仮想環境へ開発用依存を導入 |

static制限を有効にしたビルド・検証はRIPEstatへ接続します。ローカル検証ではAWSの権限・クォータや実機のHTTPS互換性までは確認できないため、デプロイ後の更新確認が必要です。

ツールは[requirements-dev.txt](requirements-dev.txt)で固定し、`PYTHON`・`CFN_LINT`・`CFN_GUARD`で実行パスを変更できます。Ruffはプレビューを含む全ルールを有効にし、行単位の抑制は使いません。例外と理由は[ruff.toml](ruff.toml)、構成固有の安全性ルールは[security.guard](security.guard)を参照してください。

設定ファイルは`ENV_FILE`で切り替えられます。コマンドライン指定は設定ファイルより優先されます（例：`make deploy RECORD_TTL=120`）。

## 削除時の扱い

スタック削除でAPI・Lambda・IAMロールは削除されます。ホストゾーン・更新済みDNSレコード・共有トークン・ログは残るため、不要なものは個別に削除してください。DNS名やレコード種別を変更した場合も、以前のレコードは自動削除されません。

## 参照

- [NEC: DDNS FAQ](https://jpn.nec.com/univerge/ix/faq/ddns.html)
- NEC IX2000/IX3000 機能説明書 Ver.10.11-1.1 §2.25、コマンドリファレンスのDDNS・SSL関連コマンド。
- [AWS: Route 53更新API](https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html)、[レコード単位のIAM条件](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/specifying-conditions-route53.html)
- [AWS: Function URLのアクセス制御](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)、[流量制限](https://docs.aws.amazon.com/lambda/latest/dg/urls-configuration.html#urls-throttling)
- [RIPEstat: RIS Prefixes](https://stat.ripe.net/docs/data-api/api-endpoints/ris-prefixes)
