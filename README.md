# IX3315 / Route 53 DDNS

NEC IXの標準DDNSクライアントからHTTPS GETでIPアドレスを通知し、AWS LambdaがRoute 53のレコードを更新します。AWS側の定義は共通リソース・API・WAFに分割し、Makefileで1つのCloudFormationテンプレートへ結合してデプロイします。Lambdaのコードも生成テンプレートへ埋め込むため、S3へのコード配置、SAM、CDK、npmは不要です。

```text
IX3315 -- HTTPS GET --> API Gateway（HTTP API / WAF方式はREST API）
                                                    |
                                             Lambda (Python 3.14)
                                               |           |
                                         Secrets Manager  Route 53
```

## 作成されるリソース

- API Gatewayと`GET /update`ルート、スロットリング設定。ASN制限の設定でAPI方式を選択します。
- Lambdaと、指定レコードの`UPSERT`だけを許可するIAMロール。
- Secrets Managerで生成する48文字の英数字の共有トークン。
- HTTP APIのアクセスログ、WAF方式のWAFログ、Lambdaログ。保存期間は標準で30日です。
- `waf`方式を選んだ場合、許可ASNと送信元IPごとの流量を検査するAWS WAF。

ホストゾーンは既存のものを指定します。DNSレコードは最初の正常な通知で作成・更新され、CloudFormationの管理対象にはしません。1スタックで1つの名前・レコード種別を更新します。AとAAAAの両方を更新する場合は、別々のスタックとIXのDDNSプロファイルを使います。

## 前提

- AWS CLI v2が使えることと、対象AWSアカウントに認証できること。
- 同じAWSアカウントにパブリックホストゾーンがあり、そのドメインがRoute 53へ委任されていること。
- 更新対象はこのDDNS用の単純なAまたはAAAAレコードであること。既存レコードを指定すると、その値とTTLを置き換えます。
- IPv4の場合、IXの通知対象インタフェースに登録するグローバルIPv4が付いていること。プライベートIP、CGNAT、DS-Lite、MAP-Eの到達性は別途検討が必要です。

API Gateway、Lambda、Secrets Manager、CloudWatch Logs、Route 53の利用料金が発生します。料金の確認先は各サービスの[AWS公式料金ページ](https://aws.amazon.com/pricing/)です。

## デプロイ

設定値は`.env`に定義し、Makefileからデプロイします。まず[.env.example](.env.example)をコピーしてください。以下はPowerShellの例です。

```powershell
Copy-Item .env.example .env
```

`.env`の`HOSTED_ZONE_ID`と`RECORD_NAME`を実際の値に変更します。DNS名は小文字で、末尾の`.`を付けません。`.env`はGNU Makeの変数定義として読み込むため、値をクォートで囲む必要はありません。`.env`はGitの管理対象から除外しています。

```dotenv
AWS_PROFILE=my-profile
REGION=ap-northeast-1
STACK_NAME=ixddns-ipv4
HOSTED_ZONE_ID=Z0123456789EXAMPLE
RECORD_NAME=router.example.com
RECORD_TYPE=A
RECORD_TTL=60
LOG_RETENTION_DAYS=30
ASN_RESTRICTION_ENABLED=false
ASN_RESTRICTION_METHOD=static
ALLOWED_ASNS=
ASN_PREFIXES_FILE=
```

`AWS_PROFILE`は空欄でも使用できます。その場合はAWS CLIの既定の認証設定を使います。AWSアクセスキーやIXの共有トークンは、この設定ファイルに追加する必要はありません。

```sh
make deploy
```

`make deploy`は必須設定を確認し、単体テスト・スキーマ・安全性ルールの検証に通った後でCloudFormationを実行します。既存スタックと同じ`STACK_NAME`を使えば更新になります。

| `.env`の変数 | CloudFormationパラメータ / 用途 | 標準値 |
| --- | --- | --- |
| `AWS_PROFILE` | AWS CLIプロファイル | 空欄 |
| `REGION` | AWSリージョン | `ap-northeast-1` |
| `STACK_NAME` | CloudFormationスタック名 | `ixddns-ipv4` |
| `HOSTED_ZONE_ID` | `HostedZoneId`。`/hostedzone/`は付けない | 必須 |
| `RECORD_NAME` | `RecordName`。更新するDNS名 | 必須 |
| `RECORD_TYPE` | `RecordType`。`A`または`AAAA` | `A` |
| `RECORD_TTL` | `RecordTTL`。DNS TTL、秒 | `60` |
| `LOG_RETENTION_DAYS` | `LogRetentionDays`。ログ保存期間、日 | `30` |
| `ASN_RESTRICTION_ENABLED` | `AsnRestrictionEnabled`。送信元ASNによる制限 | `false` |
| `ASN_RESTRICTION_METHOD` | `AsnRestrictionMethod`。`static`または`waf` | `static` |
| `ASN_PREFIXES_FILE` | static用の取得済み一覧JSON。空欄ならビルド時に取得 | 空欄 |
| `ALLOWED_ASNS` | `AllowedAsns`。許可するASNの数値をカンマ区切りで指定 | 有効時は必須 |

URLとトークンの保存先は、同じ`.env`の設定でスタック出力を取得して確認します。出力にはトークンそのものを含めていません。

```sh
make outputs
```

権限のある利用者は、次のコマンドでSecrets Managerの共有トークンを取得できます。JSONの`token`フィールドをIXに設定してください。このコマンドはトークンを画面に表示するため、出力を共有ログに保存しないでください。

```sh
make token
```

別の設定ファイルを使う場合は、`make deploy ENV_FILE=.env.ipv6`のように指定できます。コマンドラインの変数指定は設定ファイルより優先されるため、`make deploy RECORD_TTL=120`のような一時的な変更も可能です。

Lambdaの実行ロールに付けるRoute 53権限は、ホストゾーン・正規化したDNS名・レコード種別・`UPSERT`操作をすべて制限しています。リクエストからDNS名を指定する機能はありません。IXにはAWSアクセスキーを保存しません。

## 送信元ASNによる制限と料金

`.env`の`ASN_RESTRICTION_ENABLED`で有効・無効、`ASN_RESTRICTION_METHOD`で方式を選びます。低頻度のDDNS用途には`static`を推奨します。共有トークン認証とAPIのスロットリングは、全方式で必要です。

| 有効化 | 方式 | APIと送信元制限 | WAFの追加固定料金 / 月 / スタック |
| --- | --- | --- | --- |
| `false`（標準） | 無視 | HTTP API、送信元制限なし | 0 USD |
| `true` | `static`（方式の標準） | HTTP API、デプロイ時のASNのCIDR一覧をLambdaで照合 | 0 USD |
| `true` | `waf` | Regional REST API、AWS WAFのASN判定と送信元IPごとのレート制限 | 約7 USD |

現構成のWAF料金はWeb ACLが5 USD/月、ルール2つが各1 USD/月で、合計約7 USD/月です。さらにWAFのリクエスト料金（100万リクエストあたり0.60 USD）がかかります。A・AAAAを別スタックでWAF運用すると、固定料金は合計約14 USD/月です。`static`はこのWAF料金をなくし、Lambda内のCIDR照合による処理時間だけが増えます。API GatewayもHTTP APIを使うため、REST APIとは従量料金が異なります。[AWS WAF料金](https://aws.amazon.com/waf/pricing/)、[API Gateway料金](https://aws.amazon.com/api-gateway/pricing/)

これはWAF分の比較です。どの方式でもAPI Gateway・Lambda・Secrets Manager・CloudWatch Logs・Route 53等の通常料金は別途発生します。無料枠、リージョン、使用量、税によって総額は変わります。切り替え後も保持したログの保存料金は残る場合があります。

安価な方式を有効にする場合は次のように設定します。`64496,64500`は説明用の番号なので、実際の送信回線のASNへ変更してください。

```dotenv
ASN_RESTRICTION_ENABLED=true
ASN_RESTRICTION_METHOD=static
ALLOWED_ASNS=64496,64500
ASN_PREFIXES_FILE=
```

`ALLOWED_ASNS`は1〜100個の整数を指定でき、`AS`接頭辞・重複・ASN 0は受け付けません。無効時は一覧を無視し、CloudFormationへ`0`を渡します。有効時の未指定・不正な値、スイッチや方式の綴り違いはデプロイ前に停止します。

### static方式：デプロイ時にCIDRを埋め込む

`make build`（`make deploy`でも自動実行）がRIPEstatのRIS Prefixes APIから、各ASNが起点となるIPv4・IPv6経路を取得します。最新のRIS観測時点を使い、通過するだけの経路は含めません。APIのnoiseフィルターで私用経路・ホスト経路・デフォルト経路などを除外し、取得した公開CIDRは切り捨てず埋め込みます。重複・隣接範囲は同じ許可範囲に統合し、一覧を圧縮してLambdaコードへ格納します。[RIPEstat RIS Prefixes](https://stat.ripe.net/docs/data-api/api-endpoints/ris-prefixes)

LambdaはAPI Gatewayの`requestContext.http.sourceIp`（REST形式では`identity.sourceIp`）を一覧と照合し、許可範囲外ならシークレットを読む前に403で拒否します。`X-Forwarded-For`や登録する`ip`クエリの値は送信元判定に使いません。通信時のRIPEstat照会、S3読み取り、別の定期実行Lambdaはありません。[API Gatewayのイベント形式](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html)

一覧は生成テンプレートと同じディレクトリの`asn-prefixes.json`（標準では`.build/asn-prefixes.json`）にも保存します。ASN・取得日時・各ASNの観測日時・許可CIDRを確認できます。RIPEstatの取得失敗、ASNごとの空の経路、件数の欠落、不正な経路、48時間より古い観測はビルドを停止します。取得失敗時に古い一覧へ自動フォールバックせず、AWSへのデプロイも進めません。テンプレートがCloudFormationの51,200バイト制限を超える場合も停止し、CIDRを部分的に削ってデプロイしません。

取得済みの一覧を使う場合だけ`ASN_PREFIXES_FILE=.build/asn-prefixes.json`を指定できます。形式、`ALLOWED_ASNS`との一致、取得・観測から48時間以内であることを再検証します。通常は空欄にして、毎回新しく取得してください。

**Lambdaの一覧は次のデプロイまで更新されません。** 定期的に`make deploy`を実行して更新してください。48時間の検査はビルド時の条件で、稼働中のLambdaを48時間後に停止する設定ではありません。新しく追加された範囲からの通知は再デプロイまで拒否され、撤回された範囲は再デプロイまで許可されます。

RISで観測した起点経路は、ASNが保有する全アドレスの保証やWAFのASNデータベースとの完全一致ではありません。より詳細な経路の起点が別ASNでも、埋め込んだ広いCIDRに含まれれば許可します。同じASNの他の利用者も許可範囲に入るため、共有トークン認証を併用します。今回のIXのIPv6通知もIPv4のHTTPSで送るため、許可するのはHTTPS送信回線のASNです。

### waf方式：AWSが管理するASN判定を使う

従来のWAF構成を使う場合は`ASN_RESTRICTION_METHOD=waf`にします。この方式ではRIPEstatへ取得せず、AWS WAFが通信の送信元IPからASNを判定します。転送ヘッダーは判定に使いません。AWSが管理する判定を使えるため、CIDR一覧を自分で更新する必要はありません。[AWSのASN判定](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-asn-match.html)

AWS WAFはHTTP APIへ直接関連付けられないため、WAF方式だけREST APIを作成します。ASN許可ルールより先に送信元IPごとのレート制限を評価し、60秒の評価期間に60リクエストを目安として遮断します。厳密な回数保証ではありません。static方式には、このWAFの送信元IPごとのレート制限はありません。[APIの対応機能](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-vs-rest.html)、[AWSのレート制限](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html)

```sh
make deploy
make ix-config
```

**waf方式へ、またはwaf方式から切り替えるとAPIのURLが変わります。** デプロイ後に`make ix-config`で再生成し、IXのURLを更新してください。制限なしとstatic方式の切り替えは同じHTTP APIを使います。生成スクリプトは`.env`とデプロイ済みスタックの有効化・方式・許可ASNを比較するため、設定だけ変更した状態では生成を停止します。方式パラメータ追加前のASN対応スタックはwaf方式として扱います。従来の`.env`で有効化したまま方式を未指定にするとstatic方式になるため、WAFを維持したい場合は`waf`を明示してください。Lambda・共有トークン・ロググループは同じリソースを維持します。

## 定義ファイルの構成

| ファイル | 内容 |
| --- | --- |
| [cloudformation.yaml](cloudformation.yaml) | 共通パラメータ・切り替え条件・Lambda・IAM・共有トークン・ログ |
| [infrastructure/http-api.yaml](infrastructure/http-api.yaml) | 制限なし・static方式で使うHTTP API |
| [infrastructure/rest-api.yaml](infrastructure/rest-api.yaml) | waf方式で使うREST API |
| [infrastructure/waf.yaml](infrastructure/waf.yaml) | 許可ASN・WAF・関連付け・WAFログ |
| [lambda/index.py](lambda/index.py) | 両APIで共通の認証・IP検査・Route 53更新処理 |
| [scripts/build_template.py](scripts/build_template.py) | 定義の結合とLambdaコード・CIDR一覧の埋め込み |
| [scripts/asn_prefixes.py](scripts/asn_prefixes.py) | 起点CIDRの取得・検証・統合 |

`make build`で`.build/template.json`を生成します。分割したソースは個別にデプロイせず、生成した1つのテンプレートを単一のスタックとして扱います。設定値は`make deploy`が`.env`からパラメータとして渡します。`make lint`・`make guard`・`make deploy`もビルドを自動実行するため、定義を編集した後に古い生成物を使うことはありません。REST APIの定義が変わった場合は、ビルド時のハッシュでDeploymentを作り直して変更を反映します。

## IX側のコンフィグ生成

投入用のサンプルファイルを用意しています。IX2000/IX3000のVer.10.11-1.1のマニュアルに基づくもので、実機への投入・接続試験は未実施です。

| サンプル | 対応するAWS側の設定 |
| --- | --- |
| [IPv4用コンフィグ](examples/ix3315-ddns-ipv4.cfg.example) | `RECORD_TYPE=A` |
| [IPv6用コンフィグ](examples/ix3315-ddns-ipv6.cfg.example) | `RECORD_TYPE=AAAA`。IPv4のHTTPSでIPv6アドレスを通知 |

AWS側をデプロイした後、`.env`の`IX_WAN_IF`に、登録するグローバルIPv4を持つ実機のインタフェース名を設定してください。以下のインタフェース名は例なので、実際の接続方式と設定に合わせて指定します。

```dotenv
IX_WAN_IF=GigaEthernet0.1
```

```sh
make ix-config
```

[生成スクリプト](scripts/generate_ix_config.py)がCloudFormationから`UpdateUrl`と`TokenSecretArn`を取得し、Secrets Managerから共有トークンを読み取って`examples/ix3315-ddns-ipv4.cfg`を生成します。追加のPythonパッケージは不要です。実行するAWS認証には`cloudformation:DescribeStacks`と対象シークレットの`secretsmanager:GetSecretValue`が必要です。

| 置換する値 | 取得元 / 設定する変数 |
| --- | --- |
| `<UPDATE_URL>` | スタック出力の`UpdateUrl` |
| `<SHARED_TOKEN>` | スタック出力の`TokenSecretArn`が示すシークレットの`token` |
| `<WAN_IF>` | `.env`の`IX_WAN_IF`。IPv4用 |
| `<SOURCE_IF>` | `.env`の`IX_SOURCE_IF`。IPv6用、HTTPSのIPv4送信元 |
| `<NOTIFY_IF>` | `.env`の`IX_NOTIFY_IF`。IPv6用、登録するグローバルIPv6を持つインタフェース |

`<IP4>`・`<IP6>`・`<PW>`などのIXのマクロはそのまま残します。更新するドメイン名はAWS側の`.env`の`RECORD_NAME`に設定されており、IX側では指定しません。設定とスタックのレコード種別・DNS名・ホストゾーン・ASN制限が一致しない場合や、必要なインタフェース名が未指定の場合は生成を停止します。AWS側の設定を変更した場合は、先に`make deploy`を実行してください。

生成ファイルには平文の共有トークンが含まれます。`examples/*.cfg`はGitの管理対象から除外してあり、スクリプトはトークンやコンフィグ本文を画面に表示しません。保存先は`.env`の`IX_CONFIG_OUTPUT`で変更でき、その場合もGit除外対象のパスを指定してください。再実行すると同じ保存先を上書きします。生成時にAWSやIXの設定は変更せず、IXへの投入は生成ファイルを確認してから行います。

既存のWAN接続、デフォルトルート、IX自身のDNS名前解決が動作する状態で、Administrator権限のオペレーションモードから投入します。グローバルコンフィグモードに入っている場合は、先頭の`configure`を省いてください。IPv4用の主要な設定は以下です。

```text
configure
service ssl-protocol tls1.2-and-later
service password-encryption
ddns profile route53-ipv4
  url <UPDATE_URL>
  query ip=<IP4>&token=<PW>
  password plain <SHARED_TOKEN>
  transport ip
  source-interface <WAN_IF>
  update-interval 1
exit
ddns enable
ddns update route53-ipv4
show ddns route53-ipv4
```

`service ssl-protocol`はDDNS以外のHTTPSクライアント機能にも共通の設定です。変更する場合は、それらの接続先との互換性も確認してください。

`service password-encryption`はDDNSを含む対応機能のパスワード表示を暗号化します。この設定で暗号化されたパスワードは、後から平文表示に戻せません。

`show ddns`の応答内容、AWS側のログ、実際のDNSレコードを確認してから、グローバルコンフィグモードで`write memory`を実行して保存します。サンプルでは保存コマンドをコメントにしてあります。

### IXからの通知トリガー

IX側は標準DDNSクライアントが通知を実行します。IX上で独自スクリプトを起動する設定はありません。`make ix-config`は作業PCで投入用コンフィグを生成するためのコマンドです。

| トリガー | 通知タイミング |
| --- | --- |
| 監視対象インタフェースのIPアドレス変更 | 変更の約10秒後 |
| アドレス変更がない場合の定期更新 | サンプルの`update-interval 1`では1時間ごと（IXのデフォルトは24時間） |
| `ddns update プロファイル名`の実行 | 即時。サンプルでは設定投入後の初回通知に使用 |

監視対象は`notify-interface`で、未指定なら`source-interface`です。IPv4サンプルでは`.env`の`IX_WAN_IF`、IPv6サンプルでは`IX_NOTIFY_IF`に指定したインタフェースのアドレス変更を監視します。`update-interval 1`は変更の監視間隔ではなく、アドレスが変わらない場合にも通知する周期です。アドレス変更時の通知は、この1時間を待たずに実行されるため、別途スケジューラを設定する必要はありません。

回線再接続などで対象インタフェースのIPが変われば、IX自身が変更を検知してAWSへ通知します。下位サーバーから外部IPを定期的に調べる方式と比較した場合、この変更検知がIXに移すメリットになります。

ただし、マニュアルに明記されているトリガーは**IPアドレスの変化**です。リンクのup/downだけで、同じIPのまま復旧した場合にも必ず通知するかは、参照した資料では確認できません。「リンクが復旧するたびに、IPの変化に関係なく即時通知する」動作は保証していません。以上は機能説明書 Ver.10.11-1.1 §2.25.3（PDFの物理ページ404）とコマンドリファレンスの`notify-interface`・`source-interface`・`update-interval`・`ddns update`に基づく説明で、実機での動作確認は未実施です。

### IPv6用の設定

IPv6用スタックは設定ファイルで`RECORD_TYPE=AAAA`と別の`STACK_NAME`を指定して作成します。`IX_SOURCE_IF`はHTTPSをIPv4で送信するインタフェース、`IX_NOTIFY_IF`は登録するグローバルIPv6を持つインタフェースを指定します。両インタフェースは同じものを指定することもできます。

```dotenv
STACK_NAME=ixddns-ipv6
RECORD_TYPE=AAAA
IX_SOURCE_IF=GigaEthernet0.1
IX_NOTIFY_IF=GigaEthernet1.0
```

別ファイル`.env.ipv6`に設定した場合は、次のように実行します。

```sh
make deploy ENV_FILE=.env.ipv6
make ix-config ENV_FILE=.env.ipv6
```

`RECORD_TYPE=AAAA`では`examples/ix3315-ddns-ipv6.cfg`を生成します。残した`<IP6>`は、通知時にIXが`IX_NOTIFY_IF`の先頭のグローバルIPv6に置換します。

## 更新と失敗の確認

更新窓口は`ip`と`token`を各1つだけ受け付けます。不正なトークン、レコード種別に合わないアドレス、非グローバルアドレス、余分なパラメータはDNSを更新せず拒否します。

| HTTP応答 | 意味 |
| --- | --- |
| `200` / `accepted` | Route 53が変更を受理した。DNSへの反映完了を示すものではない |
| `400` | IPアドレスまたはクエリが不正 |
| `401` | トークンが未指定または不一致 |
| `403` | static方式の許可範囲外（`source_not_allowed`）、またはWAFのASN・流量制限 |
| `404` / `405` | URLまたはHTTPメソッドが不正 |
| `429` | APIのスロットリング |
| `503` | シークレット読み取り・Route 53更新の失敗、またはstatic一覧の未埋め込み・ASN不一致 |

正常時はLambdaログに`ddns_update_accepted`、AWS処理の失敗時は`ddns_update_failed`を記録します。リクエスト全体やトークンはログに記録しません。HTTP APIのアクセスログにもクエリを含めません。

static方式の送信元拒否はLambdaログの`ddns_source_rejected`で確認します。WAF方式は`make outputs`の`WafLogGroup`で遮断理由を確認します。WAFログはクエリ全体・Authorization・Cookieヘッダーを除外し、リクエストのサンプリングも無効にしています。REST APIのアクセス／実行ログは設定せず、WAFログとLambdaログで確認します。このためAPI Gatewayのリージョン共通のCloudWatchログロールを設定する必要はありません。CloudWatch Logsは標準の保存時暗号化を使用します。ログの閲覧権限は対象の利用者に限定してください。

IXのDDNSはサーバから応答があると成功と判断し、応答内容から更新の成功・失敗を判定できません。AWS側で失敗してもIXは次の通知まで再試行しない可能性があるため、`show ddns`だけでなくAWS側のログとDNSを確認してください。

```powershell
Resolve-DnsName router.example.com -Type A
```

Route 53への変更は通常60秒以内に各権威DNSへ伝播します。その後も、再帰DNSのキャッシュがTTLまで残る場合があります。共有トークンを手動で差し替えた場合は、IX側のパスワードも更新してください。Lambdaは各通知で現在のトークンを取得するため、古いトークンのキャッシュは残りません。

## 検証

Lambdaのソースを読み出して、AWSの呼び出しだけをモックしたテストを実行します。LambdaとIXコンフィグ生成のテストはPython標準ライブラリで動作し、AWSアカウントやboto3のインストールは不要です。結合テンプレートのテストには、既存の検証環境の`cfn-lint`を使います。

GNU Makeと`sh`が使える環境では、模擬AWS CLIを使い、設定ファイルの読み込み・引数の渡し方・必須設定不足時の停止も検証します。コンフィグ生成はAWSの応答を模擬し、IPv4/IPv6の置換・IXマクロの保持・秘密情報を表示しないこと・不正な設定や取得失敗時の停止を検証します。テストはAWSやRIPEstatへ接続しません。CIDR取得の失敗・古い情報・欠落と、埋め込んだ一覧によるIPv4/IPv6の許可・拒否もモックで検証します。

```powershell
make test
```

CloudFormationのスキーマ検証は`cfn-lint`で行います。AWSアカウントにおける権限・ホストゾーンの所有・サービスクォータ・実機のHTTPS互換性はローカルテストでは確認できません。デプロイ後にログと実際のレコードを確認してください。

このプロジェクトの検証環境はPython 3.14で、`.venv`内の`Ruff 0.16.6`・`cfn-lint 1.57.1`と、`.tools`内の`cfn-guard 3.2.1`を使います。Pythonの開発用依存は[requirements-dev.txt](requirements-dev.txt)でバージョンを固定しています。GNU Makeと`sh`が使える環境で、[makefile](makefile)からまとめて検証します。WindowsではMSYS2のGNU Makeと`sh`を使用できます。

新しく環境を作る場合は、Python 3.14で次のように導入します。既存の`.venv`には`make install-dev`でも導入できます。cfn-guardはPythonパッケージに含まれないため、別途用意してください。

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements-dev.txt
make validate
```

Linux/macOSでは`.venv/bin/python`を使います。

引数なしの`make`も同じ検証を実行します。static制限を有効にした環境の`make build`・`make lint`・`make guard`・`make validate`は、実際のデプロイと同じ一覧を検証するためRIPEstatにアクセスします。`make test`は外部通信しません。

| ターゲット | 内容 |
| --- | --- |
| `make build` | 分割定義とLambdaコードからテンプレートを生成 |
| `make test` | Lambda・Makefile・IXコンフィグ生成・ASN設定・結合テンプレートのテスト |
| `make install-dev` | 既存の仮想環境へ開発用依存を導入 |
| `make ruff` | Pythonの全ルール検査とフォーマット検査 |
| `make format` | Ruffの修正可能な指摘を修正し、Pythonを整形 |
| `make lint` | Ruff検査後、CloudFormationのスキーマ検証 |
| `make guard` | スキーマ検証後、プロジェクトの安全性ルールを検証 |
| `make validate` | 設定確認・テスト・Ruff・スキーマ・安全性の検証 |
| `make ix-config` | デプロイ済みスタックからIX投入用コンフィグを生成 |

リージョンは`make validate REGION=ap-northeast-1`で指定できます。別のツール環境を使う場合は、`PYTHON`、`CFN_LINT`、`CFN_GUARD`を指定して実行してください。

`security.guard`は、このDDNS構成について生成トークン、IAMの対象制限、呼び出し元の制限、ログ、APIルート、ASN制限とWAFの関連付けを検査するプロジェクト独自のルールです。AWS全体のコンプライアンス認定を行うものではありません。

## Ruffのルール方針

[ruff.toml](ruff.toml)で`select = ["ALL"]`と`preview = true`を指定し、プレビューを含む全ルールを有効にしています。Ruffのバージョンも固定し、環境によって検査結果が変わることを防ぎます。設定のルール名はRuff 0.16.6の正式名で記載しています。

行単位の`noqa`・`nolint`・`ruff: ignore`は使いません。`make ruff`は`--ignore-noqa`も指定するため、後から行単位の抑制を加えても検査を通過させません。型注釈・説明文・処理分割・例外の組み立てはコードで対応します。Lambdaコードを読み込むテストは、`exec`の直接使用をやめ、Pythonのモジュールローダーを使います。

コードの性質に合わない以下のルールだけ、設定ファイルで無効化しています。ファイルを限定できるものは対象を限定し、設定内にも理由を記載しています。

| ルール | 対象 | 理由 |
| --- | --- | --- |
| `D203`・`D213` | 全体 | 同時に有効化できない説明文の配置規則。`D211`・`D212`の形式に統一 |
| `D400`・`D415` | 全体 | 日本語の句点「。」で説明を書くため、英文の句読点を要求しない |
| `CPY001` | 全体 | 著作権者・ライセンスが未指定。著作権表示を推測して追加しない |
| `COM812` | 全体 | カンマ配置はRuff formatterで統一 |
| `PT009`・`PT027` | テスト | 標準ライブラリのunittestを採用しており、pytestへの書き換えを要求しない |
| `D102` | テスト | unittestのテスト名・assertionが仕様を示すため、各メソッドに説明を重ねない |
| `S106`・`S107` | Lambdaのテスト2ファイル | 認証の試験に必要なダミートークンで、実際の共有トークンではない |
| `S104` | 通知のテスト | `0.0.0.0`の拒否試験であり、全インタフェースの待受設定ではない |
| `S311` | ASN一覧のテスト | 再現可能な圧縮容量試験のデータ生成。暗号用途ではない |
| `S404`・`S603` | IX生成ツール・Makefileのテスト | 利用者が指定したCLIを引数配列で実行する機能・試験。shellは使用しない |
| `S404` | IX生成のテスト | 模擬応答の`CompletedProcess`型だけを使い、プロセスはモックする |
| `S310` | ASN取得ツール | 接続先は固定のHTTPS API。利用者からURLを受け取らない |
| `T201` | CLIツール3ファイル | 生成結果とエラーを標準出力・標準エラーへ表示するため |
| `INP001` | Lambda | CloudFormationのインラインコードは単一のindex.pyで、パッケージではない |
| `TRY400` | Lambda | SDK例外の本文に秘密情報が含まれ得るため、例外全文やトレースバックを記録しない |

```sh
make ruff
make format
```

`make validate`・`make lint`・`make guard`・`make deploy`でもRuff検査を実行します。

## スタック削除時の扱い

API、Lambda、IAMロールは削除されます。ホストゾーンと、Lambdaが更新したDNSレコードは残ります。共有トークンとロググループも`Retain`で残すため、不要になった場合は所有者が個別に削除してください。

`RecordName`や`RecordType`を変更した場合も、変更前のDNSレコードは自動削除されません。不要なレコードは個別に整理してください。

## 参照

- [NEC: DDNS FAQ](https://jpn.nec.com/univerge/ix/faq/ddns.html)
- NEC IX2000/IX3000 機能説明書 Ver.10.11-1.1、§2.25（DDNS）。§2.25.3（PDFの物理ページ404）に通知トリガー、§2.25.4にGET方式と応答判定の制約を記載。
- NEC IX2000/IX3000 コマンドリファレンス Ver.10.11-1.1、`service ssl-protocol`、`ddns`関連コマンド。
- [AWS: Route 53更新API](https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html)
- [AWS: Route 53のレコード単位のIAM条件](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/specifying-conditions-route53.html)
- [AWS: HTTP APIのLambda連携](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html)
- [AWS: Lambdaランタイム](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html)
- [Ruff: 設定方法](https://docs.astral.sh/ruff/configuration/)
- [Ruff: ルール一覧](https://docs.astral.sh/ruff/rules/)
