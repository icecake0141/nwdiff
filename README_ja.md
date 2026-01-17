# NW-Diff プロジェクト

NW-Diff は、ネットワークデバイスから収集された設定またはステータスデータを取得、比較、表示するために設計された Flask ベースのウェブアプリケーションです。Netmiko を利用してデバイスに接続し、CSV ファイルに定義されたデータをキャプチャします。diff-match-patch を使用して、2 つのデータセット間の差分を計算し、インライン表示およびサイドバイサイド表示で結果を提示します。差分 HTML ファイルは生成され、専用の "diff" ディレクトリに保存され、後で確認できます。

## 機能

- **デバイス設定:**
  ホスト情報（ホスト名、IP アドレス、SSH ポート、ユーザー名、デバイスモデル）は CSV ファイル (`hosts.csv`) に保持されます。

- **データキャプチャ:**
  2 つのエンドポイントにより各デバイスのデータをキャプチャします:
  - `/capture/origin/<hostname>`: 初期（または元の）データをキャプチャします。
  - `/capture/dest/<hostname>`: 最新（または宛先）のデータをキャプチャします。

  キャプチャされた出力は、それぞれ `origin` と `dest` ディレクトリに保存されます。

- **設定バックアップ:**
  履歴設定を保持し、データ損失を防ぐため、ファイル上書き前に自動バックアップを作成します:
  - キャプチャ操作時、ファイルが上書きされる前に自動的にバックアップが作成されます
  - ローテーションシステムにより、ファイルごとに最新の10個のバックアップが保持されます
  - バックアップは `backup/` ディレクトリにタイムスタンプ付きで保存されます
  - ファイル名形式: `YYYYMMDD_HHMMSS_hostname-command.txt`
  - 誤った上書きから保護し、履歴設定の追跡を可能にします
  - 必要に応じて古い設定を復元できます

- **差分計算:**
  アプリケーションは、`origin` と `dest` ディレクトリ内の対応するファイルを diff-match-patch を使用して比較します:
  - **インライン表示:** 標準の差分出力を提示します。
  - **サイドバイサイド表示:** 左側に元データ、右側に計算された差分を表示します。

  差分結果は HTML ファイルに変換され、`diff` ディレクトリに保存されます。

- **詳細なデバイス表示:**
  `/host/<hostname>` エンドポイントを通じて各デバイスの詳細情報にアクセスできます。

## インストール

1. **リポジトリのクローン:**
   ```bash
   git clone https://github.com/yourusername/nw-diff.git
   ```
2. **プロジェクトディレクトリに移動:**
   ```bash
   cd nw-diff
   ```

3. **依存関係のインストール:**
   Python がインストールされていることを確認し、必要なパッケージをインストールします:
   ```bash
   pip install -r requirements.txt
   ```
   必要なパッケージには Flask、Netmiko、diff-match-patch が含まれます。

4. **環境変数の設定:**
   - デバイス接続に必要なパスワードを設定するため、`DEVICE_PASSWORD` 環境変数を設定します:
     ```bash
     export DEVICE_PASSWORD=your_device_password
     ```
   - **機密性の高い API エンドポイント（キャプチャ、ログ、エクスポート）を保護するため、`NW_DIFF_API_TOKEN` 環境変数を設定します**:
     ```bash
     export NW_DIFF_API_TOKEN=your_secure_random_token
     ```
     安全なトークンを生成するには:
     ```bash
     python -c "import secrets; print(secrets.token_urlsafe(32))"
     ```

     **重要:** `NW_DIFF_API_TOKEN` が設定されていない場合、機密性の高いエンドポイントは認証なしでアクセス可能になります（本番環境では推奨されません）。

   - **（オプション）ホストインベントリファイルのカスタム場所を指定するため、`HOSTS_CSV` 環境変数を設定します**:
     ```bash
     export HOSTS_CSV=/path/to/hosts.csv
     ```
     設定されていない場合、アプリケーションは現在のディレクトリのデフォルトの `hosts.csv` を使用します。

     **利点:** リポジトリの外にホストインベントリを保存することで、機密データ（IP アドレス、ユーザー名、デバイスモデル）の誤ったコミットを防ぎ、セキュリティが向上します。これは、インベントリをシークレットまたは設定ボリュームとしてマウントできる本番デプロイメントに特に有用です。

     **コンテナの例:**
     ```bash
     docker run -v /secure/path/hosts.csv:/app/hosts.csv -e HOSTS_CSV=/app/hosts.csv ...
     ```

## 使用方法

### 本番モードでの実行（デフォルト）

デフォルトでは、セキュリティのため Flask デバッグモードが**無効**になっています:

1. **アプリケーションの起動:**
   ```bash
   python app.py
   ```
2. **アプリケーションへのアクセス:**
   ブラウザで [http://localhost:5000](http://localhost:5000) にアクセスします。

### 開発モードでの実行

ローカル開発では、`APP_DEBUG` 環境変数を設定してデバッグモードを有効にできます:

1. **デバッグモードで実行:**
   ```bash
   export APP_DEBUG=true
   python app.py
   ```
   またはインラインで実行:
   ```bash
   APP_DEBUG=true python app.py
   ```
2. **アプリケーションへのアクセス:**
   ブラウザで [http://localhost:5000](http://localhost:5000) にアクセスします。

**注意:** デバッグモードは機密情報を公開しセキュリティ脆弱性を生む可能性があるため、本番環境では**決して**有効にしないでください。

### エンドポイントとの連携

#### 公開エンドポイント（認証不要）
- **ホスト一覧の表示:** `/`（ホームページ）
- **詳細なデバイス情報の表示:** `/host/<hostname>`
- **ファイルの比較:** `/compare_files`

#### 保護されたエンドポイント（認証が必要）
以下のエンドポイントは `Authorization: Bearer <token>` ヘッダーによる認証が必要です:
- **データキャプチャ:**
  - 元データ: `/capture/origin/<hostname>`
  - 宛先データ: `/capture/dest/<hostname>`
  - 全デバイス: `/capture_all/origin` または `/capture_all/dest`
- **ログの表示:**
  - Web UI: `/logs`
  - API: `/api/logs`
- **データのエクスポート:**
  - HTML エクスポート: `/export/<hostname>`
  - JSON API: `/api/export/<hostname>`

**curl を使用した例:**
```bash
curl -H "Authorization: Bearer your_token_here" http://localhost:5000/api/logs
```

**注意:** `NW_DIFF_API_TOKEN` が設定されていない場合、これらのエンドポイントは認証なしで動作します（本番環境では推奨されません）。

### 差分結果の確認

計算された差分 HTML ファイルは `diff` ディレクトリに保存され、オフラインで確認できます。

## 開発

1. **開発用依存関係のインストール:**
   ```bash
   pip install -r requirements.txt -r requirements-dev.txt
   ```

2. **セキュリティ監査の実行:**
   ```bash
   pip-audit -r requirements.txt -r requirements-dev.txt
   ```

3. **フォーマット、Lint、型チェック、テスト:**
   ```bash
   black app.py tests nw_diff
   pylint app.py tests nw_diff
   mypy app.py nw_diff tests
   pytest
   ```

4. **pre-commit フックの実行:**
   ```bash
   pre-commit run --all-files
   ```
