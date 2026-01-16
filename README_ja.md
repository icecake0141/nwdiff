# Nwdiff プロジェクト

Nwdiff は、ネットワークデバイスから収集された設定またはステータスデータを取得、比較、表示するために設計された Flask ベースのウェブアプリケーションです。Netmiko を利用してデバイスに接続し、CSV ファイルに定義されたデータをキャプチャします。diff-match-patch を使用して、2 つのデータセット間の差分を計算し、インライン表示およびサイドバイサイド表示で結果を提示します。差分 HTML ファイルは生成され、専用の "diff" ディレクトリに保存され、後で確認できます。

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
   git clone https://github.com/yourusername/nwdiff.git
   ```
2. **プロジェクトディレクトリに移動:**
   ```bash
   cd /workspaces/nwdiff
   ```

3. **依存関係のインストール:**
   Python がインストールされていることを確認し、必要なパッケージをインストールします:
   ```bash
   pip install -r requirements.txt
   ```
   必要なパッケージには Flask、Netmiko、diff-match-patch が含まれます。

4. **環境変数の設定:**
   デバイス接続に必要なパスワードを設定するため、`DEVICE_PASSWORD` 環境変数を設定します:
   ```bash
   export DEVICE_PASSWORD=your_device_password
   ```

## 使用方法

1. **アプリケーションの起動:**
   ```bash
   python app.py
   ```
2. **アプリケーションへのアクセス:**
   ブラウザで [http://localhost:5000](http://localhost:5000) にアクセスします。

3. **エンドポイントとの連携:**
   - **データキャプチャ:**
     - 元データは: `/capture/origin/<hostname>`
     - 宛先データは: `/capture/dest/<hostname>`
   - **詳細なデバイス表示:**
     `/host/<hostname>`

4. **差分結果の確認:**
   計算された差分 HTML ファイルは `diff` ディレクトリに保存され、オフラインで確認できます。

## 開発

1. **開発用依存関係のインストール:**
   ```bash
   pip install -r requirements.txt -r requirements-dev.txt
   ```

2. **フォーマット、Lint、型チェック、テスト:**
   ```bash
   black tests
   pylint tests
   mypy tests
   pytest
   ```

3. **pre-commit フックの実行:**
   ```bash
   pre-commit run --all-files
   ```
