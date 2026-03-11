# MDE CLI 追加 API 実装計画

## ゴール

アラート分析に必要な MDE API を CLI に追加し、アラートから関連情報を深掘りできるようにします。

## 現在の実装状況

- [x] alerts list / get / update (MDE API)
- [x] incidents list / get / update (Graph API)
- [x] auth token / device-code (OAuth2)

## 実装タスク

### Phase 1: Advanced Hunting（優先度: 高）

KQL クエリを実行して、アラートに関連するイベントの詳細を特定できます。

- [x] 1-1. `src/cli/hunting.rs` - CLI 定義（`hunting run --query "..."` サブコマンド）
- [x] 1-2. `src/commands/hunting.rs` - `POST /api/advancedhunting/run` の実装
- [x] 1-3. `src/cli/mod.rs`, `src/commands/mod.rs` - サブコマンド登録
- [x] 1-4. `src/main.rs` - Hunting コマンドのルーティング（MDE API base_url を使用）
- [x] 1-5. `src/client/mod.rs` - `post` メソッドを追加

### Phase 2: Machines（優先度: 高）

デバイスの詳細情報（OS、リスクスコア、ヘルスステータス）を取得できます。

- [x] 2-1. `src/cli/machines.rs` - CLI 定義（`machines list / get / timeline / logon-users` サブコマンド）
- [x] 2-2. `src/commands/machines.rs` - 各エンドポイントの実装
- [x] 2-3. `src/cli/mod.rs`, `src/commands/mod.rs`, `src/main.rs` - 登録・ルーティング

### Phase 3: Machine Timeline（優先度: 中）

- [x] 3-1. Phase 2 に統合して `machines timeline` サブコマンドとして実装済み

### Phase 4: Alert 関連エンティティ（優先度: 中）

- [x] 4-1. `src/cli/alerts.rs` に `files / ips / domains` サブコマンドを追加
- [x] 4-2. `src/commands/alerts.rs` に `related_entity` 関数を追加

### Phase 5: Machine Logon Users（優先度: 低）

- [x] 5-1. Phase 2 に統合して `machines logon-users` サブコマンドとして実装済み

## API とベース URL の対応

| サブコマンド | ベース URL | スコープ |
|---|---|---|
| alerts, machines, hunting | `https://api.security.microsoft.com` | `https://api.securitycenter.microsoft.com/.default` |
| incidents | `https://graph.microsoft.com` | `https://graph.microsoft.com/.default` |

## 必要な API パーミッション

| パーミッション | 用途 |
|---|---|
| Alert.Read.All | アラート読み取り（既存） |
| Machine.Read.All | デバイス情報読み取り |
| AdvancedQuery.Read.All | Advanced Hunting クエリ実行 |
