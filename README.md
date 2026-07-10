# symbol-bootstrap — BNL Post-Quantum edition

> ⚠️ **Unofficial, experimental post-quantum (PQC) fork** of symbol-bootstrap. With the
> **unchanged standard CLI** it generates and operates **BNL Post-Quantum Catapult** networks
> (ML-DSA-44 signatures / ML-KEM-768 key exchange / iVRF block lottery / ML-DSA finality voting).
> It cannot create or join public Symbol networks. Unaffiliated with official Symbol/NEM.
> This fork is **not** the `symbol-bootstrap` package on npm.

公式 Symbol/NEM とは無関係の、非公式・実験的なポスト量子（PQC）フォークです。
**CLI の操作方法は上流と同一のまま**、BNL Post-Quantum Catapult チェーン
（ML-DSA-44 署名 / ML-KEM-768 鍵交換 / iVRF ブロック抽選 / ML-DSA 投票）の
カスタムネットワークを生成・運用できます。公開 Symbol ネットワークの構築・参加はできません。
npm で配布されている `symbol-bootstrap` パッケージとは別物です。

## クイックスタート

```bash
git clone -b pqc-bootstrap https://github.com/bootarou/symbol-bootstrap.git
cd symbol-bootstrap
npm install
npm link                        # または node bin/run で直接実行

# PQC ネットワークの生成 → compose 生成 → 起動
symbol-bootstrap config  -p bootstrap -a dual    # ML-DSA 鍵・証明書・iVRF VrfKeyLink・PQC nemesis
symbol-bootstrap compose --upgrade               # docker-compose.yml 生成
docker compose -f target/docker/docker-compose.yml up -d   # node + broker + mongo + rest
```

起動後、`http://localhost:3000/chain/info` で高さの増加を、
`/blocks/2` で iVRF proof（`iVrfProofLeaf` / `iVrfProofPath`）を確認できます。

検証済みの動作: 鍵/nemesis 生成 → 全コンテナ起動 → iVRF/ML-DSA での連続採掘（エラー 0）→
broker → mongo 投影 → REST 提供（詳細:
[PQC-bootstrap-report.md](https://github.com/bootarou/bnl-catapult-pqc/blob/feat-VRF/votiong/PQC-bootstrap-report.md)）。

## 動作要件

- Docker / Docker Compose
- Node.js >= 14
- PQC Docker イメージ（`presets/shared.yml` が参照。初回 `up` 時に Docker Hub から自動取得）:
  - `nftdrive/bnl-catapult-server-pqc:1.0.3.9-bnl`（server / broker）
  - `nftdrive/bnl-catapult-rest-pqc:2.4.3-bnl`（REST）
  - `mongo:5.0.15`（公式・無改変）
  - いずれも linux/amd64

## 上流 symbol-bootstrap との差分（`pqc-bootstrap` ブランチ）

| 箇所 | 変更 |
|---|---|
| `lib/service/CertificateService.js` | ノード証明書を **ML-DSA-44** で生成（`openssl genpkey -algorithm ML-DSA-44 -pkeyopt hexseed:<seed>` による seed 決定的導出。公開鍵が catapult とバイト一致） |
| 鍵・アカウント生成 | 署名系アカウントを **ML-DSA-44** で導出（公開鍵 1312 B・アドレスが catapult と一致）。VRF 公開鍵 = **iVRF 木の root**、voting は **ML-DSA** |
| nemesis 生成 | PQC 版 `nemgen`（PQC server イメージ内）で ML-DSA 署名 nemesis + iVRF proof を生成 |
| `lib/service/ComposeService.js` | mongo のデータディレクトリを `/data/db` に修正（公式イメージの entrypoint が chown する経路に乗せ、権限エラーで db が落ちる問題を解消） |
| `config/rest-gateway/rest.json.mustache` | `routeExtensions: []` を追加（PQC REST 2.5.1 系が要求） |
| `presets/shared.yml` | `symbolServerImage` / `symbolRestImage` を PQC イメージ（`nftdrive/bnl-catapult-*-pqc`）へ |

ベース: symbol-bootstrap v1.1.10（コンテナから抽出、`lib/` を直接パッチ）。

## 運用上の注意

- **`config --reset` は鍵・nemesis を再生成**するため、稼働中チェーンの state と齟齬が出ます。
  既存チェーンを維持する場合は `compose` のみ再生成し、生成済み設定をパッチする運用が安全です。
- 単一ノード構成での `no packet io available for ...` はピア不在による無害な警告です
  （採掘・API に影響なし）。
- node/broker を同時に `--force-recreate` すると稀に stale lock（`recovery.lock`）で broker が
  落ちます。`docker compose down` → lock 掃除 → `up -d` のクリーンサイクルで解消します。

## 関連リポジトリ

| | |
|---|---|
| [bnl-catapult-pqc](https://github.com/bootarou/bnl-catapult-pqc) | 本体モノレポ（catapult-server / REST / SDK v3） |
| [PQC-SUMMARY.md](https://github.com/bootarou/bnl-catapult-pqc/blob/feat-VRF/votiong/PQC-SUMMARY.md) ([EN](https://github.com/bootarou/bnl-catapult-pqc/blob/feat-VRF/votiong/PQC-SUMMARY.en.md)) | PQC 移行作業の総括資料 |
| [pqc-catapult-sdk-v3](https://github.com/bootarou/pqc-catapult-sdk-v3) | PQC SDK v3（アプリ開発用） |
| [pqc-catapult-explorer](https://github.com/bootarou/pqc-catapult-explorer) | ブロックエクスプローラ |
| [blockchain-network-launcher](https://github.com/bootarou/blockchain-network-launcher) | **BNL 本体** — カスタムブロックチェーンネットワークの起動・管理ツール |
| Docker Hub `nftdrive/bnl-catapult-server-pqc` / `bnl-catapult-rest-pqc` | PQC ノード / REST イメージ |

## ライセンス / 派生元

派生元: [symbol-bootstrap](https://github.com/fboucquez/symbol-bootstrap)（Fernando Boucquez, Apache License 2.0）。
上流の npm バッジ・CI バッジ・公式ドキュメントリンクは本フォークには該当しないため削除しています。
コマンドリファレンスは上流と共通です（`symbol-bootstrap --help` または派生元の docs を参照）。
