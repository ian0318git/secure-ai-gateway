# Secure AI Gateway

[English](README.md) | **繁體中文**

## 為什麼做這個專案

員工常用**個人 AI 帳號**（ChatGPT、Claude、Gemini…）分析商業文件——而這個
動作等於把機密檔案原封不動上傳到外部供應商的伺服器：沒有企業政策、沒有核
准、沒有去識別化，整份原始文件（含 PII）直接越過信任邊界。

這個專案是一個**資料保護閘道**，介於使用者與外部 LLM 之間。在資料離開你的
環境之前，閘道會：

- **封鎖**整個請求 — 偵測到 secrets（API keys、密碼、JWT、私鑰、憑證）時；
- **代碼化（tokenise）**PII 與識別資料（姓名、身分證、電話、email、地址、
  客戶編號…）成隨機、session 範圍的 opaque tokens — LLM 永遠看不到原始值，
  token 對應表也永遠不離開信任環境；
- **丟棄**目前任務不需要的欄位；
- **保護使用者的指令**，與保護文件內容相同：指令中的 raw 識別資料同樣會被
  偵測與代碼化。

因此 LLM 收到的是一份已最小化、已代碼化的資料；被封鎖的請求則什麼都不送出。

### 這個專案能解決什麼 — 以及不能解決什麼

它**大幅降低**「使用個人 AI 帳號」的資料暴露風險：

- ✅ Raw PII 與 secrets 永遠不會到達供應商；對應表留在信任環境內，session
  結束即銷毀。
- ✅ 風險從「整份機密文件外洩」降到「只剩閘道允許的非敏感內容」。

它**不能取代企業治理**：

- ❌ 帳號層級的風險仍在：聊天紀錄留存、供應商資料使用政策、帳號被盜 — 這些
  不在閘道管轄範圍。
- ❌ 它只保護**經過閘道**的流量 — 使用者直接把 raw 資料貼進 chat，是政策與
  訓練問題，不是閘道能解決的。
- ❌ 允許欄位中的**非 PII 機密內容**（營收數字、策略文字）仍然會送到 LLM。
  Tokenisation 保護的是 PII，不是「所有機密」。
- ❌ 安全邊界就是信任環境本身：控制閘道的人就能讀到對應表（threat model
  有 cover）。
- ❌ LLM 的回應仍可能包含敏感內容 — 回應保護是 M4 的範圍。

## 現況

- 階段：**M2 — tokenisation（已實作）**
- M0 設計審查：完成（v0.3）
- M1 偵測：完成 — benchmark acceptance PASS（aggregate precision 0.8458 /
  recall 0.9738；見 `docs/DECISIONS.md`）
- M2 tokenisation：已實作 — session vault、span 級替換、指令保護、安全測試套件
- M3（LLM 整合）在 M2 acceptance 與人工核准後才開始（見 `docs/POC_PLAN.md`）

## 運作方式

```
使用者指令 + 文件
        |
        v
偵測（Presidio + 中文 NLP 後端）-> 注入偵測
        -> 資料最小化 -> 代碼化 -> 政策檢查
        |
        v
        外部 LLM（只收去識別化資料）
        |
        v
回應掃描 -> token 還原（內部）-> 最終結果
```

Token 對應表是隨機、非順序、單一 gateway 呼叫範圍，session 結束即銷毀；
絕不出現在 LLM 請求、log、report 或任何 client 可見的介面。

## 文件

- `CLAUDE.md` — Claude Code 專案指令（安全規則、milestone 關卡）
- `docs/DESIGN.md` — 架構與設計規格
- `docs/SECURITY_REQUIREMENTS.md` — 安全需求（SR-001 … SR-025）
- `docs/THREAT_MODEL.md` — STRIDE 威脅模型（20 項威脅）
- `docs/POC_PLAN.md` — M0–M5 milestones 與驗收標準
- `docs/DECISIONS.md` — 決策紀錄（M0/M1/M2）

## 決策（M0, v0.3 記錄）

- **專案名稱：** secure-ai-gateway
- **授權：** Apache-2.0
- **偵測驗收：** aggregate recall >= 90% / precision >= 80%；PERSON /
  ADDRESS / ID 每類 recall >= 85% / precision >= 80%；F1 必須回報
- **Session：** 一次 gateway 呼叫（一條指令 + 一份文件）；token 對應表隨機、
  非順序、session 結束即銷毀
- **政策：** 預設拒絕；secrets 封鎖請求、PII 代碼化、非必要欄位丟棄
- **回應違規：** 封鎖（fail closed）；未知 token 永不還原
- **PoC 只用合成資料**

## PoC 限制

本 PoC 不聲稱：

- 完整的 PII 偵測
- 完整的 prompt injection 防護
- 完整的推論攻擊防護
- 生產級安全
- 法規遵循（ISO 27001、SOC 2、GDPR、澳洲隱私法）
- 企業級可用性
- 跨 session 身分關聯

即使已去識別化的內容仍會送到外部 LLM 供應商，受供應商資料處理與留存政策
約束。Tokenisation 是假名化（pseudonymisation），不是數學意義上的匿名。

## 開發

Python >= 3.12。依賴包含中文 spaCy 模型 `zh_core_web_lg`（約 575MB 下載）。

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"   # 或：uv pip install -p .venv -e ".[dev]"
.venv/bin/pytest tests/unit tests/security
.venv/bin/pytest -m benchmark tests/benchmark/   # 慢：完整偵測 benchmark
.venv/bin/python scripts/check_acceptance.py     # M1 驗收門檻
```

Benchmark 輸出在 `bench_reports/`（gitignored）。

## 授權

Apache-2.0 — 見 [LICENSE](LICENSE)。
