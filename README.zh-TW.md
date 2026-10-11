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
- ❌ LLM 的回應仍可能包含敏感內容 — 回應 guard 加以緩解：含敏感內容或違反
  政策的回應一律阻擋（fail closed），未知 token 永不還原。

## 現況

- 階段：**PoC 完成（M0–M6，v0.4.0）** — 見 `docs/FINAL_REPORT.md`
- M0 設計審查：完成（v0.3）
- M1 偵測：完成 — benchmark acceptance PASS（aggregate precision 0.8458 /
  recall 0.9738；見 `docs/DECISIONS.md`）
- M2 tokenisation：完成 — session vault、span 級替換、指令保護、安全測試套件
- M3 LLM 整合：完成 — Anthropic provider（stdlib、零新依賴）、protected
  request builder、session orchestrator、互動 CLI
- M4 回應保護：完成 — 回應 guard（重用偵測引擎做敏感資料掃描、未知/幻覺 token
  偵測、marker echo 任務合規檢查、受控 token 還原）；違規以 `response:<category>`
  機器可讀 reason fail closed；截斷（`stop_reason: max_tokens`）一律阻擋
- M5 安全測試套件：完成 — 20 項 POC_PLAN item 全數對應 passing test
  （`docs/TEST_TRACEABILITY.md`）；response 側 prompt injection 偵測
  （mirror rule、`response:injection:<CAT>`）；窮舉 fail-closed sweep
  （22 條失敗路徑、trust boundary 前零 provider calls）；SR-016 audit
  event battery；benchmark 證據以規範門檻自動 re-check
- M6 持久 token 儲存：完成（opt-in）— `--vault-store PATH` +
  `VAULT_MASTER_KEY` 讓 token 身分跨 session 保持穩定，存入
  Fernet 加密 JSON store（SR-026）；預設 session 維持 session-only；
  restore() 維持 session 範圍（舊 session token 出現在回應仍會
  阻擋，fail closed）；1011 tests 全綠

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
回應 guard：token 驗證 -> marker 檢查 -> 還原已知 token
        -> 敏感資料掃描 -> 受控還原（最終結果）
```

Token 對應表是隨機、非順序、單一 gateway 呼叫範圍，session 結束即銷毀；
絕不出現在 LLM 請求、log、report 或任何 client 可見的介面。

### 實際例子

財務部請 AI 分析這份 CSV：

```
客戶,營業收入,毛利率
Aurora Motors AU,8.4M,32%
```

指令：`請分析這份文件的營業收入`

1. **讀取** — gateway 讀檔並正規化編碼。
2. **掃描** — `Aurora Motors AU` 被標記為識別碼；公式前綴或夾帶的惡意
   指令也會在此被攔截。
3. **政策（預設拒絕）** — 偵測到密碼整筆擋下；個資換代號；允許清單外的
   欄位直接丟棄。
4. **換代號** — AI 只看到 `CUSTOMER_4f8a21, 8.4M, 32%`。對照關係隨機
   產生、僅本次處理有效，session 結束即銷毀。
5. **分析** — 外部 AI 從頭到尾不知道真實客戶名。
6. **還原** — 回覆以 `Aurora Motors AU 毛利率 32%…` 交付。本次 session
   未發出的代號一律拒絕（`response:unknown_token`）；對照表不越過信任
   邊界。

指令本身也是受保護的輸入：其中的原始識別碼會與文件走同一條管線，才送達
LLM。完整視覺化說明見
[docs/gateway_example.html](docs/gateway_example.html)。

### 什麼是 PII？

PII（個人可識別資訊，個資）是任何能認出特定個人或公司的資料 —— 姓名、
地址、身分證字號、電話、Email、客戶／員工編號、信用卡等。Gateway 對這
些內容換代號。密碼類（API key、密碼、JWT、私鑰）不是 PII 但更敏感：
偵測到就整筆擋下（fail closed）。一般數字（營收、毛利率）兩者都不是，
直接放行。三層偵測器 —— Presidio、中文 NLP 後端、自訂 regex
recognizers —— 負責分辨哪個是哪個。

試試 demo：

```bash
export ANTHROPIC_API_KEY=sk-...          # 真實 API 呼叫
.venv/bin/python -m secure_ai_gateway.cli --file data.csv \
    --instruction "請分析毛利率趨勢"       # --provider fake = 離線 demo
```

持久 token 儲存（M6，opt-in — 跑兩次，token 相同）：

```bash
export VAULT_MASTER_KEY=$(.venv/bin/python -c \
    "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
.venv/bin/python -m secure_ai_gateway.cli --file data.csv \
    --provider fake --vault-store tmp/demo.vault
.venv/bin/python -m secure_ai_gateway.cli --file data.csv \
    --provider fake --vault-store tmp/demo.vault   # 再次執行，token 相同
```

## 技術棧

核心偵測層：

| 技術 | 版本 | 角色 |
|---|---|---|
| Presidio Analyzer | 2.2.364 | PII 偵測框架（規則 + ML recognizers） |
| spaCy + `zh_core_web_lg` | 3.7.2（575MB 模型） | 注入 Presidio 的中文 NLP 後端 —— 人名／組織／地址 NER |
| 自訂 regex recognizers | 內建 | 確定性規則：台灣身分證字號、手機號碼、中文姓名規則 |

處理與儲存層：

| 技術 | 版本 | 角色 |
|---|---|---|
| charset-normalizer | 3.3.2 | 編碼偵測（避免 mojibake 藏住 PII） |
| pandas / openpyxl | >=2.2 / >=3.1.2 | 表格資料、.xlsx 解析 |
| defusedxml | 0.7.1 | 安全 XML 解析（防 XXE） |
| cryptography（Fernet） | >=50 | 持久 token store 加密（M6，opt-in） |

刻意不用：無 web framework、無資料庫、無 `requests`/`httpx` —— LLM
呼叫用 stdlib `urllib.request` 並強制 https-only（SR-001）；token 用
stdlib `secrets`。開發工具：pytest、ruff、mypy、bandit、pip-audit，
由 pre-commit gate 與 CI 強制執行。

（「無 web framework」是就 **gateway 套件** 而言。`tools/dashboard`
的本機除錯 dashboard 用 stdlib `http.server` 在 loopback 上提供頁面
——仍然沒有第三方 framework、沒有新增依賴，也不在打包發行的範圍內。
見 SR-027。）

### 每個技術在執行時做什麼

同一個六步驟，標出每一步實際做事的技術：

1. **讀取** — `charset-normalizer` 偵測檔案編碼（猜錯會讓中文變亂碼、
   讓偵測器瞎掉）；`openpyxl` + `defusedxml` 安全開啟 .xlsx（防
   XXE）；`unicodedata` 統一全形／半形（NFKC）。
2. **掃描** — 三個偵測器輪流看：spaCy 中文模型把詞標記為人／組織／
   地址；Presidio 把線索組織成「是不是 PII」的分數（還會參考「客戶」
   這類欄位名的上下文提示）；自訂 regex 用 100% 確定的規則抓格式
   （身分證、手機號碼）。
3. **政策** — 靜態政策引擎（寫死的程式，不是 AI）逐格蓋章：密碼 →
   整筆擋下、PII → 換代號、允許清單欄位 → 放行。規則說不動。
4. **換代號** — stdlib `secrets.token_hex` 生出隨機代號
   （`CUSTOMER_4f8a21`）；對照表只在記憶體（`cryptography`／Fernet
   只在 opt-in 的 M6 vault store 才登場）。
5. **分析** — stdlib `urllib.request` 發 HTTPS POST（強制 https-only，
   SR-001）；AI 只看到代號。
6. **還原** — response guard 把回覆裡每個代號對照本次 session 的
   vault 驗證（陌生代號拒絕）、掃描有無洩漏的敏感內容，再把真名換回。

以上每一環都由 1011 個測試釘住。

## 文件

- `docs/FINAL_REPORT.md` — 最終 PoC 報告（驗收、證據、residuals）
- `docs/gateway_example.html` — 視覺化運作說明（瀏覽器直接開啟）
- `CLAUDE.md` — Claude Code 專案指令（安全規則、milestone 關卡）
- `docs/DESIGN.md` — 架構與設計規格
- `docs/SECURITY_REQUIREMENTS.md` — 安全需求（SR-001 … SR-027）
- `docs/THREAT_MODEL.md` — STRIDE 威脅模型（25 項威脅）
- `docs/POC_PLAN.md` — M0–M6 milestones 與驗收標準
- `docs/DECISIONS.md` — 決策紀錄（M0/M1/M2/M5/M6 + 2026-09-18 dashboard）
- `tools/dashboard/README.md` — 本機除錯 dashboard（SR-027，開發工具）

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

### Pre-commit gate

Fail-closed 的 pre-commit hook 會在 staged Python 檔案上跑
ruff、mypy、bandit 與完整測試套件（並拒絕 commit `*.vault`
token-store 檔）。每個 clone 需啟用一次：

```bash
git config core.hooksPath .githooks
```

需要 dev tools（`uv pip install -e ".[dev]"`）。僅在緊急時用
`git commit --no-verify` 跳過 —— 不要為了方便弱化這個 gate。

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"   # 或：uv pip install -p .venv -e ".[dev]"
.venv/bin/pytest tests/unit tests/security
.venv/bin/pytest -m benchmark tests/benchmark/   # 慢：完整偵測 benchmark
.venv/bin/python scripts/check_acceptance.py     # M1 驗收門檻
```

Benchmark 輸出在 `bench_reports/`。報告檔對（`benchmark_report.json`
+ `.md`）**有進版控** —— 它是 SR-015 的驗收證據，由
`tests/security/test_m5_benchmark_evidence.py` 重驗，CI 需要它；benchmark
產生的其他檔案仍為 gitignored。

## 授權

Apache-2.0 — 見 [LICENSE](LICENSE)。
