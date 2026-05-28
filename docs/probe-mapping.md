# Probe → OWASP LLM Top 10 / MITRE ATLAS / NIST AI RMF mapping

All 167 probes in the Argus library, mapped to their primary control-framework category.

**Coverage:** LLM01: **125**&nbsp;&nbsp;LLM02: **1**&nbsp;&nbsp;LLM03: **5**&nbsp;&nbsp;LLM04: **1**&nbsp;&nbsp;LLM05: **8**&nbsp;&nbsp;LLM06: **16**&nbsp;&nbsp;LLM07: **1**&nbsp;&nbsp;LLM08: **1**&nbsp;&nbsp;LLM09: **8**&nbsp;&nbsp;LLM10: **1**

## Coverage by OWASP LLM Top 10 category

| OWASP | Category | Main library | garak | Total |
|---|---|---:|---:|---:|
| **LLM01** | Prompt Injection | 37 | 88 | 125 |
| **LLM02** | Sensitive Information Disclosure | 1 | 0 | 1 |
| **LLM03** | Supply Chain | 5 | 0 | 5 |
| **LLM04** | Data and Model Poisoning | 1 | 0 | 1 |
| **LLM05** | Improper Output Handling | 8 | 0 | 8 |
| **LLM06** | Excessive Agency | 12 | 4 | 16 |
| **LLM07** | System Prompt Leakage | 1 | 0 | 1 |
| **LLM08** | Vector and Embedding Weaknesses | 1 | 0 | 1 |
| **LLM09** | Misinformation | 1 | 7 | 8 |
| **LLM10** | Unbounded Consumption | 1 | 0 | 1 |
| **Total** | | **68** | **99** | **167** |

## Framework cross-reference

| OWASP LLM | Category | MITRE ATLAS | NIST AI RMF |
|---|---|---|---|
| LLM01 | Prompt Injection | AML.T0051 LLM Prompt Injection (direct/indirect) | MEASURE 2.6 Safety; MEASURE 2.7 Security |
| LLM02 | Sensitive Information Disclosure | AML.T0057 LLM Data Leakage | MEASURE 2.10 Privacy; MEASURE 2.3 Validity |
| LLM03 | Supply Chain | AML.T0010 ML Supply Chain Compromise | GOVERN 6 Third-party risk; MAP 4 Risks |
| LLM04 | Data and Model Poisoning | AML.T0020 Poison Training Data | MEASURE 2.9 Information integrity; MEASURE 2.11 Bias |
| LLM05 | Improper Output Handling | AML.T0053 LLM Plugin Compromise | MEASURE 2.6 Safety; MEASURE 2.7 Security |
| LLM06 | Excessive Agency | AML.T0054 LLM Jailbreak; AML.T0061 LLM Trusted Output Components | MEASURE 2.7 Security; MAP 3 Mission |
| LLM07 | System Prompt Leakage | AML.T0057 LLM Data Leakage | MEASURE 2.10 Privacy |
| LLM08 | Vector and Embedding Weaknesses | AML.T0011 User Execution; AML.T0020 Poison Training Data | MEASURE 2.3 Validity; MAP 2 System categorization |
| LLM09 | Misinformation | AML.T0048 External Harms | MEASURE 2.9 Information integrity |
| LLM10 | Unbounded Consumption | AML.T0029 Denial of ML Service | MANAGE 2.4 Performance; MEASURE 2.5 Reliability |

## Main library (68 probes)

| Probe ID | OWASP | Attack class | Severity | Targets | Prompts |
|---|---|---|---|---|---:|
| `ambient_persuasion_pasted_content` | LLM06 | ambient-persuasion,social-engineering,excessive-ag | high | http-chat,tool-using,browser-u | 1 |
| `ambient_persuasion_url_fetch` | LLM06 | ambient-persuasion,social-engineering,excessive-ag | high | browser-using,tool-using | 1 |
| `browser_dom_inject_alt_text` | LLM01 | indirect-prompt-injection,dom-injection,alt-text-i | medium | browser-using | 1 |
| `browser_dom_inject_aria_label` | LLM01 | indirect-prompt-injection,dom-injection,aria-label | medium | browser-using | 1 |
| `browser_dom_inject_css_visibility_hidden` | LLM01 | indirect-prompt-injection,dom-injection,css-hidden | medium | browser-using | 1 |
| `browser_dom_inject_data_attr` | LLM01 | indirect-prompt-injection,dom-injection,data-attr- | medium | browser-using | 1 |
| `browser_dom_inject_hidden_input` | LLM01 | indirect-prompt-injection,dom-injection,hidden-inp | medium | browser-using | 1 |
| `browser_dom_inject_html_comment` | LLM01 | indirect-prompt-injection,dom-injection,html-comme | medium | browser-using | 1 |
| `browser_dom_inject_meta_description` | LLM01 | indirect-prompt-injection,dom-injection,meta-tag-i | medium | browser-using | 1 |
| `browser_dom_inject_off_screen` | LLM01 | indirect-prompt-injection,dom-injection,off-screen | medium | browser-using | 1 |
| `browser_dom_inject_title_attr` | LLM01 | indirect-prompt-injection,dom-injection,title-attr | medium | browser-using | 1 |
| `browser_os_cmd_data_export` | LLM06 | tool-abuse,os-command-injection,data-exfiltration | critical | browser-using | 1 |
| `browser_os_cmd_dependency_update` | LLM06 | tool-abuse,os-command-injection,supply-chain | high | browser-using | 1 |
| `browser_os_cmd_install_tutorial` | LLM06 | tool-abuse,os-command-injection,remote-code-execut | critical | browser-using | 1 |
| `browser_ui_phishing_2fa_code` | LLM01 | ui-phishing,credential-extraction,mfa-bypass | high | browser-using | 1 |
| `browser_ui_phishing_api_key` | LLM01 | ui-phishing,credential-extraction,api-key-extracti | high | browser-using | 1 |
| `browser_ui_phishing_credit_card` | LLM01 | ui-phishing,financial-extraction | critical | browser-using | 1 |
| `browser_ui_phishing_government_id` | LLM01 | ui-phishing,pii-extraction,identity-extraction | critical | browser-using | 1 |
| `browser_ui_phishing_oauth_consent` | LLM01 | ui-phishing,credential-extraction,oauth-abuse | high | browser-using | 1 |
| `browser_ui_phishing_recovery_phrase` | LLM01 | ui-phishing,financial-extraction,wallet-extraction | critical | browser-using | 1 |
| `browser_ui_phishing_session_token` | LLM01 | ui-phishing,credential-extraction,session-token-ex | high | browser-using | 1 |
| `browser_ui_phishing_ssh_key` | LLM01 | ui-phishing,credential-extraction,ssh-key-extracti | high | browser-using | 1 |
| `browser_visual_inject_chart_label` | LLM01 | visual-prompt-injection,chart-label-injection | medium | browser-using | 1 |
| `browser_visual_inject_handwritten` | LLM01 | visual-prompt-injection,handwritten-injection | medium | browser-using | 1 |
| `browser_visual_inject_multilingual` | LLM01 | visual-prompt-injection,multilingual-injection | medium | browser-using | 1 |
| `browser_visual_inject_qr_code` | LLM01 | visual-prompt-injection,steganographic,qr-code-inj | medium | browser-using | 1 |
| `browser_visual_inject_screenshot_of_terminal` | LLM01 | visual-prompt-injection,terminal-screenshot-inject | medium | browser-using | 1 |
| `browser_visual_inject_stylized_logo` | LLM01 | visual-prompt-injection,logo-injection | medium | browser-using | 1 |
| `browser_visual_inject_tiny_text` | LLM01 | visual-prompt-injection,tiny-text-injection | medium | browser-using | 1 |
| `browser_visual_inject_white_on_white` | LLM01 | visual-prompt-injection,low-contrast-injection | medium | browser-using | 1 |
| `browser_dom_inject_basic` | LLM01 | indirect-prompt-injection,dom-injection | high | browser-using | 1 |
| `browser_ui_phishing_login_form` | LLM01 | ui-phishing,credential-extraction | critical | browser-using | 1 |
| `browser_visual_inject_overlay` | LLM01 | visual-prompt-injection | medium | browser-using | 1 |
| `unicode_invisible_smuggling` | LLM01 | prompt-injection,obfuscated-payload,unicode-confus | high | http-chat,tool-using,rag,brows | 4 |
| `encoded_payload_base64_link` | LLM01 | encoded-payload,prompt-injection,indirect-prompt-i | medium | http-chat,tool-using,browser-u | 1 |
| `encoded_payload_hex_codeblock` | LLM01 | encoded-payload,prompt-injection,indirect-prompt-i | medium | http-chat,tool-using | 1 |
| `install_time_postinstall_hook` | LLM03 | install-time-exec,supply-chain,unauthorized-trigge | high | tool-using | 1 |
| `install_time_preinstall_script` | LLM03 | install-time-exec,supply-chain,unauthorized-trigge | high | tool-using | 1 |
| `missing_allowlist_arbitrary_egress` | LLM06 | missing-allowlist,tool-abuse | high | tool-using,browser-using | 1 |
| `missing_budget_unbounded_loop` | LLM06 | missing-budget-limit,tool-abuse | medium | tool-using | 1 |
| `missing_confirmation_irreversible` | LLM06 | missing-confirmation-prompt,excessive-agency | high | tool-using | 1 |
| `missing_gate_cloud_api_call` | LLM06 | missing-human-gate,excessive-agency | critical | tool-using | 1 |
| `missing_gate_file_write` | LLM06 | missing-human-gate,excessive-agency | high | tool-using | 1 |
| `missing_gate_npm_install` | LLM06 | missing-human-gate,excessive-agency | high | tool-using | 1 |
| `obfuscated_code_minified_js` | LLM05 | obfuscated-code,supply-chain,prompt-injection | high | http-chat,tool-using,browser-u | 1 |
| `obfuscated_code_powershell_encoded` | LLM05 | obfuscated-code,supply-chain,os-command-injection | high | tool-using | 1 |
| `owasp_01_prompt_injection_basic` | LLM01 | prompt-injection,direct | medium | http-chat | 2 |
| `owasp_02_sensitive_info_disclosure` | LLM02 | data-exfil | high | http-chat | 3 |
| `owasp_03_supply_chain` | LLM03 | supply-chain | medium | http-chat | 2 |
| `owasp_04_poisoning` | LLM04 | poisoning | medium | http-chat | 2 |
| `owasp_05_improper_output_handling` | LLM05 | output-handling | medium | http-chat | 3 |
| `owasp_05_output_cmd_injection` | LLM05 | output-handling,command-injection | high | http-chat,tool-using | 3 |
| `owasp_05_output_eval_injection` | LLM05 | output-handling,eval-injection | high | http-chat,tool-using | 3 |
| `owasp_05_output_sql_rce` | LLM05 | output-handling,sql-injection | high | http-chat | 3 |
| `owasp_05_output_svg_xss` | LLM05 | output-handling,xss | medium | http-chat | 3 |
| `owasp_05_upload_svg_xss_render` | LLM05 | output-handling,xss,file-upload | high | http-upload | 3 |
| `owasp_06_excessive_agency` | LLM06 | tool-abuse | high | http-chat,tool-using | 3 |
| `owasp_07_system_prompt_leakage` | LLM07 | data-exfil,prompt-injection | high | http-chat | 3 |
| `owasp_08_vector_weaknesses` | LLM08 | rag-injection | medium | http-chat,rag | 2 |
| `owasp_09_misinformation` | LLM09 | hallucination | medium | http-chat | 3 |
| `owasp_10_unbounded_consumption` | LLM10 | dos,cost-amplification | medium | http-chat | 3 |
| `shadow_credentials_env_exfil` | LLM03 | shadow-credentials,credential-extraction,data-exfi | critical | tool-using | 1 |
| `shadow_credentials_oauth_webhook` | LLM03 | shadow-credentials,credential-extraction,data-exfi | critical | tool-using | 1 |
| `syscard_bon` | LLM01 | jailbreak,stochastic | medium | http-chat | 4 |
| `syscard_confused_deputy` | LLM01 | tool-abuse,indirect-prompt-injection | high | http-chat,tool-using | 2 |
| `syscard_crescendo` | LLM01 | jailbreak,multi-turn | medium | http-chat | 3 |
| `syscard_many_shot_jailbreak` | LLM01 | jailbreak,context-exploitation | medium | http-chat | 1 |
| `syscard_sleeper_agent` | LLM01 | backdoor,alignment-faking | high | http-chat | 3 |

## garak library (99 probes)

Argus bundles 99 [garak](https://github.com/NVIDIA/garak) probes wrapped as YAML adapters under `orchestrator/orchestrator/redteam/probes/garak/`. They cover:

| Family | Count | Primary OWASP category |
|---|---:|---|
| `latentinjection_*` | 15 | LLM01 Prompt Injection |
| `promptinject_*` | 6 | LLM01 Prompt Injection |
| `dan_*` | 15 | LLM01 Prompt Injection |
| `snowball_*` | 6 | LLM09 Misinformation |
| `misleading_*` | 1 | LLM09 Misinformation |
| `malwaregen_*` | 4 | LLM06 Excessive Agency |

## Notes & limitations

- **Multi-category overlap.** Each probe is mapped to its *primary* OWASP category. Many probes touch a second category in practice — e.g. `owasp_07_system_prompt_leakage` is also LLM02 (sensitive info disclosure). See each probe's `attack_class` field for the full taxonomy.
- **MITRE ATLAS technique IDs** target the ATLAS v4.0 matrix released 2024-03. AML.T0051 has sub-techniques for direct (.000) and indirect (.001) prompt injection; most Argus probes fit one or the other.
- **NIST AI RMF citations** target the **MEASURE** function of the AI RMF 1.0 published 2023-01. Probes don't cover GOVERN or MANAGE functions directly — those are organisational controls outside the scope of black-box testing.
- **EU AI Act / GDPR mapping** is not surfaced here but is captured per-finding via the `atlas/owasp/nist/eu` fields persisted by the orchestrator in `redteam_findings` (see V20 migration).
