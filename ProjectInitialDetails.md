# Project Initial Details T1
**Done by Team 1:** Xyrus, Ritu, Nandhini, Riddhi, Sam, Zhi Xian

## Repository Link
**GitHub URL:** https://github.com/2603724-ZHXIAN/26INF1103-P4-G1.git

## Real-World Problem
Traditional cybersecurity tools output raw technical telemetry (hash reports, antivirus flags) that non-technical users can't interpret. Hence, when they encounter a suspicious link or file, they often don't know what to do next and miss the chance to learn how and why it was dangerous.

Our application plans to solve this by combining VirusTotal's technical telemetry with Gemini AI's semantic analysis to turn unstructured inputs into an automated pipeline that evaluates risk and gives step-by-step mitigation guidance. Additionally, it also functions as an educational tool, breaking down the different threat types (smishing, spear phishing, and Trojan malware) into plain language for users to learn and be able to spot future attacks independently.

## Target Users
* **Everyday Non-Technical Users:** Individuals in need of a quick, educational evaluation of suspicious emails, text messages, or URLs.
* **Small & Medium Enterprise (SME) Employees:** Staff members who require fast verification of questionable vendor invoices or login links. This allows them to simultaneously receive micro-training on corporate phishing awareness.
* **Tier-1 Security Helpdesk / SOC Handlers:** Security teams seeking an automated tool to handle initial threat triage and log repeated scam patterns. This also generates educational summaries for the staff.

## User Inputs
The application collects structured inputs via a Command-Line Interface (CLI) managed strictly by the `io_manager`. Users can provide four distinct types of data:
* **Unstructured Text / Email Body:** Raw text messages, suspicious emails, or SMS strings entered directly into the terminal.
* **URLs & Web Domains:** Web addresses extracted from suspicious communications.
* **File Paths & Screenshots:** Local file paths pointing to suspected email attachments (`.pdf`, `.exe`, `.xlsx`) or image screenshots of scam messages.
* **Database Query Criteria and Common Threat Summaries:** Numerical menu choices and search criteria retrieve past assessments and summaries of the most common threat types in stored records through the `data_manager`.

## Utilization of AI
The system utilizes the Gemini API within the `ai_manager` as the primary semantic processor to interpret available findings and provide plain-language explanations and guidance.
* **Contextual Threat Education:** Beyond simply flagging a threat, Gemini is prompted to analyze the attack vector and generate brief educational breakdowns. For example, when a text message is analyzed, the AI explains the concept of "smishing" (SMS phishing) and how attackers use artificial urgency. Where VirusTotal findings support a malware classification in URL and file, Gemini identifies the reported category (e.g., ransomware, keylogger, or trojan) and explains its typical behaviour to our users.
* **Prompt Engineering & Context Aggregation:** The `ai_manager` dynamically constructs a system prompt that combines the raw user input, VirusTotal technical metrics, and historical logs.
* **Web Search Grounding:** For emerging threats, Gemini utilizes live search grounding to cross-reference real-world scam trends and pull up-to-date educational examples of how similar scams have operated recently.
* **User Guidance:** Once VirusTotal identifies a threat, Gemini will suggest tailored mitigation and containment steps based on the tactics used by the malware/threat. These are recommendations only; the application does not automatically perform containment actions.

## Business Rules 
The `logic_manager` layer accepts Gemini's validated JSON output, VirusTotal metrics, and historical database records to execute deterministic business rules in Python. The AI is restricted from making final system decisions; all routing and alerts are enforced by multi-condition Python logic.

## Security Policies
The business rules define the practical security policies our application follows to keep users safe. Under these rules, if an input is flagged as potentially malicious, the system urgently advises the user to isolate their device and explains how the specific attack works. If a message has no malware detections in the available report, but uses high-pressure tactics to manipulate the user, the policy treats it as a severe phishing threat. The rules also ensure that repeated submissions matching previously flagged threat records are raised within the defined risk levels: Low, Moderate, High and Critical. Slightly suspicious inputs trigger a caution warning, and inputs with no threat indicators are reported as having no detected threat indicators, without guaranteeing safety.

Additional thresholds and escalation rules will be refined during implementation and testing. 

## Decision-Making Rules & Logic Matrix 
To actually enforce these policies, the decision-making logic uses Python to evaluate the raw data against hard numerical thresholds. The code looks at the exact number of VirusTotal hits, the AI's percentage score for scam probability, and the count of previous database matches. For example, the code only triggers a critical-risk warning with recommended protective actions if VirusTotal flags the file 5 or more times and the AI is over 80% confident it's a scam. By structuring the code this way, the system guarantees that the Python script always makes the final, predictable security call rather than letting the AI decide on its own.

## Validations and Exceptions
* **Schema Validation:** The `ai_manager` verifies that all expected JSON keys exist (including the `educational_insight` string) and checks their data types and permitted ranges before handing the data over to the `logic_manager`. 
* **API Failure Resiliency:** If an API connection fails or a service becomes unavailable, `try/except` blocks catch the relevant exceptions and log the issue. The application displays a clear message advising the user to try again later and marks the assessment as incomplete. Available historical records may provide limited guidance but are clearly identified as previous findings, not a fresh assessment.
* **Modular Layer Fault Tolerance:** The system architecture enforces strict separation of concerns and includes error handling so that failures in individual layers, such as the AI Manager or Data Manager, are handled where possible without crashing the application. The remaining functional layers use appropriate default fallbacks to keep the CLI available where possible, while clearly informing users of unavailable features or incomplete operations.