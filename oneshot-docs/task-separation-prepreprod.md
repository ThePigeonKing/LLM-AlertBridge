# Summary: what was planned for the Project stage and for the Master’s thesis

## Overall topic
Development of a research prototype of an information security alert analysis system using a locally deployed LLM.

Target architecture:
- Wazuh as the alert source / SIEM layer
- FastAPI backend as orchestrator
- local LLM running via LM Studio on a laptop
- simple web interface for the analyst
- Yandex Cloud test environment with Linux hosts
- later extension with osquery-based context enrichment

Core principle:
- the LLM must assist the SOC analyst in initial alert triage
- the LLM must not make autonomous security decisions or perform automated response actions

---

## 1. What was planned for the Project stage

The Project stage was supposed to include **both research and a working software result**, not just theoretical analysis.

### Research tasks
- analyze applicability of LLMs to SOC alert triage
- compare several locally runnable LLM models and select one as the main model
- compare SIEM/XDR options and justify choosing Wazuh
- compare host context enrichment approaches and justify osquery as the future direction of system development
- justify the overall architecture of the prototype

### Practical tasks
- deploy a cloud test environment in Yandex Cloud
- deploy Wazuh and prepare Linux hosts that generate alerts
- implement a backend service that:
  - receives alerts from Wazuh
  - normalizes alert data
  - sends the alert context to the local LLM
  - receives a structured response from the model
  - stores the result
- implement a simple web interface that:
  - shows the alert
  - shows the LLM analysis result
  - allows reviewing processed alerts

### Expected software result of the Project stage
A working pipeline like:

**Wazuh → backend → local LLM → web interface**

### Scope limitations of the Project stage
At the Project stage it was considered acceptable:
- **not** to implement full osquery integration yet
- **not** to implement analyst-to-LLM dialogue yet
- **not** to implement similar incident search yet
- **not** to implement feedback loop yet
- **not** to run full scientific experiments yet

So the Project stage should already produce a **working baseline prototype**, but still remain limited in functionality.

---

## 2. What was planned for the Master’s thesis stage

The Master’s thesis was planned as an **extension of the already working project-stage prototype** into a fuller research system.

### Functional extensions planned for the thesis
- implement full host context enrichment using osquery
- add interactive analyst-to-LLM dialogue
- improve prompts and structured output
- add search for similar incidents / historical cases
- add analyst feedback collection
- improve architecture and data persistence where needed

### Research tasks planned for the thesis
- run original experiments on the prepared test environment
- compare system modes such as:
  - without LLM
  - with LLM but without advanced context enrichment
  - with LLM and enriched host context
- compare selected LLM models on real scenarios
- evaluate usefulness of the system for alert triage
- describe limitations and formulate scientific conclusions

### Expected thesis result
The thesis should produce:
- a more complete research-grade prototype
- additional analytical capabilities
- experimental evaluation based on the author’s own environment and test scenarios
- conclusions on effectiveness, limitations, and possible future development

---

## 3. Key boundary between Project and Thesis

### Project
- subject-area research
- technology selection
- architecture justification
- deployment of the test environment
- implementation of a **working baseline prototype**
- one-shot LLM analysis displayed in a web UI

### Thesis
- extension of that prototype
- richer context collection
- interactive dialogue
- similar incident search
- analyst feedback
- original experiments and evaluation

---

## 4. Infrastructure assumption
- the cloud environment contains:
  - `core-compute`
  - `target-1-compute`
  - `target-2-compute`
  - `attacker-compute`
  - `openvpn-access-server`
- the LLM runs locally on the laptop through LM Studio
- connectivity between the laptop and cloud environment is provided through VPN / tunneling
- internal IP addresses are used as the stable addressing scheme for the environment

---

## 5. What should be checked now
The agent should compare:
1. what has already been implemented from the Project-stage baseline prototype
2. what is still missing to fully complete the Project stage
3. what features are intentionally postponed to the Master’s thesis stage
4. what additional work is required to turn the project prototype into a full Master’s thesis-level research system