# Technical Specification for Developing an Information Security Alert Analysis System Using a Local LLM
## Context: Project + Master’s Thesis

---

## 1. Purpose of This Document

This document is intended for a coding-oriented LLM that will assist with software design and implementation.

Based on this document, the model must:

1. correctly understand the problem domain and development goals;
2. distinguish between the two stages of work:
   - **Stage 1 — Project**
   - **Stage 2 — Master’s Thesis**
3. first create a realistic implementation plan;
4. then assist with development step by step:
   - first for the **Project** stage;
   - then for the **Master’s Thesis** stage.

Important:  
there is **no separate MVP stage**. There are only two stages:
- **Project**
- **Master’s Thesis**

---

## 2. General Idea of the System

The goal is to develop a research prototype of a software module for analyzing information security alerts using a locally deployed large language model (LLM).

The system must integrate into a SOC/SIEM environment and assist an information security analyst in performing initial alert analysis.

### Core workflow
1. The SIEM system detects an event and generates an alert.
2. The developed module receives the alert.
3. The module normalizes the alert data.
4. The module sends the prepared context to a locally deployed LLM.
5. The LLM returns a structured analytical output.
6. The result is shown to the analyst through a web interface.
7. At the Master’s Thesis stage, the system is extended with additional contextual enrichment, interactive dialogue, and research-oriented capabilities.

### Key principle
The LLM **does not make autonomous decisions** and **does not perform automated response actions**.  
It is used **as an intelligent assistant for the analyst**, while the final decision always remains with the human.

---

## 3. Why This System Is Being Developed

Problem statement:
- SOC/SIEM systems generate a large number of alerts;
- a significant portion of alerts requires manual triage;
- the analyst spends time collecting context and performing initial interpretation;
- this increases workload and slows down response time.

Development goal:
- reduce routine workload for the analyst;
- accelerate initial alert triage;
- provide a more structured and convenient view of an incident;
- achieve this without sending sensitive data to external cloud-based LLM services.

---

## 4. Baseline Technology Context

### Selected or expected technologies
- **SIEM / alert source:** Wazuh
- **Local LLM:** runs locally on a MacBook Pro via **LM Studio**
- **Backend / orchestration:** Python + FastAPI
- **Web interface:** simple web UI, without unnecessary complexity
- **Test environment:** Yandex Cloud
- **Linux hosts:** virtual machines in the test environment
- **Context enrichment at the Thesis stage:** osquery
- **Storage for service data:** SQLite or PostgreSQL at early stages, PostgreSQL preferred later
- **Queues / async processing:** if needed at the Thesis stage, e.g. Redis/Celery

### Infrastructure constraints
- the LLM runs **locally**, not in the cloud;
- the cloud is needed for:
  - Wazuh,
  - test Linux hosts,
  - the developed backend service,
  - data storage and scenario testing
- **open-source** solutions are preferred

---

## 5. Architectural Concept

### System components
1. **Alert source**
   - Wazuh
   - generates and stores alerts

2. **Backend / Orchestrator**
   - receives alerts from Wazuh
   - normalizes data
   - prepares requests for the LLM
   - receives model responses
   - stores analysis results
   - exposes data to the web interface

3. **Local LLM**
   - runs via LM Studio
   - is accessed through API
   - generates structured analytical output

4. **Web interface**
   - displays a list of alerts or a selected alert
   - shows the analysis result
   - at the Thesis stage, allows interactive dialogue with the model

5. **Context enrichment module**
   - may be minimal or absent as a fully implemented integration during the Project stage
   - must be implemented with osquery during the Thesis stage

6. **Data storage**
   - stores:
     - received alerts,
     - analysis results,
     - processing history,
     - at the Thesis stage: dialogues, feedback, and similar cases

---

## 6. Strict Separation Into Two Stages

# STAGE 1 — PROJECT

## 6.1. Goal of the Project Stage
Build a working prototype of an IS alert analysis system using a local LLM and a web interface, while also completing the research-based justification of the selected architecture and core technologies.

## 6.2. What must be done during the Project stage

### Research part
1. Study the applicability of LLMs to SOC tasks.
2. Compare several locally runnable LLMs and choose the primary model.
3. Compare SIEM/XDR solutions and justify the selection of Wazuh.
4. Compare context enrichment approaches and justify osquery as the direction for future system development.

### Practical part
1. Prepare the test environment:
   - deploy Wazuh;
   - prepare Linux hosts;
   - ensure generation and delivery of test alerts.

2. Implement a backend service that:
   - receives alerts from Wazuh;
   - normalizes them;
   - sends them to the LLM;
   - receives the model output;
   - stores the result;
   - exposes the result via API.

3. Implement a simple web interface that:
   - shows an alert;
   - shows the LLM analysis result;
   - allows viewing previously processed alerts.

4. Implement a baseline LLM output format, for example:
   - short event summary;
   - preliminary hypothesis;
   - possible causes;
   - indicators that require attention;
   - recommended manual verification steps.

## 6.3. What is NOT mandatory during the Project stage
1. Full osquery integration.
2. A full analyst-to-LLM dialogue mode.
3. Similar incident search.
4. Analyst feedback mechanism.
5. Deep experimental evaluation with custom metrics.
6. A complex production-grade microservice architecture.

## 6.4. Minimum functional result of the Project stage
By the end of the Project stage, there must be a working system where:
- Wazuh acts as the alert source;
- a backend receives alerts;
- a local LLM is called through LM Studio;
- analysis results are stored;
- a web interface exists;
- an analyst can open a page and see:
  - the alert itself;
  - the LLM output for that alert.

## 6.5. Completion criterion for the Project stage
The stage is complete if the following working scenario can be demonstrated:

**Wazuh → alert → backend → LLM → web UI → displayed analysis result**

---

# STAGE 2 — MASTER’S THESIS

## 6.6. Goal of the Thesis Stage
Extend the project prototype into a more complete research system and conduct an experimental evaluation of its effectiveness.

## 6.7. What must be done during the Thesis stage

### Functional system development
1. Implement context enrichment via osquery.
2. Add interactive analyst-to-LLM dialogue.
3. Improve prompt structure and response format.
4. Add similar incident search.
5. Add a mechanism for storing and using analyst feedback.
6. Improve the interface and the internal service architecture.

### Research part of the Thesis
1. Conduct original experiments on the test environment.
2. Compare the system in several modes:
   - without LLM;
   - with LLM but without extended context;
   - with LLM and context enrichment.
3. Compare multiple LLMs on the author’s own scenarios.
4. Measure the usefulness of the system with selected metrics.
5. Describe limitations of the approach and formulate conclusions.

## 6.8. What should distinguish the Thesis stage from the Project stage
At the Thesis stage, the system must evolve beyond a baseline prototype and become a research-grade service that:
- provides richer analysis;
- uses additional context;
- allows analyst interaction with the model;
- supports extended scenarios;
- is evaluated experimentally on the prepared test environment.

## 6.9. Completion criterion for the Thesis stage
The stage is complete if:
- the key extensions are implemented;
- original experiments are conducted;
- results are obtained and described;
- conclusions about effectiveness and limitations are formulated.

---

## 7. Functional Requirements

# 7.1. Requirements for the Project stage

## Backend
It must:
- receive alert data;
- validate and normalize input data;
- create a unified internal alert format;
- call the local LLM through the LM Studio API;
- receive the model output;
- store the analysis result;
- provide data to the frontend.

## LLM integration
It must:
- work with one selected model;
- use a fixed system prompt;
- return a structured result;
- preferably use JSON or a JSON-like structured format.

## Web interface
It must:
- be simple and understandable;
- allow viewing alerts;
- allow opening a page for a specific alert;
- display the LLM response;
- avoid unnecessary frontend complexity.

## Data storage
It must store:
- alert identifier;
- raw alert data;
- normalized alert data;
- LLM response;
- processing timestamp;
- processing status.

# 7.2. Requirements for the Thesis stage

## Context enrichment
It must:
- collect host data via osquery from Linux systems;
- include these results in the overall context bundle;
- improve analysis quality.

## Analyst dialogue
It must:
- allow follow-up questions;
- use the current alert and its context;
- store dialogue history.

## Similarity search
It must:
- support searching for similar incidents;
- use historical alerts and/or cases;
- return similar events and a similarity score.

## Feedback loop
It must:
- allow the analyst to rate the usefulness of the answer;
- record the final classification of the event;
- prepare the basis for future system improvement.

## Experimental evaluation
It must support:
- comparison of different system modes;
- collection of data for analysis;
- preparation of a basis for scientific conclusions.

---

## 8. Non-Functional Requirements

### For both stages
1. The code must be clear and modular.
2. The architecture must support further extension without full redesign.
3. Unnecessary complexity must be avoided at early stages.
4. There must be no automated incident response.
5. All functions must support the analyst rather than replace the analyst.
6. The local LLM must be used through a stable and reproducible interface.
7. The codebase must be suitable for demonstration and further development.

---

## 9. Suggested Repository Structure

```
project-root/
  README.md
  docs/
    architecture.md
    project_scope.md
    thesis_scope.md
  backend/
    app/
      api/
      services/
      models/
      schemas/
      db/
      integrations/
        wazuh/
        lm_studio/
        osquery/           # may be empty or a stub during the Project stage
    tests/
  frontend/
    templates/            # if using Jinja2
    static/
    src/                  # if using a lightweight frontend framework
  scripts/
  data/
  prompts/
    system_prompt.txt
    analysis_prompt.txt
  experiments/            # especially important for the Thesis stage
```

---

## 10. Suggested Internal Analysis Output Format

During the Project stage, it is recommended to use a structured result similar to the following:

```
{
  "summary": "Short description of the event",
  "hypothesis": "Preliminary hypothesis about the nature of the event",
  "possible_causes": [
    "Cause 1",
    "Cause 2"
  ],
  "key_indicators": [
    "Indicator 1",
    "Indicator 2"
  ],
  "recommended_checks": [
    "Action 1",
    "Action 2"
  ],
  "confidence_note": "Short note about confidence level and the need for manual verification"
}
```

At the Thesis stage, the format may be extended with:
- context sources;
- impact of context on the conclusion;
- similar incidents;
- dialogue history;
- analyst comments;
- usefulness rating.

---

## 11. What the Model Must Do After Reading This Document

After reading this file, the model must act in the following order:

### Step 1. Analysis
- briefly restate the architecture and goals;
- identify the requirements of the **Project** stage;
- separately identify the requirements of the **Thesis** stage;
- explicitly note that development must begin with the **Project** stage.

### Step 2. Planning
- create a detailed work plan;
- split development into stages;
- identify dependencies between tasks;
- separate mandatory Project tasks from future Thesis tasks.

### Step 3. Implementation of the Project stage
Help develop, in order:
1. repository structure;
2. backend;
3. LM Studio integration;
4. Wazuh integration;
5. baseline data storage;
6. simple web interface;
7. demonstration workflow.

### Step 4. Preparation for the Thesis transition
After the Project stage is complete:
- identify which modules are already ready;
- determine which interfaces must be extended;
- plan how to add osquery, dialogue, similarity search, feedback, and experiments.

### Step 5. Implementation of the Thesis stage
After the Project stage is completed, move on to:
- context enrichment;
- dialogue support;
- experimental modules;
- architectural improvements;
- implementation of research-significant features.

---

## 12. Development Priorities

# Priority 1 — mandatory for the Project stage
- backend architecture;
- Wazuh integration;
- LM Studio integration;
- receiving and displaying analysis;
- simple web UI;
- storage of analysis results.

# Priority 2 — mandatory for the Thesis stage
- osquery enrichment;
- analyst-to-LLM dialogue;
- similarity search;
- feedback loop;
- experiments and metrics.

# Priority 3 — optional improvements
- asynchronous processing;
- task queue;
- advanced frontend;
- authentication;
- extended reports;
- export of results.

---

## 13. What Must Not Be Done Incorrectly

1. Do not mix the **Project** and **Thesis** stages as if everything must be implemented at once.
2. Do not forget that the **Project** stage must also include a **real working software result**, not only analysis.
3. Do not design the system as a fully autonomous analyst.
4. Do not build an architecture where cloud infrastructure is required to run the model itself.
5. Do not make the implementation unnecessarily complex when a simple demonstrable solution is enough for the Project stage.
6. Do not invent experimental results; experiments belong to the Thesis stage and must be based on real data from the test environment.

---

## 14. Short Final Interpretation

### What the "Project" stage is
It is the working software foundation of the system:
- code already exists;
- integrations already exist;
- a web interface already exists;
- the local LLM already analyzes alerts.

### What the "Master’s Thesis" stage is
It is the extension of the project foundation into a research-oriented service:
- more context;
- more interactivity;
- more analytical functions;
- original experiments and scientific conclusions.

---
