## Technical Detail Template

*Target Audience: Sysadmins, Developers, and Security Engineers.*

### I. Attack Path Narrative (Red Team Specific)

* **Timeline of Events:** A chronological log of actions taken.
* **Visual Attack Path:** A diagram showing the progression from initial access to the objective (e.g., Perimeter -> Workstation -> Domain Admin).

### II. Detailed Findings

For each vulnerability, include:

* **ID & Title:** (e.g., `TECH-001: Insecure Direct Object Reference`)
* **Severity:** CVSS v3.1/4.0 Score.
* **Description:** A clear explanation of the technical flaw.
* **Evidence & Reproduction:**
* Step-by-step instructions to recreate the finding.
* Screenshots with clear annotations.
* Code snippets or HTTP request/response logs.


* **Remediation:** Specific, actionable technical steps to fix the issue.

### III. Cleanup & Infrastructure

* A list of all tools, shells, or accounts created during the test that need to be removed to return the environment to its original state.
