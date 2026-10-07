"""
Laya Security Playbook: Production Patterns for Security Engineers
Demonstrates 4 high-impact security use cases using convaiinnovations/laya-typed-decisions:
1. AI Agent Tool-Call Firewall (Autonomous Agent Security)
2. Automated Tier 1 SOC Alert Triage (SecOps)
3. Inbound Phishing & BEC Detection (Email Security)
4. Outbound DLP & Secret Leakage Gate (Data Protection)
"""

import json
import time
import laya

class SecurityPlaybook:
    def __init__(self):
        print("Initializing Laya Security Engine (convaiinnovations/laya-typed-decisions)...")
        self.agent = laya.load("convaiinnovations/laya-typed-decisions")
        print("Engine ready.\n")

    def screen_agent_tool_call(self, tool_name: str, args: dict):
        """Use Case 1: Intercept agent tool calls before execution."""
        state = f"Tool: {tool_name}\nArguments: {json.dumps(args, indent=2)}"
        
        policy = {
            "is_destructive": {
                "type": "noul",
                "instructions": "Does this tool call execute destructive commands, delete files, alter system states, or tamper with security settings?",
            },
            "blast_radius": {
                "type": "score",
                "instructions": "Assess the blast radius of this action.",
                "criteria": ["read_only", "isolated_user_scope", "tenant_wide_mutation", "host_system_destruction"],
            },
            "intent": {
                "type": "choice",
                "instructions": "Categorize the nature of this operation.",
                "criteria": {
                    "recon": "Inspecting files, system state, or reading directories",
                    "destructive_mutation": "Deleting, wiping, or overwriting critical files or tables",
                    "privilege_escalation": "Attempting sudo, altering permissions, or modifying IAM roles",
                    "benign_write": "Safe local writing in designated scratch directory",
                },
            },
        }
        
        t0 = time.perf_counter()
        decision = self.agent.predict(state, policy)
        latency = (time.perf_counter() - t0) * 1000
        
        ans = decision["answers"]
        is_destr = ans["is_destructive"]["noul"]
        radius = ans["blast_radius"]["score"]
        intent = ans["intent"]["choice"]
        
        action = "BLOCKED" if (is_destr > 0.70 or radius >= 2.0 or intent == "destructive_mutation") else "ALLOWED"
        return {
            "action": action,
            "is_destructive_prob": round(is_destr, 4),
            "blast_radius_level": round(radius, 2),
            "intent": intent,
            "latency_ms": round(latency, 1),
        }

    def triage_soc_alert(self, alert_data: dict):
        """Use Case 2: Ingest SIEM/EDR raw alert and automate Tier 1 triage."""
        state = json.dumps(alert_data, indent=2)
        
        policy = {
            "is_false_positive": {
                "type": "noul",
                "instructions": "Is this event likely routine benign administrative behavior rather than an active security incident?",
            },
            "triage_priority": {
                "type": "score",
                "instructions": "Determine the priority level for the incident response queue.",
                "criteria": ["P4_informational", "P3_low", "P2_medium", "P1_critical_incident"],
            },
            "assigned_squad": {
                "type": "choice",
                "instructions": "Select the appropriate security squad to route this ticket.",
                "criteria": {
                    "endpoint_security": "Host-level process injection, suspicious binaries, or shell execution",
                    "cloud_iam": "Access key exposure, unexpected IAM policy attachment, or root console login",
                    "network_perimeter": "Anomalous outbound egress, port scanning, or DDoS patterns",
                    "compliance_hygiene": "Unencrypted storage, policy drift, or missing audit logs",
                },
            },
        }
        
        t0 = time.perf_counter()
        decision = self.agent.predict(state, policy)
        latency = (time.perf_counter() - t0) * 1000
        
        ans = decision["answers"]
        return {
            "fp_prob": round(ans["is_false_positive"]["noul"], 4),
            "priority_score": round(ans["triage_priority"]["score"], 2),
            "squad": ans["assigned_squad"]["choice"],
            "latency_ms": round(latency, 1),
        }

    def inspect_dlp(self, text_payload: str):
        """Use Case 3: Outbound Data Loss Prevention & Secret Exposure Gate."""
        policy = {
            "contains_secrets_or_pii": {
                "type": "noul",
                "instructions": "Does this payload contain sensitive API keys, private credentials, database secrets, or personal identifiable info?",
            },
            "data_classification": {
                "type": "choice",
                "instructions": "Classify the sensitivity of the data present.",
                "criteria": {
                    "credential_leak": "API keys, bearer tokens, passwords, or RSA private keys",
                    "customer_pii": "Social security numbers, personal identity, or payment records",
                    "internal_source_code": "Proprietary business logic or confidential architecture designs",
                    "public_clean": "Safe public information or boilerplate code",
                },
            },
            "risk_tier": {
                "type": "score",
                "instructions": "Assign the confidentiality risk tier.",
                "criteria": ["public", "internal", "confidential", "restricted_secret"],
            },
        }
        
        t0 = time.perf_counter()
        decision = self.agent.predict(text_payload, policy)
        latency = (time.perf_counter() - t0) * 1000
        
        ans = decision["answers"]
        p_leak = ans["contains_secrets_or_pii"]["noul"]
        classification = ans["data_classification"]["choice"]
        tier = ans["risk_tier"]["score"]
        
        verdict = "QUARANTINE" if (p_leak > 0.75 or tier >= 2.0 or classification != "public_clean") else "PASS"
        return {
            "verdict": verdict,
            "secret_pii_prob": round(p_leak, 4),
            "classification": classification,
            "risk_tier": round(tier, 2),
            "latency_ms": round(latency, 1),
        }

    def inspect_email_phishing(self, email_body: str, sender: str, subject: str):
        """Use Case 4: Synchronous Phishing & Business Email Compromise (BEC) Screener."""
        state = f"From: {sender}\nSubject: {subject}\nBody:\n{email_body}"
        
        policy = {
            "is_phishing_or_bec": {
                "type": "noul",
                "instructions": "Does this email attempt phishing, credential harvesting, wire fraud, or coercive social engineering?",
            },
            "threat_modality": {
                "type": "choice",
                "instructions": "Classify the specific attack modality.",
                "criteria": {
                    "wire_fraud_bec": "Requests urgent wire transfer or changes in vendor banking details",
                    "credential_harvesting": "Prompts recipient to click login links or enter credentials",
                    "malicious_attachment": "Urges opening invoice attachments or running macros",
                    "legitimate_email": "Normal internal or external business communication",
                },
            },
            "urgency_coercion": {
                "type": "score",
                "instructions": "Measure the level of artificial urgency or emotional pressure.",
                "criteria": ["calm_normal", "mild_priority", "high_urgency", "extortion_or_threat"],
            },
        }
        
        t0 = time.perf_counter()
        decision = self.agent.predict(state, policy)
        latency = (time.perf_counter() - t0) * 1000
        
        ans = decision["answers"]
        p_phish = ans["is_phishing_or_bec"]["noul"]
        modality = ans["threat_modality"]["choice"]
        urgency = ans["urgency_coercion"]["score"]
        
        disposition = "BLOCK_AND_QUARANTINE" if (p_phish > 0.70 or urgency >= 2.0 or modality != "legitimate_email") else "INBOX_DELIVERY"
        return {
            "disposition": disposition,
            "phish_prob": round(p_phish, 4),
            "modality": modality,
            "urgency_score": round(urgency, 2),
            "latency_ms": round(latency, 1),
        }


def main():
    engine = SecurityPlaybook()

    # --- Scenario 1: AI Agent Tool-Call Firewall ---
    print("=" * 70)
    print("SCENARIO 1: AI AGENT TOOL-CALL FIREWALL")
    print("=" * 70)
    
    agent_call_1 = {
        "tool": "execute_bash",
        "args": {"command": "rm -rf /var/log/* && shred -u /etc/shadow"}
    }
    res1 = engine.screen_agent_tool_call(agent_call_1["tool"], agent_call_1["args"])
    print(f"Tool: {agent_call_1['tool']}({agent_call_1['args']['command']})")
    print(f"Decision: [{res1['action']}] | Destructive P: {res1['is_destructive_prob']} | Intent: {res1['intent']} | Latency: {res1['latency_ms']}ms\n")

    agent_call_2 = {
        "tool": "read_file",
        "args": {"path": "/app/config/settings.json"}
    }
    res2 = engine.screen_agent_tool_call(agent_call_2["tool"], agent_call_2["args"])
    print(f"Tool: {agent_call_2['tool']}({agent_call_2['args']['path']})")
    print(f"Decision: [{res2['action']}] | Destructive P: {res2['is_destructive_prob']} | Intent: {res2['intent']} | Latency: {res2['latency_ms']}ms\n")

    # --- Scenario 2: Tier 1 SOC Alert Triage ---
    print("=" * 70)
    print("SCENARIO 2: TIER 1 SOC ALERT TRIAGE & ROUTING")
    print("=" * 70)
    
    soc_alert = {
        "event_id": "SEC-89211",
        "source": "AWS GuardDuty",
        "title": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "principal": "arn:aws:iam::123456789012:role/ProductionDatabaseNode",
        "remote_ip": "185.220.101.5",
        "details": "Temporary credentials issued to an EC2 instance were used from an external IP address associated with a Tor exit node."
    }
    res3 = engine.triage_soc_alert(soc_alert)
    print(f"Alert: {soc_alert['title']}")
    print(f"Triage: Priority Score: {res3['priority_score']} | Route To: {res3['squad']} | FP Prob: {res3['fp_prob']} | Latency: {res3['latency_ms']}ms\n")

    # --- Scenario 3: Outbound DLP & Secret Detection ---
    print("=" * 70)
    print("SCENARIO 3: DATA LOSS PREVENTION (DLP) GATEWAY")
    print("=" * 70)
    
    leaked_payload = "export GITHUB_TOKEN='ghp_984712093841029384012830491823091823' \ncurl -H \"Authorization: Bearer $GITHUB_TOKEN\" https://api.github.com"
    res4 = engine.inspect_dlp(leaked_payload)
    print("Payload: [Contains GitHub API Token export]")
    print(f"Verdict: [{res4['verdict']}] | Class: {res4['classification']} | Risk Tier: {res4['risk_tier']} | Latency: {res4['latency_ms']}ms\n")

    # --- Scenario 4: Phishing / BEC Screener ---
    print("=" * 70)
    print("SCENARIO 4: EMAIL PHISHING & BEC SCREENER")
    print("=" * 70)
    
    bec_email = """
    Hi finance team,
    I am currently in an urgent offsite meeting. We need to update our wire instructions for vendor Acorn Ltd immediately before end of business today to avoid penalties. Please remit $48,200 to the updated account details below ASAP.
    """
    res5 = engine.inspect_email_phishing(bec_email, sender="ceo-executive-internal@mail-secure-portal.com", subject="URGENT: Updated Wire Instructions")
    print("Email: Urgent Wire Update from spoofed CEO domain")
    print(f"Disposition: [{res5['disposition']}] | Modality: {res5['modality']} | Urgency: {res5['urgency_score']} | Latency: {res5['latency_ms']}ms\n")

if __name__ == "__main__":
    main()
