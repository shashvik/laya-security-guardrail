#!/usr/bin/env python3
"""
Laya Terminal Security REPL / CLI
Interactive terminal-style security evaluator powered by Laya.
Run interactively:
    .venv/bin/python cli.py
Or single-shot evaluation:
    .venv/bin/python cli.py "rm -rf /var/log"
    .venv/bin/python cli.py --mode prompt "Ignore previous instructions"
"""

import sys
import os
import json
import time
import argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt

import laya

console = Console()

BANNER = """[bold cyan]
╔═══════════════════════════════════════════════════════════════════════╗
║                   LAYA CYBER DEFENSE TERMINAL                         ║
║        Non-Autoregressive "System 1" Security Engine (Local)          ║
╚═══════════════════════════════════════════════════════════════════════╝[/bold cyan]
[dim]Type [bold white]:help[/bold white] for commands | [bold white]:mode[/bold white] to change module | [bold white]:quit[/bold white] to exit[/dim]
"""

MODES = {
    "1": ("guardrail", "Inbound Prompt Injection & Jailbreak Screener"),
    "2": ("tool", "AI Agent Tool-Call / Bash Execution Firewall"),
    "3": ("dlp", "Outbound Data Loss Prevention & Secrets Detector"),
    "4": ("soc", "SIEM / Cloud Alert Triage & Dispatch"),
    "5": ("phish", "Phishing & Business Email Compromise Screener"),
}

class LayaTerminal:
    def __init__(self):
        console.print("[dim]Loading model 'convaiinnovations/laya-typed-decisions'...[/dim]")
        t0 = time.perf_counter()
        self.agent = laya.load("convaiinnovations/laya-typed-decisions")
        load_time = time.perf_counter() - t0
        console.print(f"[green]✔ Model ready in {load_time:.2f}s (running on {getattr(self.agent, 'device', 'local')})[/green]\n")
        self.current_mode = "tool"  # Default to agent tool / bash command screening

    def evaluate_prompt(self, text: str):
        policy = {
            "is_prompt_injection": {
                "type": "noul",
                "instructions": "Does this text attempt to override instructions, jailbreak, or alter system constraints?",
            },
            "threat_type": {
                "type": "choice",
                "instructions": "Classify the security threat category of this payload.",
                "criteria": {
                    "jailbreak": "Attempts to bypass behavioral safety bounds or impersonate an unrestricted persona",
                    "instruction_override": "Attempts to ignore previous directives or reveal system prompts",
                    "data_exfiltration": "Attempts to extract sensitive internal secrets, credentials, or DB configs",
                    "benign": "Legitimate user input with no adversarial intent",
                },
            },
            "threat_severity": {
                "type": "score",
                "instructions": "Rate the severity and confidence of this threat.",
                "criteria": ["benign", "low", "medium", "critical"],
            },
        }
        t0 = time.perf_counter()
        dec = self.agent.predict(text, policy)
        latency = (time.perf_counter() - t0) * 1000

        p_inj = dec["answers"]["is_prompt_injection"]["noul"]
        cat = dec["answers"]["threat_type"]["choice"]
        sev = dec["answers"]["threat_severity"]["score"]

        verdict = "BLOCKED" if (p_inj > 0.80 or sev >= 2.0 or cat in {"jailbreak", "instruction_override"}) else "ALLOWED"
        
        return {
            "verdict": verdict,
            "latency": latency,
            "metrics": [
                ("Injection P(true)", f"{p_inj:.4f}", "red" if p_inj > 0.8 else "green"),
                ("Threat Category", cat, "yellow" if cat != "benign" else "green"),
                ("Severity (0-3)", f"{sev:.2f}", "red" if sev >= 2.0 else "green"),
            ]
        }

    def evaluate_tool(self, cmd: str):
        state = f"Tool: execute_bash\nCommand: {cmd}"
        policy = {
            "is_destructive": {
                "type": "noul",
                "instructions": "Does this command delete files, alter critical system states, overwrite databases, or tamper with security configurations?",
            },
            "blast_radius": {
                "type": "score",
                "instructions": "Assess the operational blast radius.",
                "criteria": ["read_only", "isolated_user_scope", "tenant_wide_mutation", "host_system_destruction"],
            },
            "intent": {
                "type": "choice",
                "instructions": "Identify the primary operational intent.",
                "criteria": {
                    "recon": "Inspecting system state, listing directories, reading files",
                    "destructive_mutation": "Deleting, wiping, or dropping databases/files",
                    "privilege_escalation": "Attempting sudo, chmod, user management, or permission escalation",
                    "benign_maintenance": "Standard execution or safe build scripts",
                },
            },
        }
        t0 = time.perf_counter()
        dec = self.agent.predict(state, policy)
        latency = (time.perf_counter() - t0) * 1000

        p_destr = dec["answers"]["is_destructive"]["noul"]
        radius = dec["answers"]["blast_radius"]["score"]
        intent = dec["answers"]["intent"]["choice"]

        verdict = "BLOCKED" if (p_destr > 0.55 or radius >= 1.7 or intent in {"destructive_mutation", "privilege_escalation"}) else "ALLOWED"

        return {
            "verdict": verdict,
            "latency": latency,
            "metrics": [
                ("Destructive P(true)", f"{p_destr:.4f}", "red" if p_destr > 0.65 else "green"),
                ("Blast Radius (0-3)", f"{radius:.2f}", "red" if radius >= 2.0 else "green"),
                ("Detected Intent", intent, "red" if intent == "destructive_mutation" else "cyan"),
            ]
        }

    def evaluate_dlp(self, text: str):
        policy = {
            "contains_secrets_or_pii": {
                "type": "noul",
                "instructions": "Does this text contain private API keys, passwords, bearer tokens, or PII?",
            },
            "classification": {
                "type": "choice",
                "instructions": "Classify the sensitivity of the data present.",
                "criteria": {
                    "credential_leak": "API keys, bearer tokens, passwords, or private keys",
                    "customer_pii": "Social security, identity, or credit card records",
                    "internal_source_code": "Confidential internal code or architecture",
                    "public_clean": "Safe public information or boilerplate",
                },
            },
            "risk_tier": {
                "type": "score",
                "instructions": "Assign the confidentiality risk tier.",
                "criteria": ["public", "internal", "confidential", "restricted_secret"],
            },
        }
        t0 = time.perf_counter()
        dec = self.agent.predict(text, policy)
        latency = (time.perf_counter() - t0) * 1000

        p_leak = dec["answers"]["contains_secrets_or_pii"]["noul"]
        cls = dec["answers"]["classification"]["choice"]
        tier = dec["answers"]["risk_tier"]["score"]

        verdict = "QUARANTINE" if (p_leak > 0.70 or tier >= 2.0 or cls != "public_clean") else "PASS"

        return {
            "verdict": verdict,
            "latency": latency,
            "metrics": [
                ("Secrets Leak P(true)", f"{p_leak:.4f}", "red" if p_leak > 0.7 else "green"),
                ("Classification", cls, "red" if cls != "public_clean" else "green"),
                ("Risk Tier (0-3)", f"{tier:.2f}", "yellow" if tier >= 1.5 else "green"),
            ]
        }

    def evaluate_soc(self, text: str):
        policy = {
            "is_false_positive": {
                "type": "noul",
                "instructions": "Is this event likely routine benign administrative behavior?",
            },
            "priority": {
                "type": "score",
                "instructions": "Determine priority level.",
                "criteria": ["P4_informational", "P3_low", "P2_medium", "P1_critical_incident"],
            },
            "squad": {
                "type": "choice",
                "instructions": "Select the appropriate security squad to route this ticket.",
                "criteria": {
                    "endpoint_security": "Host-level process injection, suspicious binaries, shell execution",
                    "cloud_iam": "Access key exposure, unexpected IAM policy attachment, root login",
                    "network_perimeter": "Anomalous outbound egress, port scanning, DDoS patterns",
                    "compliance_hygiene": "Unencrypted storage, policy drift, missing audit logs",
                },
            },
        }
        t0 = time.perf_counter()
        dec = self.agent.predict(text, policy)
        latency = (time.perf_counter() - t0) * 1000

        fp = dec["answers"]["is_false_positive"]["noul"]
        pri = dec["answers"]["priority"]["score"]
        sq = dec["answers"]["squad"]["choice"]

        verdict = "ESCALATE" if (fp < 0.5 and pri >= 1.0) else "ROUTINE"

        return {
            "verdict": verdict,
            "latency": latency,
            "metrics": [
                ("False Positive P", f"{fp:.4f}", "yellow" if fp > 0.5 else "cyan"),
                ("Priority (0-3)", f"{pri:.2f}", "red" if pri >= 2.0 else "green"),
                ("Route Squad", sq, "magenta"),
            ]
        }

    def evaluate_phish(self, text: str):
        policy = {
            "is_phishing_or_bec": {
                "type": "noul",
                "instructions": "Does this text attempt phishing, credential harvesting, wire fraud, or coercive social engineering?",
            },
            "threat_modality": {
                "type": "choice",
                "instructions": "Classify the specific attack modality.",
                "criteria": {
                    "wire_fraud_bec": "Requests urgent wire transfer or banking changes",
                    "credential_harvesting": "Prompts to click login links or enter credentials",
                    "malicious_attachment": "Urges opening invoice attachments or running macros",
                    "legitimate_email": "Normal business correspondence",
                },
            },
            "urgency": {
                "type": "score",
                "instructions": "Measure artificial urgency or emotional pressure.",
                "criteria": ["calm_normal", "mild_priority", "high_urgency", "extortion_or_threat"],
            },
        }
        t0 = time.perf_counter()
        dec = self.agent.predict(text, policy)
        latency = (time.perf_counter() - t0) * 1000

        p_ph = dec["answers"]["is_phishing_or_bec"]["noul"]
        mod = dec["answers"]["threat_modality"]["choice"]
        urg = dec["answers"]["urgency"]["score"]

        verdict = "BLOCK" if (p_ph > 0.70 or urg >= 2.0 or mod != "legitimate_email") else "PASS"

        return {
            "verdict": verdict,
            "latency": latency,
            "metrics": [
                ("Phishing P(true)", f"{p_ph:.4f}", "red" if p_ph > 0.7 else "green"),
                ("Modality", mod, "red" if mod != "legitimate_email" else "green"),
                ("Urgency (0-3)", f"{urg:.2f}", "yellow" if urg >= 1.5 else "green"),
            ]
        }

    def evaluate(self, input_text: str, mode: str = None):
        target_mode = mode or self.current_mode
        if target_mode == "tool":
            return self.evaluate_tool(input_text)
        elif target_mode == "guardrail" or target_mode == "prompt":
            return self.evaluate_prompt(input_text)
        elif target_mode == "dlp":
            return self.evaluate_dlp(input_text)
        elif target_mode == "soc":
            return self.evaluate_soc(input_text)
        elif target_mode == "phish":
            return self.evaluate_phish(input_text)
        else:
            return self.evaluate_tool(input_text)

    def print_result(self, input_text: str, res: dict):
        verdict = res["verdict"]
        verdict_color = "red" if verdict in {"BLOCKED", "QUARANTINE", "BLOCK", "ESCALATE"} else "green"
        
        table = Table(title=f"Laya Decision: [{verdict_color}]{verdict}[/{verdict_color}] ({res['latency']:.1f}ms)", show_header=True, header_style="bold magenta")
        table.add_column("Parameter", style="cyan", width=25)
        table.add_column("Value", style="bold")
        
        for k, v, color in res["metrics"]:
            table.add_row(k, f"[{color}]{v}[/{color}]")
        
        console.print(table)
        console.print()

    def run_repl(self):
        console.print(BANNER)
        console.print(f"[bold yellow]Active Mode:[/bold yellow] [bold green]{self.current_mode}[/bold green] (Agent Tool / Command Firewall)")
        console.print("[dim]Type any bash command, tool call, or text to evaluate it in real time.\n[/dim]")

        while True:
            try:
                user_input = Prompt.ask(f"[bold cyan]laya-sec ({self.current_mode})[/bold cyan]").strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[yellow]Exiting Laya Defense Terminal.[/yellow]")
                break

            if not user_input:
                continue

            if user_input in {":quit", ":exit", ":q"}:
                console.print("[yellow]Exiting Laya Defense Terminal.[/yellow]")
                break

            if user_input in {":help", ":h"}:
                console.print("""
[bold]Commands:[/bold]
  [cyan]:mode[/cyan]        - Switch inspection mode (tool, guardrail, dlp, soc, phish)
  [cyan]:tool <cmd>[/cyan] - Screen a specific bash/tool command
  [cyan]:guard <tx>[/cyan] - Screen a prompt for jailbreak/injections
  [cyan]:dlp <txt>[/cyan]  - Screen for PII / secrets
  [cyan]:soc <log>[/cyan]  - Triage a SOC alert
  [cyan]:phish <eml>[/cyan]- Screen an email
  [cyan]:quit[/cyan]        - Exit the terminal
""")
                continue

            if user_input.startswith(":mode"):
                parts = user_input.split()
                if len(parts) > 1:
                    target = parts[1].lower()
                    valid_names = [v[0] for v in MODES.values()]
                    if target in valid_names:
                        self.current_mode = target
                        console.print(f"[green]Switched mode to: [bold]{self.current_mode}[/bold][/green]\n")
                        continue
                console.print("\n[bold]Select inspection mode:[/bold]")
                for k, (name, desc) in MODES.items():
                    console.print(f"  [{k}] [bold cyan]{name:<10}[/bold cyan] : {desc}")
                sel = Prompt.ask("Choose [1-5]", choices=["1", "2", "3", "4", "5"], default="2")
                self.current_mode = MODES[sel][0]
                console.print(f"[green]Switched mode to: [bold]{self.current_mode}[/bold][/green]\n")
                continue

            # Command shortcuts
            mode_override = None
            if user_input.startswith(":tool "):
                mode_override = "tool"
                user_input = user_input[6:]
            elif user_input.startswith(":guard "):
                mode_override = "guardrail"
                user_input = user_input[7:]
            elif user_input.startswith(":dlp "):
                mode_override = "dlp"
                user_input = user_input[5:]
            elif user_input.startswith(":soc "):
                mode_override = "soc"
                user_input = user_input[5:]
            elif user_input.startswith(":phish "):
                mode_override = "phish"
                user_input = user_input[7:]

            res = self.evaluate(user_input, mode=mode_override)
            self.print_result(user_input, res)

def main():
    parser = argparse.ArgumentParser(description="Laya Terminal Defense REPL")
    parser.add_argument("input_text", nargs="?", help="Command or text to evaluate (single-shot)")
    parser.add_argument("--mode", "-m", choices=["tool", "guardrail", "dlp", "soc", "phish"], default="tool", help="Inspection mode")
    args = parser.parse_args()

    terminal = LayaTerminal()

    if args.input_text:
        res = terminal.evaluate(args.input_text, mode=args.mode)
        terminal.print_result(args.input_text, res)
    else:
        terminal.run_repl()

if __name__ == "__main__":
    main()
