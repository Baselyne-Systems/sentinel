"use client";

import { useState, useRef, useEffect } from "react";
import { agentApi, type AnalysisResult, type SSEEventType } from "@/lib/api";

// ── Priority badge ─────────────────────────────────────────────────────────────

function PriorityBadge({ score }: { score: number }) {
  const color =
    score >= 8
      ? "bg-red-900/60 text-red-300 border-red-700"
      : score >= 5
        ? "bg-amber-900/60 text-amber-300 border-amber-700"
        : "bg-green-900/60 text-green-300 border-green-700";
  const label = score >= 8 ? "CRITICAL" : score >= 5 ? "HIGH" : "LOW";
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs font-semibold ${color}`}>
      <span className="text-base font-bold">{score}</span>
      <span>/10 · {label}</span>
    </span>
  );
}

// ── Terraform snippet ──────────────────────────────────────────────────────────

function IacSnippet({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  if (!code.trim()) return null;
  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <div className="mt-2 relative">
      <pre className="bg-[#0d0f1a] border border-[#2a2d3e] rounded-md p-3 text-xs text-emerald-300 overflow-x-auto whitespace-pre-wrap">
        {code}
      </pre>
      <button
        onClick={handleCopy}
        className="absolute top-2 right-2 text-xs text-slate-500 hover:text-slate-300 bg-[#1a1d2e] px-2 py-0.5 rounded border border-[#2a2d3e]"
      >
        {copied ? "Copied!" : "Copy"}
      </button>
    </div>
  );
}

// ── Tool use indicator ─────────────────────────────────────────────────────────

function ToolUsePill({ toolName, summary }: { toolName: string; summary: string }) {
  return (
    <div className="flex items-start gap-2 text-xs text-slate-500 my-1">
      <span className="shrink-0 bg-blue-900/40 border border-blue-800 text-blue-300 px-2 py-0.5 rounded font-mono">
        {toolName}
      </span>
      <span className="text-slate-500">{summary}</span>
    </div>
  );
}

// ── Collapsible thinking block ─────────────────────────────────────────────────

function ThinkingBlock({ text, isStreaming }: { text: string; isStreaming: boolean }) {
  const [open, setOpen] = useState(false);
  if (!text) return null;
  return (
    <div className="mb-3 border border-violet-800/50 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-3 py-2 bg-violet-900/20 hover:bg-violet-900/30 transition-colors text-xs text-violet-300"
      >
        <span className="flex items-center gap-2 font-medium">
          <span className="text-violet-400">✦</span>
          Claude&apos;s reasoning
          {isStreaming && <span className="animate-pulse text-violet-500">thinking…</span>}
        </span>
        <span className="text-violet-600">{open ? "▲ hide" : "▼ show"}</span>
      </button>
      {open && (
        <div className="px-3 py-3 bg-[#0d0f1a] max-h-80 overflow-y-auto">
          <p className="text-xs text-violet-300/70 font-mono whitespace-pre-wrap leading-relaxed">
            {text}
            {isStreaming && <span className="animate-pulse text-violet-400">▋</span>}
          </p>
        </div>
      )}
    </div>
  );
}

// ── Main AnalysisPanel ─────────────────────────────────────────────────────────

interface Props {
  nodeId: string;
  initialAnalysis?: AnalysisResult | null;
}

type StreamState = "idle" | "streaming" | "done" | "error";

export function AnalysisPanel({ nodeId, initialAnalysis }: Props) {
  const [state, setState] = useState<StreamState>(initialAnalysis ? "done" : "idle");
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(initialAnalysis ?? null);
  const [streamText, setStreamText] = useState("");
  const [thinkingText, setThinkingText] = useState("");
  const [toolEvents, setToolEvents] = useState<Array<{ name: string; summary: string }>>([]);
  const [errorMsg, setErrorMsg] = useState("");
  const [enableThinking, setEnableThinking] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const textRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (textRef.current) {
      textRef.current.scrollTop = textRef.current.scrollHeight;
    }
  }, [streamText]);

  const startAnalysis = () => {
    setStreamText("");
    setThinkingText("");
    setToolEvents([]);
    setErrorMsg("");
    setAnalysis(null);
    setState("streaming");

    abortRef.current = agentApi.streamAnalysis(
      nodeId,
      (event: SSEEventType) => {
        if (event.event === "text_delta") {
          setStreamText((t) => t + event.text);
        } else if (event.event === "thinking_delta") {
          setThinkingText((t) => t + event.thinking);
        } else if (event.event === "tool_use") {
          setToolEvents((prev) => [
            ...prev,
            { name: event.tool_name, summary: event.tool_result_summary },
          ]);
        } else if (event.event === "analysis_complete") {
          setAnalysis(event.result);
          setState("done");
        } else if (event.event === "error") {
          setErrorMsg(event.message);
          setState("error");
        }
      },
      () => {
        setState((s) => (s === "streaming" ? "done" : s));
      },
      (err) => {
        setErrorMsg(err.message);
        setState("error");
      },
      { thinking: enableThinking }
    );
  };

  const cancel = () => {
    abortRef.current?.abort();
    setState("idle");
  };

  return (
    <div className="bg-[#13152a] border border-[#2a2d3e] rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-slate-100 font-semibold text-lg">AI Security Analysis</h2>
        <div className="flex items-center gap-3">
          {/* Extended thinking toggle — only shown in idle/done state */}
          {(state === "idle" || state === "done") && (
            <label className="flex items-center gap-1.5 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={enableThinking}
                onChange={(e) => setEnableThinking(e.target.checked)}
                className="w-3.5 h-3.5 accent-violet-500"
              />
              <span className="text-xs text-slate-500">Extended thinking</span>
            </label>
          )}
          {state === "idle" && (
            <button
              onClick={startAnalysis}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors"
            >
              Analyze with AI
            </button>
          )}
          {state === "streaming" && (
            <button
              onClick={cancel}
              className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm font-medium rounded-lg transition-colors"
            >
              Cancel
            </button>
          )}
          {state === "done" && (
            <button
              onClick={startAnalysis}
              className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm font-medium rounded-lg transition-colors"
            >
              Re-analyze
            </button>
          )}
        </div>
      </div>

      {/* Streaming state */}
      {state === "streaming" && (
        <div>
          {/* Extended thinking block (collapsible) */}
          <ThinkingBlock text={thinkingText} isStreaming={true} />

          {toolEvents.length > 0 && (
            <div className="mb-3 space-y-1">
              <p className="text-xs text-slate-600 uppercase tracking-wider mb-1">Graph queries</p>
              {toolEvents.map((t, i) => (
                <ToolUsePill key={i} toolName={t.name} summary={t.summary} />
              ))}
            </div>
          )}
          {streamText && (
            <div
              ref={textRef}
              className="max-h-60 overflow-y-auto text-slate-400 text-sm font-mono whitespace-pre-wrap bg-[#0d0f1a] rounded-lg p-3 border border-[#2a2d3e]"
            >
              {streamText}
              <span className="animate-pulse text-blue-400">▋</span>
            </div>
          )}
          {!streamText && !thinkingText && (
            <div className="flex items-center gap-2 text-slate-500 text-sm">
              <span className="animate-spin">⟳</span> Gathering context from graph…
            </div>
          )}
          {!streamText && thinkingText && (
            <div className="flex items-center gap-2 text-slate-500 text-sm">
              <span className="animate-pulse text-violet-400">✦</span> Reasoning…
            </div>
          )}
        </div>
      )}

      {/* Error state */}
      {state === "error" && (
        <div className="bg-red-900/20 border border-red-800 rounded-lg p-4 text-red-300 text-sm">
          <strong>Analysis failed:</strong> {errorMsg}
          <button
            onClick={startAnalysis}
            className="ml-4 underline hover:no-underline text-red-400"
          >
            Retry
          </button>
        </div>
      )}

      {/* Idle state */}
      {state === "idle" && (
        <p className="text-slate-500 text-sm">
          Click &quot;Analyze with AI&quot; to get an LLM-powered risk assessment, blast radius analysis,
          and step-by-step remediation for this finding.
          {enableThinking && (
            <span className="ml-1 text-violet-400">
              Extended thinking is enabled — Claude will reason step-by-step before responding.
            </span>
          )}
        </p>
      )}

      {/* Results */}
      {analysis && state === "done" && (
        <div className="space-y-6 mt-2">
          {/* Thinking block (collapsible, collapsed by default after completion) */}
          {thinkingText && <ThinkingBlock text={thinkingText} isStreaming={false} />}

          {/* Priority */}
          <div className="flex items-start gap-4">
            <PriorityBadge score={analysis.priority_score} />
            <p className="text-slate-400 text-sm">{analysis.priority_rationale}</p>
          </div>

          {/* Risk narrative */}
          <div>
            <h3 className="text-slate-300 font-medium text-sm uppercase tracking-wider mb-2">
              Risk Narrative
            </h3>
            <p className="text-slate-400 text-sm leading-relaxed whitespace-pre-wrap">
              {analysis.risk_narrative}
            </p>
          </div>

          {/* Attack paths */}
          {analysis.attack_paths_summary && (
            <div>
              <h3 className="text-slate-300 font-medium text-sm uppercase tracking-wider mb-2">
                Attack Paths
              </h3>
              <p className="text-slate-400 text-sm leading-relaxed">
                {analysis.attack_paths_summary}
              </p>
            </div>
          )}

          {/* Remediation steps */}
          {analysis.remediation_steps.length > 0 && (
            <div>
              <h3 className="text-slate-300 font-medium text-sm uppercase tracking-wider mb-3">
                Remediation Steps
              </h3>
              <ol className="space-y-4">
                {analysis.remediation_steps.map((step) => (
                  <li key={step.step_number} className="flex gap-3">
                    <span className="shrink-0 w-6 h-6 rounded-full bg-blue-900/50 border border-blue-800 text-blue-300 text-xs flex items-center justify-center font-bold">
                      {step.step_number}
                    </span>
                    <div className="flex-1">
                      <p className="text-slate-200 text-sm font-medium">{step.title}</p>
                      <p className="text-slate-400 text-sm mt-1">{step.description}</p>
                      {step.iac_snippet && <IacSnippet code={step.iac_snippet} />}
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          )}

          <p className="text-slate-600 text-xs">
            Analyzed by {analysis.model} · {new Date(analysis.analyzed_at).toLocaleString()}
          </p>
        </div>
      )}
    </div>
  );
}
