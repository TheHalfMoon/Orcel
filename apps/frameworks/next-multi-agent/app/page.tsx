"use client";

import { useState, type ComponentProps } from "react";
import { useOrcelAgent } from "@orcel/orcel/react";

const AGENTS = [
  {
    description: "Customer-facing triage and troubleshooting",
    initialPrompt: "My checkout page is failing.",
    name: "support",
  },
  {
    description: "Invoices, plans, and payment questions",
    initialPrompt: "Why did my invoice increase?",
    name: "billing",
  },
  {
    description: "Research summaries and source planning",
    initialPrompt: "Compare two options briefly.",
    name: "research",
  },
] as const;

type AgentName = (typeof AGENTS)[number]["name"];

export default function Home() {
  return (
    <main>
      <header>
        <p>Next.js named agents fixture</p>
        <h1>Three orcel agents mounted through one Next.js app</h1>
      </header>
      <section className="grid">
        {AGENTS.map((agent) => (
          <AgentPanel key={agent.name} agent={agent} />
        ))}
      </section>
    </main>
  );
}

function AgentPanel({
  agent,
}: {
  readonly agent: {
    readonly description: string;
    readonly initialPrompt: string;
    readonly name: AgentName;
  };
}) {
  const orcel = useOrcelAgent({ agent: agent.name });
  const [message, setMessage] = useState(agent.initialPrompt);
  const isBusy = orcel.status === "submitted" || orcel.status === "streaming";

  const submit: ComponentProps<"form">["onSubmit"] = async (event) => {
    event.preventDefault();
    const trimmed = message.trim();
    if (trimmed.length === 0 || isBusy) return;
    setMessage("");
    await orcel.send(trimmed);
  };

  return (
    <article>
      <div className="panel-header">
        <div>
          <h2>{agent.name}</h2>
          <p>{agent.description}</p>
        </div>
        <span>{orcel.status}</span>
      </div>

      <div className="messages">
        {orcel.data.messages.length === 0 ? (
          <p className="empty">Send a short prompt to the {agent.name} agent.</p>
        ) : (
          orcel.data.messages.map((item) => (
            <div className="message" data-role={item.role} key={item.id}>
              <strong>{item.role}</strong>
              {item.parts.map((part, index) =>
                part.type === "text" ? <p key={index}>{part.text}</p> : null,
              )}
            </div>
          ))
        )}
      </div>

      <form onSubmit={submit}>
        <textarea
          aria-label={`Message ${agent.name} agent`}
          onChange={(event) => setMessage(event.currentTarget.value)}
          value={message}
        />
        <button disabled={isBusy || message.trim().length === 0} type="submit">
          Send to {agent.name}
        </button>
      </form>
    </article>
  );
}
