// Inspector: detail panel for the currently selected process. Shows identity,
// history, sockets, open files, env vars, spoof/malfind artifacts, and any
// findings whose target references this PID.
import { useMemo } from "react";
import { useAppStore } from "@/stores/app.store";
import { LevelBadge, MitreLinks } from "@/components/common";
import type { Finding, ProcessRecord } from "@/models";

function Section({
  title,
  count,
  children,
}: {
  title: string;
  count?: number;
  children: React.ReactNode;
}) {
  return (
    <div className="insp-section">
      <h4>
        {title}
        {count !== undefined && <span className="insp-count">{count}</span>}
      </h4>
      {children}
    </div>
  );
}

function findingsForPid(findings: Finding[], pid: string): Finding[] {
  return findings.filter((f) => new RegExp(`\\(${pid}\\)`).test(f.target));
}

export function Inspector() {
  const selectedPid = useAppStore((s) => s.selectedPid);
  const records = useAppStore((s) => s.records);
  const findings = useAppStore((s) => s.findings);

  const rec: ProcessRecord | undefined = selectedPid
    ? records.get(selectedPid)
    : undefined;
  const pidFindings = useMemo(
    () => (selectedPid ? findingsForPid(findings, selectedPid) : []),
    [findings, selectedPid]
  );

  if (!rec) {
    return (
      <aside className="inspector inspector-empty">
        <p>Select a process node to inspect its artifacts.</p>
      </aside>
    );
  }

  const envEntries = Object.entries(rec.envars);

  return (
    <aside className="inspector">
      <header className="insp-header">
        <h3>
          {rec.comm ?? rec.raw["Comm"] ?? "process"}{" "}
          <span className="insp-pid">pid {rec.pid}</span>
        </h3>
        <dl className="insp-meta">
          {rec.ppid && (
            <>
              <dt>PPID</dt>
              <dd>{rec.ppid}</dd>
            </>
          )}
          {rec.uid && (
            <>
              <dt>UID</dt>
              <dd>{rec.uid}</dd>
            </>
          )}
          {rec.cmdline && (
            <>
              <dt>cmdline</dt>
              <dd className="mono wrap">{rec.cmdline}</dd>
            </>
          )}
        </dl>
      </header>

      {pidFindings.length > 0 && (
        <Section title="Findings" count={pidFindings.length}>
          <ul className="insp-findings">
            {pidFindings.map((f, i) => (
              <li key={i}>
                <LevelBadge level={f.level} />
                <span className="insp-rule">{f.rule}</span>
                <MitreLinks technique={f.technique} refs={f.mitre} />
                <div className="insp-detail">{f.detail}</div>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {rec.spoof && (rec.spoof.commSpoofed || rec.spoof.exeDeleted || rec.spoof.cmdlineSpoofed) && (
        <Section title="Process spoofing">
          <table className="insp-kv">
            <tbody>
              {rec.spoof.commSpoofed && (
                <tr>
                  <td>comm_spoofed</td>
                  <td>{rec.spoof.commSpoofed}</td>
                </tr>
              )}
              {rec.spoof.cmdlineSpoofed && (
                <tr>
                  <td>cmdline_spoofed</td>
                  <td>{rec.spoof.cmdlineSpoofed}</td>
                </tr>
              )}
              {rec.spoof.exeDeleted && (
                <tr>
                  <td>exe_deleted</td>
                  <td>{rec.spoof.exeDeleted}</td>
                </tr>
              )}
            </tbody>
          </table>
        </Section>
      )}

      {rec.malfind.length > 0 && (
        <Section title="Malfind regions" count={rec.malfind.length}>
          <table className="insp-table">
            <thead>
              <tr>
                <th>Address</th>
                <th>Protection</th>
              </tr>
            </thead>
            <tbody>
              {rec.malfind.map((m, i) => (
                <tr key={i}>
                  <td className="mono">{m.address}</td>
                  <td className="mono">{m.protection}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}

      {rec.history.length > 0 && (
        <Section title="Command history" count={rec.history.length}>
          <ul className="insp-history">
            {rec.history.map((h, i) => (
              <li key={i} className="mono">
                {h.commandTime && <span className="insp-time">{h.commandTime}</span>}
                {h.command}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {rec.sockets.length > 0 && (
        <Section title="Sockets" count={rec.sockets.length}>
          <table className="insp-table">
            <thead>
              <tr>
                <th>Proto</th>
                <th>Local</th>
                <th>Remote</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {rec.sockets.map((s, i) => (
                <tr key={i} className="mono">
                  <td>{s.proto}</td>
                  <td>
                    {s.localAddr}
                    {s.localPort ? `:${s.localPort}` : ""}
                  </td>
                  <td>{s.remoteAddr}</td>
                  <td>{s.state}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}

      {rec.files.length > 0 && (
        <Section title="Open files" count={rec.files.length}>
          <table className="insp-table">
            <thead>
              <tr>
                <th>FD</th>
                <th>Path</th>
              </tr>
            </thead>
            <tbody>
              {rec.files.map((f, i) => (
                <tr key={i} className="mono">
                  <td>{f.fd}</td>
                  <td className="wrap">{f.path}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}

      {envEntries.length > 0 && (
        <Section title="Environment" count={envEntries.length}>
          <table className="insp-kv">
            <tbody>
              {envEntries.map(([k, v]) => (
                <tr key={k}>
                  <td className="mono">{k}</td>
                  <td className="mono wrap">{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}
    </aside>
  );
}
