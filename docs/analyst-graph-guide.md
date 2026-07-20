# Process Graph — Quick Guide for Analysts

The **Process Graph** page is designed for rapid triage of memory dumps. Every process node is color-coded by threat level, spacing is expanded for clarity, and you can explore the graph interactively without cluttering your view.

## Reading the Colors

The legend at the bottom of the graph shows what each color means:

### 🟢 **Benign** (green outline, dark fill)
Clean processes with no findings, normal ancestry, and non-suspicious names. Most system utilities, libraries, and user-spawned processes land here. **Expected in every memory image**.

### ⚪ **System** (gray outline, subdued)
Kernel-internal and system daemons (`systemd`, `init`, `kworker`, kernel threads). These are almost always benign and intentionally de-emphasized so they don't clutter your threat assessment. **Safe to ignore unless anomalies are nearby**.

### 🟡 **Suspicious** (amber/gold outline, orange fill)
Processes with **warnings** from the detection engine, or unusual process names (all-caps, no extension on Windows, etc.). Not yet confirmed malicious, but warrant inspection. Click to see what triggered the warning.

### 🔴 **Alert** (red outline, red glow)
Processes with confirmed **alert-level findings** — injected regions (malfind), hidden modules, spoofed identity, syscall hooks, or command patterns matching known attacks. **Always click these first**.

### 🟣 **Hidden** (purple dashed outline)
Orphan or deeply nested processes with no clear parent chain or processes that Volatility couldn't fully resolve. These are unusual and suspicious by definition. **High-priority investigation candidates**.

---

## Layout Modes

**Tree mode** (default) — processes arranged in a clean hierarchical lineage, left-to-right by depth. Useful for seeing parent-child relationships and spawn chains.

**Force mode** — organic layout driven by physics simulation. Nodes repel each other, pulling the graph apart so crowding is less of a problem. Useful for seeing clusters of related activity.

Toggle between them using the buttons in the top-left corner.

---

## Interacting with the Graph

- **Drag a node** — pins it in place. The node stays where you drop it even if the graph re-renders. Useful for manually organizing a complex tree for closer inspection.
- **Double-click a node** — releases it back into the physics simulation (force mode only).
- **Click a node** — selects it and drives the Inspector panel (right sidebar). Shows history, sockets, open files, environment, and all findings tied to that process.
- **Scroll** — zoom in/out.
- **Drag the background** — pan around.
- **Fit button** — re-frames the graph to fit the view.

---

## Analyst Workflow

1. **Load the pstree CSV** and any supplementary CSVs (bash, lsof, etc.). The graph builds automatically.

2. **Scan for red and purple nodes** — these are your highest priorities. Click each one and read the findings.

3. **Follow chains** — if you find a suspicious process, hover over its parent to see what spawned it. Click the parent to see *its* findings and environment.

4. **Check for anomalies**:
   - A benign process with an unusual child (e.g., `apache2` → `bash`). ← **red flag**
   - A system daemon spawning a network tool or shell. ← **red flag**
   - A process far from the init tree with no parent chain. ← **hidden flag**

5. **Use the Inspector** to drill into details: shell history, environment variables, open sockets, and files.

6. **Switch to the File Cache tab** if you see suspicious file activity, or the **Modules & Rootkits tab** if there are T1014 (Rootkit) findings.

---

## Pro Tips

- **Crowding** — if the graph is still dense even with expanded spacing, try **Force mode** and let it settle for a few seconds. Nodes will push apart naturally.
- **Large images** — memory dumps with 1000+ processes can slow the graph. Focus on nodes with findings first using the Findings dashboard, then load their PIDs into the graph.
- **Keyboard shortcuts** — in Force mode, double-click a node to release it back into physics, which helps unknot overlapping chains.
- **Export findings** — the Findings dashboard lets you export all findings as CSV or JSON for your report.

---

## Key Signals by Category Combination

| Scenario | What to look for |
|----------|---|
| Green parent + red child | Process injection / privilege escalation attempt |
| System nodes + red nearby | Rootkit or kernel-level tampering (check the Modules tab) |
| Purple + red siblings | Hidden malware family, possibly from same dropper |
| Leaf node (no children) + alert | Malicious tool or payload that completed and exited |
| High-depth (8+ levels) + benign | May be obfuscation or deep nesting to evade detection; check the chain |

---

## Next Steps

1. **Findings Dashboard** — flip to the **Files & Modules** page to see all findings, scored by severity, with ATT&CK technique mapping.
2. **File Cache** — recover cached files from memory; useful if you find suspicious download/write activity in the graph.
3. **Modules & Rootkits** — inspect kernel modules, hidden modules, and syscall-table integrity. This page lights up if you load `linux.lsmod`, `linux.malware.hidden_modules`, or `linux.malware.check_syscall` CSVs.

---

## Questions?

- **How do I know which Volatility plugins to run?** See `docs/volatility-commands.md` in the package.
- **Can I run plugins from the app?** Yes — click **▸ Run Volatility** in the header (if the backend is connected).
- **What if the graph is still too crowded?** Increase the spacing by editing `COL_GAP` and `ROW_GAP` constants in `ProcessTree.tsx`, or use the Force layout and let physics sort it out.
