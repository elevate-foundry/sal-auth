/* ============================================================
   BBID Mathematical Framework Writeup — Home Page
   Design: Cryptographic Codex
   - IBM Plex Serif body/headings, IBM Plex Mono code/math
   - Deep charcoal bg, warm off-white text, amber accent
   - Asymmetric left-rail nav + main content column
   - KaTeX for math rendering
   ============================================================ */

import { useEffect, useRef, useState } from "react";
import { InlineMath, BlockMath } from "react-katex";
import "katex/dist/katex.min.css";

// ── Section data for left-rail navigation ──────────────────
const SECTIONS = [
  { id: "abstract",   label: "Abstract" },
  { id: "sec1",       label: "1. Feature Vector Space" },
  { id: "sec2",       label: "2. Random Projection LSH" },
  { id: "sec3",       label: "3. Fuzzy Commitment (BCH)" },
  { id: "sec4",       label: "4. BBES Mapping Function" },
  { id: "sec5",       label: "5. Entropy & Collision Bounds" },
  { id: "discussion", label: "Discussion" },
];

// ── Scroll-reveal hook ─────────────────────────────────────
function useReveal() {
  useEffect(() => {
    const els = document.querySelectorAll(".reveal");
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add("visible");
            observer.unobserve(e.target);
          }
        });
      },
      { threshold: 0.08 }
    );
    els.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, []);
}

// ── Active section tracking ────────────────────────────────
function useActiveSection(ids: string[]) {
  const [active, setActive] = useState(ids[0]);
  useEffect(() => {
    const handler = () => {
      const scrollY = window.scrollY + 120;
      let current = ids[0];
      for (const id of ids) {
        const el = document.getElementById(id);
        if (el && el.offsetTop <= scrollY) current = id;
      }
      setActive(current);
    };
    window.addEventListener("scroll", handler, { passive: true });
    return () => window.removeEventListener("scroll", handler);
  }, [ids]);
  return active;
}

// ── Braille encoder (byte → 8-dot Unicode braille) ─────────
function toBraille(text: string): string {
  const BRAILLE_BASE = 0x2800;
  return Array.from(text)
    .map((c) => String.fromCodePoint(BRAILLE_BASE + (c.charCodeAt(0) % 256)))
    .join("");
}

// ── Live Braille Encoder Widget ────────────────────────────
function BrailleEncoder() {
  const [input, setInput] = useState("BBID");
  const encoded = toBraille(input);
  return (
    <div className="callout my-8">
      <div className="callout-title">Live BBES Encoder — f(Y_m) = 0x2800 + byte_value</div>
      <div className="flex flex-col gap-3 mt-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value.slice(0, 32))}
          placeholder="Type text to encode…"
          className="bg-transparent border border-[oklch(0.28_0.01_260)] rounded px-3 py-2 font-mono text-sm text-[oklch(0.91_0.012_80)] outline-none focus:border-[oklch(0.75_0.16_65)] transition-colors"
        />
        <div className="braille-display tracking-widest break-all">
          {encoded || "⠀"}
        </div>
        <div className="font-mono text-xs text-[oklch(0.45_0.008_80)]">
          {input.length} char{input.length !== 1 ? "s" : ""} → {encoded.length} braille cell{encoded.length !== 1 ? "s" : ""}
          {" · "}
          {encoded.length * 8} bits of identity
        </div>
      </div>
    </div>
  );
}

// ── Collision table data ───────────────────────────────────
const COLLISION_ROWS = [
  { cells: "8 Cells",  bits: "64 bits",  pop: "1,000,000",     risk: "~0.0027%",        note: "Safe PoC" },
  { cells: "8 Cells",  bits: "64 bits",  pop: "10,000,000",    risk: "~0.27%",          note: "Degraded" },
  { cells: "16 Cells", bits: "128 bits", pop: "8,000,000,000", risk: "~9.4 × 10⁻²⁰",   note: "Global-scale safe" },
];

// ── Main page ──────────────────────────────────────────────
export default function Home() {
  useReveal();
  const sectionIds = SECTIONS.map((s) => s.id);
  const active = useActiveSection(sectionIds);
  const [railOpen, setRailOpen] = useState(false);

  return (
    <div className="min-h-screen braille-bg">
      {/* ── Top bar ── */}
      <header className="sticky top-0 z-50 border-b border-[oklch(0.22_0.008_260)] bg-[oklch(0.11_0.008_260/0.95)] backdrop-blur-sm">
        <div className="container flex items-center justify-between h-12">
          <span className="font-mono text-xs tracking-widest text-[oklch(0.75_0.16_65)] uppercase">
            ⠃⠃⠊⠙ · sal-auth
          </span>
          <span className="font-mono text-xs text-[oklch(0.40_0.008_80)]">
            Mathematical Framework v1.0
          </span>
          {/* Mobile rail toggle */}
          <button
            className="lg:hidden font-mono text-xs text-[oklch(0.55_0.008_80)] hover:text-[oklch(0.75_0.16_65)] transition-colors"
            onClick={() => setRailOpen((o) => !o)}
          >
            {railOpen ? "✕ close" : "§ sections"}
          </button>
        </div>
      </header>

      <div className="container flex gap-0 lg:gap-12 pt-10 pb-24">
        {/* ── Left rail ── */}
        <aside
          className={`
            ${railOpen ? "block" : "hidden"} lg:block
            fixed lg:sticky top-[3.5rem] lg:top-[4.5rem]
            left-0 lg:left-auto
            w-64 lg:w-52 xl:w-60
            h-screen lg:h-[calc(100vh-4.5rem)]
            bg-[oklch(0.11_0.008_260)] lg:bg-transparent
            border-r border-[oklch(0.22_0.008_260)] lg:border-none
            px-6 lg:px-0 pt-6 lg:pt-0
            overflow-y-auto
            flex-shrink-0
            z-40
          `}
        >
          <div className="font-mono text-[0.6rem] tracking-[0.18em] uppercase text-[oklch(0.35_0.008_80)] mb-4">
            Contents
          </div>
          <nav className="flex flex-col gap-1">
            {SECTIONS.map((s) => (
              <a
                key={s.id}
                href={`#${s.id}`}
                className={`rail-link ${active === s.id ? "active" : ""}`}
                onClick={() => setRailOpen(false)}
              >
                {s.label}
              </a>
            ))}
          </nav>

          <div className="mt-10 border-t border-[oklch(0.22_0.008_260)] pt-6">
            <div className="font-mono text-[0.6rem] tracking-[0.18em] uppercase text-[oklch(0.35_0.008_80)] mb-3">
              Repository
            </div>
            <a
              href="https://github.com/elevate-foundry/sal-auth"
              target="_blank"
              rel="noopener noreferrer"
              className="rail-link"
            >
              elevate-foundry/sal-auth ↗
            </a>
            <a
              href="https://github.com/elevate-foundry/bbid-challenge"
              target="_blank"
              rel="noopener noreferrer"
              className="rail-link mt-1"
            >
              elevate-foundry/bbid-challenge ↗
            </a>
          </div>
        </aside>

        {/* ── Main content ── */}
        <main className="flex-1 min-w-0 max-w-3xl">

          {/* ── Hero ── */}
          <section id="abstract" className="mb-16 reveal">
            <div className="section-badge mb-3">Elevate Foundry · Technical Writeup</div>
            <h1 className="text-4xl lg:text-5xl font-bold text-[oklch(0.91_0.012_80)] leading-tight mb-6">
              Formalizing{" "}
              <span className="text-[oklch(0.75_0.16_65)]">BBID</span>
              <br />
              A Cryptographic Biometric<br />Identity Framework
            </h1>

            <div className="braille-display mb-6 select-none" aria-hidden="true">
              ⣾⣄⠹⢟⣓⠆⡧⣠
            </div>

            <div className="callout">
              <div className="callout-title">Abstract</div>
              <p className="text-[oklch(0.80_0.012_80)] leading-relaxed text-base">
                To elevate BBID from a creative proof-of-concept into a cryptographically
                and mathematically sound framework, we replace the naïve SHA-256 pipeline
                with a formalized <strong className="text-[oklch(0.91_0.012_80)]">Biometric/Behavioral Fusion Engine</strong>.
                By combining <strong className="text-[oklch(0.91_0.012_80)]">Locality-Sensitive Hashing (LSH)</strong>,{" "}
                <strong className="text-[oklch(0.91_0.012_80)]">BCH Error-Correcting Codes</strong>, and a formal{" "}
                <strong className="text-[oklch(0.91_0.012_80)]">Galois Field mapping</strong> to the Unicode Braille block,
                the system eliminates the avalanche effect while maintaining a zero-cookie architecture.
                The result is a highly deterministic, noise-insulated biometric identity protocol
                suitable for enterprise authentication at global scale.
              </p>
            </div>
          </section>

          <hr className="section-rule" />

          {/* ── Section 1 ── */}
          <section id="sec1" className="mb-14 reveal">
            <div className="section-badge mb-2">Section 1</div>
            <h2 className="text-2xl lg:text-3xl font-bold text-[oklch(0.91_0.012_80)] mb-6">
              Feature Vector Space Formulation
            </h2>

            <p className="text-[oklch(0.80_0.012_80)] mb-5">
              We model the user's device and behavior as a high-dimensional composite
              feature vector <InlineMath math="X \in \mathbb{R}^{D}" />, where{" "}
              <InlineMath math="D = d_H + d_B" />.
            </p>

            <div className="callout mb-6">
              <div className="callout-title">Definition — Composite Feature Vector</div>
              <ul className="space-y-2 text-[oklch(0.80_0.012_80)] text-sm">
                <li>
                  <strong className="text-[oklch(0.91_0.012_80)]">Deterministic Hardware Subspace</strong>{" "}
                  <InlineMath math="H \in \mathbb{R}^{d_H}" />: Canvas metrics, WebGL constants,
                  CPU cores, and screen geometry — treated as discrete categorical coordinates
                  mapped to integer spaces.
                </li>
                <li>
                  <strong className="text-[oklch(0.91_0.012_80)]">Stochastic Behavioral Subspace</strong>{" "}
                  <InlineMath math="B \in \mathbb{R}^{d_B}" />: Mean keystroke flight time,
                  mouse acceleration variance, scroll velocity entropy, and math calculation latency.
                </li>
              </ul>
            </div>

            <p className="text-[oklch(0.80_0.012_80)] mb-4">
              Because <InlineMath math="B" /> is subjected to environmental and human noise,
              any two observations <InlineMath math="X_1" /> and <InlineMath math="X_2" /> from
              the same user will satisfy:
            </p>

            <div className="eq-block">
              <span className="eq-label">EQ-1</span>
              <BlockMath math="X_2 = X_1 + \epsilon" />
              <p className="text-[oklch(0.55_0.008_80)] text-xs mt-2 font-mono">
                where <InlineMath math="\epsilon \sim \mathcal{N}(0, \Sigma)" /> represents Gaussian measurement noise.
              </p>
            </div>
          </section>

          <hr className="section-rule" />

          {/* ── Section 2 ── */}
          <section id="sec2" className="mb-14 reveal">
            <div className="section-badge mb-2">Section 2</div>
            <h2 className="text-2xl lg:text-3xl font-bold text-[oklch(0.91_0.012_80)] mb-6">
              The Analog-to-Digital Bridge: Random Projection LSH
            </h2>

            <p className="text-[oklch(0.80_0.012_80)] mb-5">
              To convert the noisy vector <InlineMath math="X" /> into a stable identity
              token without relying on local storage, we pass the behavioral subspace through
              a <strong className="text-[oklch(0.91_0.012_80)]">Signed Random Projection (SimHash)</strong> filter.
              This preserves the cosine similarity between sessions.
            </p>

            <p className="text-[oklch(0.80_0.012_80)] mb-4">
              We define a set of <InlineMath math="k" /> random hyperplanes{" "}
              <InlineMath math="R = \{r_1, r_2, \dots, r_k\}" />, where each{" "}
              <InlineMath math="r_i \in \mathbb{R}^{D}" /> is drawn from a standard normal
              distribution <InlineMath math="\mathcal{N}(0, I)" />.
              The projection function <InlineMath math="h_R(X)" /> generates a <InlineMath math="k" />-bit
              binary string where the <InlineMath math="i" />-th bit is:
            </p>

            <div className="eq-block">
              <span className="eq-label">EQ-2</span>
              <BlockMath math="h_i(X) = \begin{cases} 1 & \text{if } X \cdot r_i \geq 0 \\ 0 & \text{if } X \cdot r_i < 0 \end{cases}" />
            </div>

            <h3 className="text-lg font-semibold text-[oklch(0.91_0.012_80)] mt-8 mb-4">
              Probability of Bit Agreement
            </h3>

            <p className="text-[oklch(0.80_0.012_80)] mb-4">
              The probability that any given bit matches between two separate visits is
              directly proportional to the angular similarity of the user's behavior:
            </p>

            <div className="eq-block">
              <span className="eq-label">EQ-3</span>
              <BlockMath math="\mathbb{P}(h_i(X_1) = h_i(X_2)) = 1 - \frac{\theta(X_1, X_2)}{\pi}" />
              <p className="text-[oklch(0.55_0.008_80)] text-xs mt-2 font-mono">
                where <InlineMath math="\theta(X_1, X_2) = \arccos\!\left(\dfrac{X_1 \cdot X_2}{\|X_1\|\|X_2\|}\right)" />
              </p>
            </div>
          </section>

          <hr className="section-rule" />

          {/* ── Section 3 ── */}
          <section id="sec3" className="mb-14 reveal">
            <div className="section-badge mb-2">Section 3</div>
            <h2 className="text-2xl lg:text-3xl font-bold text-[oklch(0.91_0.012_80)] mb-6">
              Stabilization via Fuzzy Commitment (Juels–Wattenberg)
            </h2>

            <p className="text-[oklch(0.80_0.012_80)] mb-5">
              For the OAuth provider (<code>sal-auth</code>) to output an{" "}
              <em>exact, immutable</em> Braille string across sessions without saving
              cookies, we implement a <strong className="text-[oklch(0.91_0.012_80)]">Fuzzy Commitment Scheme</strong> using
              a Bose–Chaudhuri–Hocquenghem <InlineMath math="\text{BCH}(n, k, t)" /> error-correcting
              code over the Galois Field <InlineMath math="GF(2^m)" />.
            </p>

            <h3 className="text-lg font-semibold text-[oklch(0.91_0.012_80)] mt-8 mb-4">
              Enrollment Phase (First Visit)
            </h3>

            <ol className="space-y-4 text-[oklch(0.80_0.012_80)] list-none pl-0">
              {[
                <>The system generates a noisy biometric bit-string <InlineMath math="w = h_R(X) \in \{0, 1\}^n" />.</>,
                <>The server randomly selects a canonical identity codeword <InlineMath math="c \in C" /> from the BCH codebook.</>,
                <>The server computes a public blinding factor (the commitment token) <InlineMath math="\delta" />:</>,
                <>The server stores <InlineMath math="\delta" /> in the Neo4j graph linked to the initial visitor node. The canonical ID is securely hashed as <InlineMath math="H(c)" /> for verification.</>,
              ].map((item, i) => (
                <li key={i} className="flex gap-4 items-start">
                  <span className="font-mono text-[oklch(0.75_0.16_65)] text-sm mt-0.5 flex-shrink-0 w-5">
                    {i + 1}.
                  </span>
                  <span>{item}</span>
                </li>
              ))}
            </ol>

            <div className="eq-block mt-4">
              <span className="eq-label">EQ-4 · Commitment</span>
              <BlockMath math="\delta = w \oplus c" />
            </div>

            <h3 className="text-lg font-semibold text-[oklch(0.91_0.012_80)] mt-8 mb-4">
              Authentication Phase (Returning Visit)
            </h3>

            <ol className="space-y-4 text-[oklch(0.80_0.012_80)] list-none pl-0">
              {[
                <>The user returns and generates a noisy vector yielding a new bitstring <InlineMath math="w' = h_R(X')" />.</>,
                <>The server retrieves the historic blinding factor <InlineMath math="\delta" /> from the graph and extracts a noisy codeword <InlineMath math="c'" />:</>,
                <>The server runs the BCH decoding algorithm <InlineMath math="\text{Decode}(c')" />. If the behavioral drift is within the error threshold (Hamming distance <InlineMath math="d_H(w, w') \leq t" />), the error-correcting code eliminates the noise, snapping <InlineMath math="c'" /> back to the exact canonical codeword <InlineMath math="c" />:</>,
              ].map((item, i) => (
                <li key={i} className="flex gap-4 items-start">
                  <span className="font-mono text-[oklch(0.75_0.16_65)] text-sm mt-0.5 flex-shrink-0 w-5">
                    {i + 1}.
                  </span>
                  <span>{item}</span>
                </li>
              ))}
            </ol>

            <div className="eq-block mt-4">
              <span className="eq-label">EQ-5 · Noisy Recovery</span>
              <BlockMath math="c' = w' \oplus \delta = (w' \oplus w) \oplus c" />
            </div>

            <div className="eq-block">
              <span className="eq-label">EQ-6 · BCH Decode</span>
              <BlockMath math="\text{Decode}(c') = c \quad \text{if } d_H(w, w') \leq t" />
            </div>
          </section>

          <hr className="section-rule" />

          {/* ── Section 4 ── */}
          <section id="sec4" className="mb-14 reveal">
            <div className="section-badge mb-2">Section 4</div>
            <h2 className="text-2xl lg:text-3xl font-bold text-[oklch(0.91_0.012_80)] mb-6">
              The BBES Mapping Function (Bits → Braille)
            </h2>

            <p className="text-[oklch(0.80_0.012_80)] mb-5">
              Once the canonical codeword <InlineMath math="c" /> is recovered and verified,
              it must be mapped to the 8-dot Braille Unicode block (<code>U+2800</code> to <code>U+28FF</code>).
              Each 8-dot Braille cell natively represents exactly 1 byte (<InlineMath math="2^8 = 256" /> possibilities).
            </p>

            <p className="text-[oklch(0.80_0.012_80)] mb-4">
              Let the canonical bitstring <InlineMath math="c" /> be divided into a sequence of{" "}
              <InlineMath math="M" /> bytes, where each byte{" "}
              <InlineMath math="Y_m \in \{0, \ldots, 255\}" />. The bits of <InlineMath math="Y_m" /> map
              directly to the standardized ISO/IEC 15924 Braille dot numbering grid:
            </p>

            <div className="callout mb-6">
              <div className="callout-title">ISO/IEC 15924 Braille Dot Grid</div>
              <pre className="bg-transparent border-none p-0 text-sm text-[oklch(0.80_0.012_80)]">{`  (Bit 0) Dot 1 ⠿ Dot 4 (Bit 3)
  (Bit 1) Dot 2 ⠿ Dot 5 (Bit 4)
  (Bit 2) Dot 3 ⠿ Dot 6 (Bit 5)
  (Bit 6) Dot 7 ⠿ Dot 8 (Bit 7)`}</pre>
            </div>

            <p className="text-[oklch(0.80_0.012_80)] mb-4">
              The mathematical mapping function <InlineMath math="f(Y_m)" /> yields the exact
              Unicode scalar value:
            </p>

            <div className="eq-block">
              <span className="eq-label">EQ-7 · BBES Mapping</span>
              <BlockMath math="f(Y_m) = \texttt{0x2800} + \sum_{i=0}^{7} b_i \cdot 2^i" />
            </div>

            <p className="text-[oklch(0.80_0.012_80)] mb-6">
              If <InlineMath math="c" /> is a 64-bit string, it yields an elegant, exactly
              deterministic 8-character Braille identity string on the user's dashboard.
              Try it yourself:
            </p>

            <BrailleEncoder />
          </section>

          <hr className="section-rule" />

          {/* ── Section 5 ── */}
          <section id="sec5" className="mb-14 reveal">
            <div className="section-badge mb-2">Section 5</div>
            <h2 className="text-2xl lg:text-3xl font-bold text-[oklch(0.91_0.012_80)] mb-6">
              Entropy, Uniqueness, and Collision Bounds
            </h2>

            <p className="text-[oklch(0.80_0.012_80)] mb-5">
              To ensure this satisfies enterprise authentication requirements, we evaluate
              the collision probability under the{" "}
              <strong className="text-[oklch(0.91_0.012_80)]">Birthday Paradox</strong> for a
              64-bit (<InlineMath math="M=8" />) vs. 128-bit (<InlineMath math="M=16" />) Braille
              string configuration.
            </p>

            <p className="text-[oklch(0.80_0.012_80)] mb-4">
              Let <InlineMath math="N" /> be the population size, and{" "}
              <InlineMath math="d = 2^k" /> be the total available keyspace. The probability
              of at least one identity collision is bounded by:
            </p>

            <div className="eq-block">
              <span className="eq-label">EQ-8 · Collision Bound</span>
              <BlockMath math="P(\text{collision}) \approx 1 - \exp\!\left( - \frac{N^2}{2^{k+1}} \right)" />
            </div>

            <div className="overflow-x-auto mt-6 mb-6">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Braille String</th>
                    <th>Available Bits (k)</th>
                    <th>Population (N)</th>
                    <th>P(collision)</th>
                    <th>Assessment</th>
                  </tr>
                </thead>
                <tbody>
                  {COLLISION_ROWS.map((row) => (
                    <tr key={row.cells + row.pop}>
                      <td className="text-[oklch(0.75_0.16_65)]">{row.cells}</td>
                      <td>{row.bits}</td>
                      <td>{row.pop}</td>
                      <td className="font-mono">{row.risk}</td>
                      <td className={row.note === "Global-scale safe" ? "text-[oklch(0.75_0.16_65)]" : "text-[oklch(0.55_0.008_80)]"}>
                        {row.note}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="callout">
              <div className="callout-title">Security Takeaway</div>
              <p className="text-[oklch(0.80_0.012_80)] text-sm leading-relaxed">
                By moving to a <strong className="text-[oklch(0.91_0.012_80)]">16-cell Braille signature</strong> (128 bits of entropy),
                the system completely eliminates collision vectors across the entire population of the planet,
                even when allowing for a <InlineMath math="t = 12" /> bit error correction margin
                in the behavioral biometric layer. This shifts <code>sal-auth</code> from a
                high-risk probabilistic matching engine to a highly deterministic, noise-insulated
                biometric identity protocol.
              </p>
            </div>
          </section>

          <hr className="section-rule" />

          {/* ── Discussion ── */}
          <section id="discussion" className="mb-14 reveal">
            <div className="section-badge mb-2">Discussion</div>
            <h2 className="text-2xl lg:text-3xl font-bold text-[oklch(0.91_0.012_80)] mb-6">
              Open Question: Hyperplane Seeding Strategy
            </h2>

            <p className="text-[oklch(0.80_0.012_80)] mb-5">
              With this adjustment, the <code>sal-auth</code> codebase shifts from a
              high-risk probabilistic matching engine to a highly deterministic,
              noise-insulated biometric identity protocol.
            </p>

            <p className="text-[oklch(0.80_0.012_80)] mb-5">
              One critical implementation decision remains open: how to seed the initial
              random hyperplanes <InlineMath math="R" /> for the random projection step.
              Two architectures are viable:
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
              {[
                {
                  title: "Static Bundle",
                  desc: "Hyperplanes are deterministically generated from a fixed seed and bundled into the client-side package. Simple, fast, and reproducible — but the projection matrix is public knowledge, enabling adversarial perturbation.",
                  pro: "Zero latency, fully offline",
                  con: "Projection matrix is observable",
                },
                {
                  title: "Dynamic Server-Side",
                  desc: "Hyperplanes are served by the Cloudflare Worker upon session initialization, derived from a per-visitor secret stored in Neo4j. The projection matrix is never exposed to the client.",
                  pro: "Projection matrix stays private",
                  con: "Requires one extra round-trip",
                },
              ].map((opt) => (
                <div key={opt.title} className="callout">
                  <div className="callout-title">{opt.title}</div>
                  <p className="text-[oklch(0.80_0.012_80)] text-sm mb-3">{opt.desc}</p>
                  <div className="font-mono text-xs space-y-1">
                    <div className="text-[oklch(0.65_0.14_145)]">+ {opt.pro}</div>
                    <div className="text-[oklch(0.65_0.18_25)]">− {opt.con}</div>
                  </div>
                </div>
              ))}
            </div>

            <p className="text-[oklch(0.80_0.012_80)] mb-4">
              The dynamic approach is recommended for production deployments of <code>sal-auth</code>.
              The Cloudflare Worker already holds the Neo4j connection and can derive a
              per-visitor projection seed from the visitor's UUID using a keyed HKDF:
            </p>

            <pre className="text-sm">
{`# Per-visitor hyperplane derivation (Python pseudocode)
import hmac, hashlib, numpy as np

def derive_hyperplanes(visitor_id: str, server_secret: bytes,
                       k: int = 64, D: int = 128) -> np.ndarray:
    seed_bytes = hmac.new(
        server_secret,
        visitor_id.encode(),
        hashlib.sha256
    ).digest()
    rng = np.random.default_rng(
        np.frombuffer(seed_bytes, dtype=np.uint8)
    )
    return rng.standard_normal((k, D))  # shape: (k, D)`}
            </pre>

            <p className="text-[oklch(0.80_0.012_80)] mt-6">
              This ensures that even if an adversary observes many BBID outputs, they
              cannot reconstruct the projection matrix without the server secret — preserving
              the security guarantees of the fuzzy commitment scheme.
            </p>
          </section>

          {/* ── Footer ── */}
          <footer className="border-t border-[oklch(0.22_0.008_260)] pt-8 mt-4">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
              <div>
                <div className="font-mono text-xs text-[oklch(0.40_0.008_80)] mb-1">
                  Elevate Foundry · Ryan Barrett
                </div>
                <div className="font-mono text-xs text-[oklch(0.30_0.008_80)]">
                  Salt Lake City, UT · app.realquick.io
                </div>
              </div>
              <div className="flex gap-4">
                <a
                  href="https://github.com/elevate-foundry/sal-auth"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-xs text-[oklch(0.40_0.008_80)] hover:text-[oklch(0.75_0.16_65)] border-none transition-colors"
                >
                  sal-auth ↗
                </a>
                <a
                  href="https://elevate-foundry.github.io/bbid-challenge"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-xs text-[oklch(0.40_0.008_80)] hover:text-[oklch(0.75_0.16_65)] border-none transition-colors"
                >
                  live demo ↗
                </a>
              </div>
            </div>
          </footer>
        </main>
      </div>
    </div>
  );
}
