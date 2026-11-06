import type { Severity } from "./overview.ts";

/** A severity's glyph: each level has its own shape and colour, so it reads without hue. */
export function Glyph(props: { severity: Severity }) {
  return (
    <svg class={`sev ${props.severity}`} viewBox="0 0 14 14" role="img" aria-label={props.severity}>
      {props.severity === "critical" ? (
        <>
          <path d="M7 1.2 13 12.3H1z" fill="currentColor" />
          <path
            d="M7 5.2v3.2M7 10.1v.1"
            stroke="#1a0d0d"
            stroke-width="1.5"
            stroke-linecap="round"
          />
        </>
      ) : props.severity === "high" ? (
        <path d="M7 1 13 7 7 13 1 7z" fill="currentColor" />
      ) : props.severity === "medium" ? (
        <>
          <circle cx="7" cy="7" r="5.2" fill="none" stroke="currentColor" stroke-width="2" />
          <path d="M7 1.8a5.2 5.2 0 0 1 0 10.4z" fill="currentColor" />
        </>
      ) : (
        <circle cx="7" cy="7" r="4.6" fill="none" stroke="currentColor" stroke-width="1.6" />
      )}
    </svg>
  );
}

type IconName =
  | "sweep"
  | "wrench"
  | "mac"
  | "repo"
  | "server"
  | "gear"
  | "check"
  | "done"
  | "wait"
  | "chev";

const PATHS: Record<IconName, string> = {
  sweep: "M13.5 8A5.5 5.5 0 1 1 11.9 4.1M13.5 2.5v3h-3",
  wrench:
    "M10.1 1.6a4 4 0 0 0-4.3 5.3L1.7 11a1.6 1.6 0 0 0 2.3 2.3l4.1-4.1a4 4 0 0 0 5.3-4.3L11.2 7.2 9.2 6.8 8.8 4.8z",
  mac: "M3 3.5h10a1.5 1.5 0 0 1 1.5 1.5v5.5A1.5 1.5 0 0 1 13 12H3a1.5 1.5 0 0 1-1.5-1.5V5A1.5 1.5 0 0 1 3 3.5zM5.5 14h5",
  repo: "M3.5 2.5h8a1 1 0 0 1 1 1v9.5h-8.5a1.5 1.5 0 0 1 0-3h8.5M3.5 2.5v9",
  server:
    "M3 2.5h10a1 1 0 0 1 1 1V6a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1zM3 9h10a1 1 0 0 1 1 1v2.5a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V10a1 1 0 0 1 1-1z",
  gear: "M8 5.8a2.2 2.2 0 1 0 0 4.4 2.2 2.2 0 0 0 0-4.4zM8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M3.4 12.6l1.4-1.4M11.2 4.8l1.4-1.4",
  check: "M3.5 8.4 6.6 11.4 12.5 4.8",
  done: "M5 8.2 7.1 10.2 11 5.9",
  wait: "M8 2.5a5.5 5.5 0 1 0 0 11 5.5 5.5 0 0 0 0-11z",
  chev: "M10 3.5 5.5 8l4.5 4.5",
};

/** A line icon, drawn in the current text colour. */
export function Icon(props: { name: IconName }) {
  return (
    <svg class={`icon ${props.name}`} viewBox="0 0 16 16" aria-hidden="true">
      {props.name === "done" ? <circle cx="8" cy="8" r="6.5" class="done-disc" /> : null}
      <path d={PATHS[props.name]} />
    </svg>
  );
}
