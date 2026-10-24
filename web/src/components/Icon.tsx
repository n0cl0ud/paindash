const CIRCLE = "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z";
const SHIELD = "M12 21.5s7.5-3.6 7.5-9.5V5.3L12 2.5 4.5 5.3V12c0 5.9 7.5 9.5 7.5 9.5z";

const PATHS = {
  check: ["M20 6 9 17l-5-5"],
  close: ["M18 6 6 18", "M6 6l12 12"],
  alert: ["M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z", "M12 9v4", "M12 17h.01"],
  flame: [
    "M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.4-.5-2-1-3-1.1-2.1-.2-4 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.2.4-2.3 1-3a2.5 2.5 0 0 0 2.5 2.5z",
  ],
  deploy: ["M12 16V4", "m7 9 5-5 5 5", "M4 20h16"],
  removed: [CIRCLE, "M8 12h8"],
  scanOk: [CIRCLE, "m8.5 12 2.5 2.5 4.5-5"],
  scanFail: [CIRCLE, "m15 9-6 6", "m9 9 6 6"],
  vulnNew: [SHIELD, "M12 8v4.5", "M12 16h.01"],
  vulnFixed: [SHIELD, "m9 12 2 2 4-4"],
  database: [
    "M4 6c0 1.7 3.6 3 8 3s8-1.3 8-3-3.6-3-8-3-8 1.3-8 3z",
    "M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6",
    "M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6",
  ],
  external: ["M15 3h6v6", "M10 14 21 3", "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"],
  arrowRight: ["M5 12h14", "m13 6 6 6-6 6"],
  search: ["M18 11a7 7 0 1 1-14 0 7 7 0 0 1 14 0z", "m20.5 20.5-4.5-4.5"],
  refresh: ["M21 12a9 9 0 1 1-2.6-6.4L21 8", "M21 3v5h-5"],
  box: ["M21 8 12 3 3 8v8l9 5 9-5z", "M3 8l9 5 9-5", "M12 13v8"],
  chevronDown: ["m6 9 6 6 6-6"],
  shieldOff: [SHIELD, "m4 4 16 16"],
  undo: ["M9 14 4 9l5-5", "M4 9h10.5a5.5 5.5 0 0 1 0 11H11"],
  clock: [CIRCLE, "M12 7v5l3 2"],
  globe: [CIRCLE, "M3 12h18", "M12 3a13.5 13.5 0 0 1 0 18 13.5 13.5 0 0 1 0-18"],
  download: ["M12 3v12", "m7 10 5 5 5-5", "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"],
  terminal: ["M5 4h14a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z", "m7 9 3 3-3 3", "M13 15h4"],
  copy: ["M10 8h9a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-9a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2z", "M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"],
  github: [
    "M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.1-1.3-.3-2.5-1-3.5.3-1.2.3-2.4 0-3.5 0 0-1 0-3 1.5a10.3 10.3 0 0 0-5.5 0C6.5 2 5.5 2 5.5 2c-.3 1.1-.3 2.3 0 3.5A5.4 5.4 0 0 0 4.5 9c0 3.5 3 5.5 6 5.5-.4.5-.7 1.1-.8 1.7-.2.6-.2 1.2-.2 1.8v4",
    "M9 18c-4.5 2-5-2-7-2",
  ],
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name, className = "size-4" }: { name: IconName; className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      {PATHS[name].map((d) => (
        <path key={d} d={d} />
      ))}
    </svg>
  );
}
