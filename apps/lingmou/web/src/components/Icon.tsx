import type { ReactNode } from "react";

export type IconName =
  | "agent"
  | "agents"
  | "arrowDown"
  | "arrowRight"
  | "attention"
  | "chevronDown"
  | "close"
  | "database"
  | "eye"
  | "file"
  | "history"
  | "graph"
  | "inspect"
  | "link"
  | "lock"
  | "menu"
  | "plan"
  | "pause"
  | "play"
  | "question"
  | "reply"
  | "refresh"
  | "search"
  | "session"
  | "shield"
  | "spark"
  | "step"
  | "stop"
  | "summary"
  | "syscall"
  | "terminal"
  | "tool"
  | "network"
  | "user"
  | "warning";

const paths: Record<IconName, ReactNode> = {
  agent: <><path d="M7.5 9.5a4.5 4.5 0 0 1 9 0v2.25a4.5 4.5 0 0 1-9 0Z" /><path d="M9 18.25h6M12 16.25v2" /><path d="M5.5 10.5H4m16 0h-1.5" /><circle cx="10" cy="11" r=".55" fill="currentColor" stroke="none" /><circle cx="14" cy="11" r=".55" fill="currentColor" stroke="none" /></>,
  agents: <><circle cx="9" cy="9" r="3" /><path d="M3.75 18c.55-2.7 2.3-4.1 5.25-4.1s4.7 1.4 5.25 4.1" /><path d="M15.5 7.2a2.6 2.6 0 0 1 0 4.95M16.3 14.25c2.15.3 3.45 1.55 3.95 3.75" /></>,
  arrowDown: <path d="m7 10 5 5 5-5" />,
  arrowRight: <path d="m9 7 5 5-5 5" />,
  attention: <><path d="M12 3.5 21 19H3Z" /><path d="M12 8v5" /><path d="M12 16.2v.1" /></>,
  chevronDown: <path d="m7 9.5 5 5 5-5" />,
  close: <><path d="m7 7 10 10M17 7 7 17" /></>,
  database: <><ellipse cx="12" cy="5.5" rx="7.5" ry="3" /><path d="M4.5 5.5v6c0 1.65 3.35 3 7.5 3s7.5-1.35 7.5-3v-6M4.5 11.5v6c0 1.65 3.35 3 7.5 3s7.5-1.35 7.5-3v-6" /></>,
  eye: <><path d="M3 12s3.3-5.5 9-5.5 9 5.5 9 5.5-3.3 5.5-9 5.5S3 12 3 12Z" /><circle cx="12" cy="12" r="2.5" /></>,
  file: <><path d="M6.5 3.5h7l4 4V20H6.5Z" /><path d="M13.5 3.5v4h4M9 12h6M9 15.5h4.5" /></>,
  history: <><path d="M4.5 8.5V4.75M4.5 4.75h3.75" /><path d="M5.2 6.2A8 8 0 1 1 4 14" /><path d="M12 8v4.25l2.75 1.75" /></>,
  graph: <><circle cx="6" cy="6" r="2.25" /><circle cx="18" cy="8" r="2.25" /><circle cx="9" cy="18" r="2.25" /><path d="m8.15 6.35 7.7 1.3M7 8.05l1.45 7.8M16.7 9.85l-6.4 6.3" /></>,
  inspect: <><path d="M4 5h11v14H4Z" /><path d="M8 9h3M8 12h3M8 15h2" /><circle cx="16.5" cy="15.5" r="3" /><path d="m18.75 17.75 2 2" /></>,
  link: <><path d="m9.5 14.5-1 1a3.5 3.5 0 0 1-5-5l3-3a3.5 3.5 0 0 1 5 0" /><path d="m14.5 9.5 1-1a3.5 3.5 0 1 1 5 5l-3 3a3.5 3.5 0 0 1-5 0" /><path d="m8.5 15.5 7-7" /></>,
  lock: <><rect x="5" y="10" width="14" height="10" rx="2" /><path d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10M12 14v2.5" /></>,
  menu: <><path d="M5 7h14M5 12h14M5 17h14" /></>,
  plan: <><circle cx="7" cy="6" r="1.25" /><circle cx="7" cy="12" r="1.25" /><circle cx="7" cy="18" r="1.25" /><path d="M10.5 6H19M10.5 12H19M10.5 18H19" /></>,
  pause: <><path d="M9 7v10M15 7v10" /></>,
  play: <path d="m9 6 9 6-9 6Z" />,
  question: <><circle cx="12" cy="12" r="9" /><path d="M9.75 9a2.5 2.5 0 1 1 3.4 2.35c-.8.35-1.15.85-1.15 1.65" /><path d="M12 16.5v.1" /></>,
  reply: <><path d="M5 5.5h14v10H9l-4 3Z" /><path d="M8.5 9h7M8.5 12h5" /></>,
  refresh: <><path d="M19 8V4.5M19 4.5h-3.5" /><path d="M18.35 5.3A8 8 0 1 0 20 14" /></>,
  search: <><circle cx="10.5" cy="10.5" r="5.5" /><path d="m14.5 14.5 4 4" /></>,
  session: <><rect x="4" y="4" width="16" height="16" rx="3" /><path d="M8 8h8M8 12h8M8 16h5" /></>,
  shield: <><path d="M12 3.5 19 6v5.2c0 4.2-2.65 7.35-7 9.3-4.35-1.95-7-5.1-7-9.3V6Z" /><path d="m8.7 12 2.1 2.1 4.5-4.5" /></>,
  spark: <><path d="M12 3.5c.35 3.2 2.3 5.15 5.5 5.5-3.2.35-5.15 2.3-5.5 5.5-.35-3.2-2.3-5.15-5.5-5.5 3.2-.35 5.15-2.3 5.5-5.5Z" /><path d="M18.25 14.5c.15 1.45 1.05 2.35 2.5 2.5-1.45.15-2.35 1.05-2.5 2.5-.15-1.45-1.05-2.35-2.5-2.5 1.45-.15 2.35-1.05 2.5-2.5Z" /></>,
  step: <><circle cx="12" cy="12" r="8.5" /><path d="m9 12 2 2 4-4" /></>,
  stop: <rect x="6.5" y="6.5" width="11" height="11" rx="1.5" />,
  summary: <><path d="M6 4.5h12v15H6Z" /><path d="M9 8h6M9 11.5h6M9 15h4" /></>,
  syscall: <><path d="M4 7.5h3l1.6-3 3.1 15 2.2-11 1.8 5.5H20" /><path d="M4 20h16" /></>,
  terminal: <><rect x="3.5" y="5" width="17" height="14" rx="2.5" /><path d="m7.5 9 2.5 2.5L7.5 14M12.5 14H17" /></>,
  tool: <><path d="M14.9 5.2a4.25 4.25 0 0 0-5.55 5.55L4.4 15.7a2.2 2.2 0 1 0 3.1 3.1l4.95-4.95A4.25 4.25 0 0 0 18 8.3l-2.55 2.55-2.3-2.3Z" /></>,
  network: <><circle cx="12" cy="12" r="8.5" /><path d="M3.5 12h17M12 3.5c2.1 2.3 3.2 5.15 3.2 8.5s-1.1 6.2-3.2 8.5c-2.1-2.3-3.2-5.15-3.2-8.5S9.9 5.8 12 3.5Z" /></>,
  user: <><circle cx="12" cy="8.5" r="3.5" /><path d="M5.5 19c.65-3.4 2.8-5.1 6.5-5.1s5.85 1.7 6.5 5.1" /></>,
  warning: <><circle cx="12" cy="12" r="9" /><path d="M12 7.5v6" /><path d="M12 16.5v.1" /></>,
};

export function Icon({ name, size = 18, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      focusable="false"
      height={size}
      viewBox="0 0 24 24"
      width={size}
      fill="none"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="1.8"
    >
      {paths[name]}
    </svg>
  );
}
