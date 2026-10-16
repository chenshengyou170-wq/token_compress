export type JsonValue = unknown;

export type ExplanationSource =
  | "deterministic_command_analysis"
  | "deterministic_file_change_analysis"
  | "tool_capability_registry"
  | "agent_plan"
  | "contextual_inference"
  | "os_observation"
  | "security_policy"
  | "codexscope_policy"
  | "codex_app_server"
  | "user_decision"
  | "conservative_fallback"
  | string;

export type ActivityEffects = {
  reads?: string[];
  writes?: string[];
  network?: string[];
  processes?: string[];
  external_write?: boolean | null;
};

export type ActivityRisk = {
  level?: string;
  reasons?: string[];
  basis?: string;
  policy_basis?: string;
  matched_rules?: unknown[];
  blocking_rule?: string;
  policy_id?: string;
  policy_mode?: string;
  policy_stage?: string;
  policy_result?: string;
};

export type PolicyBlockSummary = {
  schema_version?: string;
  policy_id?: string;
  policy_name?: string;
  headline?: string;
  summary?: string;
  reason?: string;
  result_summary?: string;
  next_step?: string;
  technical_reasons?: string[];
};

export type ActivityExplanation = {
  schema_version?: string;
  headline?: string;
  action?: string;
  description?: string;
  purpose?: {
    text?: string;
    source?: ExplanationSource;
    confidence?: string;
  };
  effects?: ActivityEffects;
  risk?: ActivityRisk;
  result?: {
    status?: string;
    summary?: string;
    exit_code?: number | null;
    duration_ms?: number | null;
    output_lines?: number;
    decision?: string;
    operations?: string[];
  };
  tool?: {
    server?: string | null;
    name?: string;
    capability?: string;
    side_effects_registered?: boolean;
    non_sensitive_arguments?: unknown;
  };
  sources?: ExplanationSource[];
  suboperations?: Array<{
    action?: string;
    command?: string;
    operator?: string | null;
    description?: string;
    effects?: ActivityEffects;
    risk?: ActivityRisk;
    recognized?: boolean;
  }>;
  policy_summary?: PolicyBlockSummary;
  conservative_fallback?: boolean;
  cwd?: string | null;
};

export type EvidenceObservation = {
  kind?: string;
  label?: string;
  source?: ExplanationSource;
  turn_id?: string | null;
  item_id?: string | null;
  pid?: number | string | null;
  ppid?: number | string | null;
  observed_at?: number | null;
  file_path?: string | null;
  network_target?: string | null;
  syscall?: string | null;
  correlation_confidence?: string;
  policy_id?: string | null;
  blocking_rule?: string | null;
  matched_rules?: unknown[];
  device?: number | null;
  inode?: number | null;
  content_sha256?: string | null;
  git_blob?: string | null;
};

export type FileSnapshot = {
  path: string;
  scope: string;
  accesses: string[];
  sources: string[];
  confidence_tier: ConfidenceTier;
  observed_at: number;
  observed_from?: number;
  observed_to?: number;
  processes?: Array<{
    pid?: number | string | null;
    ppid?: number | string | null;
    source?: string;
  }>;
  line_ranges?: Array<Record<string, unknown>>;
  device?: number | null;
  inode?: number | null;
  mode?: number | null;
  size?: number | null;
  mtime_ns?: number | null;
  content_sha256?: string | null;
  git_blob?: string | null;
  capture_completeness: string;
  identity_id: string;
  identity_basis: string;
  version_id?: string | null;
  sensitivity_labels?: string[];
};

export type ActivityEvidence = {
  schema_version?: string;
  availability?: string;
  completeness?: string;
  summary?: string;
  observations?: EvidenceObservation[];
  negative_observations?: Array<{
    label?: string;
    source?: ExplanationSource;
    scope?: string;
  }>;
  correlation?: {
    turn_id?: string | null;
    item_id?: string | null;
    pid?: number | string | null;
    ppid?: number | string | null;
    started_at?: number | null;
    ended_at?: number | null;
    source?: string | null;
    confidence?: string;
  };
  os_trace?: {
    status?: string;
    backend?: string | null;
    trace_prefix?: string | null;
    file_pattern?: string | null;
  };
};

export type ActivityStep = {
  id?: string;
  index?: number;
  title?: string;
  status?: string;
  source?: string;
};

export type WorkbenchEvent = {
  seq: number;
  event_id: string;
  occurred_at: number;
  kind: string;
  source: string;
  status: string;
  thread_id?: string | null;
  turn_id?: string | null;
  item_id?: string | null;
  title: string;
  summary: JsonValue;
  payload: Record<string, unknown> | JsonValue;
  explanation?: ActivityExplanation;
  evidence?: ActivityEvidence;
  step?: ActivityStep;
  file_snapshots?: FileSnapshot[];
  privacy?: {
    credentials?: string;
    conversation_persisted?: boolean;
  };
};

export type Interaction = {
  id: string;
  kind: "approval" | "user_input";
  method: string;
  created_at?: number;
  thread_id?: string | null;
  turn_id?: string | null;
  item_id?: string | null;
  command?: string;
  cwd?: string;
  reason?: string;
  file_changes?: unknown;
  permissions?: unknown;
  questions?: Array<{
    id: string;
    header?: string;
    question: string;
    options?: Array<{ label: string; description?: string }>;
    isSecret?: boolean;
  }>;
  risk?: ActivityRisk;
  explanation?: ActivityExplanation;
  evidence?: ActivityEvidence;
  choices?: string[];
};

export type WorkbenchTask = {
  goal?: string | null;
  started_at?: number | null;
  current_step?: ActivityStep | null;
  steps?: ActivityStep[];
  active_command?: {
    item_id?: string | null;
    headline?: string;
    command?: string;
    started_at?: number;
  } | null;
};

export type WorkbenchState = {
  agent_backend?: "codex" | "codebuddy" | string;
  active_scenario?: WorkBuddyScenario | null;
  mcp_gateway_status?: {
    status?: string;
    scenario_id?: string;
    sandbox_id?: string;
    endpoint?: string;
    transport?: string;
    updated_at?: number;
  };
  connected: boolean;
  connection_error?: string | null;
  workspace: string;
  run_dir: string;
  thread_id?: string | null;
  active_turn_id?: string | null;
  turn_status: string;
  model?: string | null;
  approval_policy: string;
  sandbox: string;
  security_mode: string;
  policy_transition?: boolean;
  policy_error?: string | null;
  policy_constraint?: { summary: string; status: string; denied_paths: string[] } | null;
  last_seq: number;
  privacy: {
    credentials: string;
    conversation_persisted: boolean;
    forensic_context_encrypted?: boolean;
  };
  history?: {
    available: boolean;
    run_id?: string | null;
    project_root?: string | null;
    index_path?: string | null;
    error?: string | null;
    source_of_truth?: string;
  };
  pending_interactions: Interaction[];
  task?: WorkbenchTask;
  live_security?: {
    run_id?: string;
    activity?: string;
    monitor?: {
      os_audit?: string;
      file_audit?: string;
    };
    enforcement?: { state?: string; label?: string; source?: string };
    summary?: {
      tools?: number;
      commands?: number;
      file_events?: number;
      blocked_events_visible?: number;
      pending_approvals?: number;
      syscalls?: number;
    };
  };
};

export type WorkBuddyScenario = {
  id: string;
  slug: string;
  title: string;
  category: string;
  phase: "initial" | "planned" | string;
  scenario_type: "fault_injection" | string;
  runnable: boolean;
  fixed_seed: string;
  default_prompt: string;
  tool_path: string[];
  fault_injection: string;
  expected_control: string;
  final_business_state: string;
  expected_policy_ids: string[];
  recovery: string;
  result_summary: string;
  availability: "available" | "planned" | "agent_unavailable" | "restart_required" | "workbuddy_start_required" | string;
  availability_reason?: string | null;
  launch_url?: string | null;
};

export type ScenarioCatalog = {
  schema_version: string;
  total: number;
  runnable: number;
  launched?: number;
  agent_backend: string;
  launch_hint?: string | null;
  scenarios: WorkBuddyScenario[];
};

export type FeedFilter = "all" | "needs_action" | "changes" | "tools" | "risk";

export type SyscallAgentItem = {
  item_id: string;
  event_id?: string | null;
  turn_id?: string | null;
  title?: string | null;
  confidence_tier: "fact" | "strong" | "candidate" | string;
  basis: string;
};

export type SyscallEvent = {
  seq: number;
  wall_time_ns: number;
  monotonic_ns?: number | null;
  pid?: number | null;
  tid?: number | null;
  ppid?: number | null;
  comm?: string | null;
  syscall: string;
  category?: string | null;
  access?: string | null;
  path?: string | null;
  path_scope?: string | null;
  fd?: number | null;
  bytes?: number | null;
  endpoint?: {
    family?: string;
    address?: string;
    port?: number;
    path?: string;
  } | null;
  endpoint_text?: string | null;
  result?: unknown;
  errno?: string | null;
  success?: boolean | null;
  duration_ns?: number | null;
  arguments?: string | null;
  synthetic?: boolean;
  agent_item?: SyscallAgentItem;
};

export type SyscallAssociation = {
  item_id?: string;
  event_id?: string | null;
  turn_id?: string | null;
  title?: string | null;
  pid?: number | null;
  started_at?: number | null;
  ended_at?: number | null;
  availability?: string;
  confidence?: string;
  reason?: string;
  pids?: number[];
};

export type SyscallQueryResponse = {
  schema_version: string;
  items: SyscallEvent[];
  total: number | null;
  view: {
    mode: "behavior" | "key" | "all" | string;
    matching_raw: number | null;
    shown: number | null;
    filtered_or_grouped: number | null;
    rollup_window_seconds?: number | null;
  };
  association?: SyscallAssociation | null;
  page: {
    limit: number;
    order: "asc" | "desc";
    has_more: boolean;
    next_before_seq?: number | null;
    next_after_seq?: number | null;
  };
  index: {
    last_seq: number;
    indexed_events: number;
  };
};

export type SyscallStatus = {
  schema_version: string;
  run_id?: string | null;
  scope: string;
  scope_label: string;
  profile: "behavior" | "focused" | "full" | string;
  profile_label: string;
  collection: {
    enabled: boolean;
    requested: string;
    status: string;
    known_loss: boolean;
    captured_events: number;
    observed_events?: number;
    filtered_events?: number;
    filtered_noise?: number;
    filtered_repeats?: number;
    rate_per_second: number;
    raw_bytes: number;
    dropped: number;
    parse_errors: number;
    reader_error?: unknown;
    limit_reached: boolean;
    max_events?: number | null;
    max_bytes?: number | null;
    content_capture: false;
    exec_argv_capture: false;
  };
  index: {
    indexed_events: number;
    last_seq: number;
    lag_events: number;
    partial_line: boolean;
    parse_errors: number;
    syncing: boolean;
    last_error?: string | null;
  };
  summary: {
    total: number;
    pids: number;
    failed: number;
    network: number;
    writes: number;
    first_event_ns?: number | null;
    last_event_ns?: number | null;
    categories: Record<string, number>;
    top_syscalls: Array<{ name: string; count: number }>;
  };
  privacy: {
    buffer_payloads: string;
    exec_arguments: string;
    credentials: string;
  };
};

export type SyscallProcess = {
  pid: number;
  ppid?: number | null;
  comm?: string | null;
  total: number;
  first_seen_ns: number;
  last_seen_ns: number;
  failed: number;
  network: number;
  depth: number;
  is_root: boolean;
};

export type SyscallDensityBucket = {
  index: number;
  from_ns: number;
  to_ns: number;
  total: number;
  failed: number;
  network: number;
  writes: number;
};

export type PolicyCatalogEntry = {
  id: string;
  name: string;
  risk_level: string;
  action: string;
  enabled: boolean;
  mode: "observe" | "review" | "deny" | string;
  stage: string;
  evidence_source: string;
  enforceable_now: boolean;
  stateful: boolean;
  tested: string;
  block_headline?: string | null;
  block_summary?: string | null;
  safe_next_step?: string | null;
};

export type PolicyCatalogGroup = {
  id: string;
  name: string;
  description: string;
  policies: PolicyCatalogEntry[];
};

export type PolicyCatalog = {
  schema_version: string;
  total: number;
  groups: PolicyCatalogGroup[];
};

export type ActivityGroup = {
  id: string;
  step: ActivityStep;
  events: WorkbenchEvent[];
};

export type ConfidenceTier = "fact" | "strong" | "candidate" | "unproven";

export type HistoryRun = {
  run_id: string;
  run_dir: string;
  started_at?: number | null;
  ended_at?: number | null;
  thread_count: number;
  event_count: number;
  anchor_count: number;
  last_indexed_seq: number;
};

export type HistoryResponse = {
  schema_version: string;
  project_id: string;
  index_path: string;
  runs: HistoryRun[];
  status: NonNullable<WorkbenchState["history"]>;
};

export type InvestigationListItem = {
  id: string;
  anchor_event_key: string;
  run_id: string;
  event_id: string;
  occurred_at: number;
  thread_id?: string | null;
  turn_id?: string | null;
  item_id?: string | null;
  title: string;
  summary: string;
  risk_level: string;
  status: string;
  evidence_availability: string;
  blocked: boolean;
  action?: string | null;
  policy_id?: string | null;
  blocking_rule?: string | null;
};

export type InvestigationListResponse = {
  schema_version: string;
  project_id: string;
  items: InvestigationListItem[];
  total: number;
};

export type InvestigationNode = {
  id: string;
  node_type: "event" | "attempt" | "time_gap" | string;
  stage: InvestigationStage;
  stage_memberships?: InvestigationStage[];
  title: string;
  summary: string;
  occurred_at: number;
  run_id: string;
  event_id?: string | null;
  thread_id?: string | null;
  turn_id?: string | null;
  item_id?: string | null;
  kind?: string;
  status?: string;
  risk_level?: string;
  confidence_tier: ConfidenceTier;
  confidence: number;
  fact_scope: string;
  evidence_availability: string;
  evidence_completeness: string;
  file_snapshots: FileSnapshot[];
  entities?: InvestigationEntity[];
  sensitive: boolean;
  chain_relevance: number;
  event: WorkbenchEvent;
};

export type InvestigationEntity = {
  event_key: string;
  entity_type: "network" | "process" | "executable" | "policy" | string;
  entity_key: string;
  scope_key: string;
  role: string;
  display_value: string;
  source: string;
  confidence_tier: ConfidenceTier;
  observed_at: number;
  attributes: Record<string, unknown>;
};

export type InvestigationStage = "entry" | "access" | "collect" | "transform" | "egress" | "outcome";

export type InvestigationEdge = {
  id: string;
  source: string;
  target: string;
  relation: string;
  confidence_tier: ConfidenceTier;
  confidence: number;
  evidence: string;
  causal: boolean;
};

export type InvestigationDetail = {
  schema_version: string;
  id: string;
  project_id: string;
  anchor_event_key: string;
  created_at: number;
  summary: {
    earliest_trigger: InvestigationAnswer;
    key_asset: InvestigationAnswer;
    dangerous_outlet: InvestigationAnswer;
    final_outcome: InvestigationAnswer & { status?: string };
  };
  chain_score: number;
  stage_coverage: number;
  stages: Array<{
    id: InvestigationStage;
    status: "present" | "missing";
    node_id?: string | null;
    confidence_tier: ConfidenceTier;
  }>;
  minimal_chain: InvestigationNode[];
  minimal_edges: InvestigationEdge[];
  timeline: Array<InvestigationNode | InvestigationTimeGap>;
  evidence_gaps: Array<{
    node_id: string;
    title: string;
    detail: string;
    impact: string;
  }>;
  context_capsules: Array<{
    schema_version: string;
    run_id: string;
    thread_id: string;
    turn_id: string;
    event_count: number;
    prompt: string;
    plan_steps: string[];
    reads: string[];
    writes: string[];
    outcomes: string[];
    privacy: { credentials: string; conversation: string };
  }>;
  graph: {
    nodes: InvestigationNode[];
    edges: InvestigationEdge[];
    node_count: number;
    edge_count: number;
    entity_count?: number;
  };
  privacy: {
    credentials: string;
    file_contents: string;
    file_versions: string;
    conversation_default: string;
    forensic_context_available: boolean;
  };
  proof_boundary: string[];
};

export type InvestigationAnswer = {
  value: string;
  detail: string;
  confidence_tier: ConfidenceTier;
  occurred_at?: number | null;
};

export type InvestigationTimeGap = {
  id: string;
  node_type: "time_gap";
  duration_seconds: number;
  occurred_at: number;
  title: string;
  summary: string;
};

export type HarnessLayer = {
  id: "protocol" | "harness" | "os" | "filesystem";
  label: string;
  status: string;
  records: number;
  observed_records?: number;
  detail: string;
};

export type HarnessOperation = {
  name: string;
  label: string;
  category: string;
  record_kind: "span" | "event";
  count: number;
  errors: number;
  average_duration_ms?: number | null;
  last_received_at?: string | null;
};

export type HarnessTraceRecord = {
  id: string;
  received_at?: string | null;
  record_kind: "span" | "event";
  name: string;
  label: string;
  category: string;
  duration_ms?: number | null;
  outcome: "success" | "error" | string;
  attributes: Record<string, string | number | boolean>;
};

export type HarnessMonitorSnapshot = {
  schema_version: string;
  run_id?: string | null;
  run_status: string;
  refreshed_at: string;
  status: string;
  telemetry: {
    requested: string;
    enabled: boolean;
    status: string;
    backend?: string | null;
    transport?: string | null;
    collector_scope: string;
    content_capture: boolean;
    unknown_attributes_persisted: boolean;
    max_events?: number | null;
    known_loss: boolean;
    parse_errors: number;
    dropped_records: number;
  };
  summary: {
    records: number;
    spans: number;
    events: number;
    unique_operations: number;
    last_received_at?: string | null;
    protocol_messages: number;
    os_events: number;
    os_observed_events: number;
    filesystem_events: number;
  };
  layers: HarnessLayer[];
  operations: HarnessOperation[];
  recent: HarnessTraceRecord[];
  privacy: {
    prompts: string;
    tool_arguments: string;
    tool_output: string;
    credentials: string;
    content_capture: boolean;
  };
  proof_boundary: string[];
};

export type TokenComponentUsage = {
  id: string; label: string; protected: boolean;
  before: number | null; after: number | null; saved: number | null;
  requests: number; compressed_requests: number;
};

export type ToolTokenUsage = {
  name: string; before: number | null; after: number | null; saved: number | null;
  definition_before: number | null; definition_after: number | null;
  call_before: number | null; call_after: number | null;
  result_before: number | null; result_after: number | null;
};

export type TokenUsage = {
  schema_version: string;
  capture_state: "live" | "finished" | "not_connected";
  relay_enabled: boolean;
  configurable: boolean;
  mode: string;
  requested_mode: string;
  processing?: boolean;
  local: {
    before: number | null; after: number | null; saved: number | null;
    savings_percent: number | null; requests: number; compressed_requests: number;
    current_input: number | null; current_input_quality: string;
  };
  official: {
    source: string; input_tokens: number | null; output_tokens: number | null;
    total_tokens: number | null; cached_input_tokens: number | null;
    compression_tokens: number | null; known_compression_tokens: number;
    missing_compression_calls: number; measured_requests: number;
    missing_requests: number; complete: boolean;
  };
  recent_requests: Array<{
    request_id: string; status: string; before: number | null; after: number | null;
    official_input: number | null; official_output: number | null;
  }>;
  output?: { responses?: number; before?: number; after?: number; saved?: number; pending?: boolean; billing_reduction: false; source: "post_generation" };
  methods?: Array<{ id: string; label: string; attempted: number; accepted: number; saved: number; unavailable: number; rejected: number }>;
  breakdown?: {
    source: string; requests: number; incomplete_requests: number;
    components: TokenComponentUsage[]; tools: ToolTokenUsage[];
    latest: {
      request_id: string | null; tokenizer: string | null; complete: boolean;
      components: TokenComponentUsage[]; tools: ToolTokenUsage[];
    };
  };
};
