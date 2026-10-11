"""The supported algorithms, including optional reference implementations."""
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Method:
    name: str
    description: str
    lossy: bool = False
    remote: bool = False
    requirements: str = ""


METHODS = {
    m.name: m for m in (
        Method("off", "Unchanged baseline"),
        Method("structure", "Reversible JSON tables, log templates, repeats and snapshot deltas"),
        Method("caveman", "Local Caveman prose rules", True),
        Method("extract", "Structure plus task-conditioned verbatim excerpts", True),
        Method("jev", "Structure plus TypeSafe paragraph selection", True, True, "TYPESAFE_API_KEY"),
        Method("kimi", "Structure plus Kimi paragraph selection", True, True, "KIMI_API_KEY"),
        Method("llmlingua2", "Structure plus local LLMLingua-2 token deletion", True, False,
               "compression extra and local LLMLingua-2 model_path"),
        Method("llm_rewrite", "Protected free rewriting used by the historical Kimi experiment", True, True,
               "KIMI_API_KEY"),
        Method("caveman_llm", "Caveman prompt with an accountable OpenAI-compatible client", True, True,
               "KIMI_API_KEY (or injected chat client); Caveman reference_path"),
        Method("caveman_nlp", "Upstream Caveman spaCy token filtering", True, False,
               "nlp extra, installed spaCy model and Caveman reference_path"),
        Method("caveman_mlm", "Upstream Caveman masked-token predictability filtering", True, False,
               "nlp + compression extras, local RoBERTa and spaCy models, Caveman reference_path"),
        Method("headroom", "Headroom ContentRouter: JSON, logs, search, tables, configs and HTML", True, False,
               "headroom extra (native core); optional injected ContentRouter"),
        Method("generic_agent", "GenericAgent-style tag shortening and whole-turn history window", True),
        Method("auto", "Structure then lexical extraction, with reread feedback", True),
    )
}
ALIASES = {"hybrid": "structure"}


def available_methods() -> list[dict]:
    """List capabilities, not a claim that optional dependencies are installed."""
    return [asdict(m) for m in METHODS.values()]


def canonical_method(name: str) -> str:
    name = ALIASES.get(name, name)
    if name not in METHODS:
        raise ValueError(f"Unknown method {name!r}; choose from {', '.join(METHODS)}")
    return name
