"""Chinese NLP backend configuration (explicit, no English fallback).

The AnalyzerEngine is built with ``supported_languages=["zh"]`` and a
custom ``RecognizerRegistry`` that contains only the spaCy zh NER
recogniser. presidio's built-in (English-centric) recognisers are
never loaded: ``AnalyzerEngine.__init__`` only calls
``load_predefined_recognizers`` when the registry is empty
(presidio 2.2.364 removed the ``default_recognizers`` parameter).

The NER recogniser is restricted to PERSON / GPE / LOC / ORG via an
identity label mapping and an explicit ignore list: DATE / TIME /
MONEY / PERCENT / CARDINAL / NORP ... are deliberately NOT adopted —
the gateway detects identity data, not document content semantics.

spaCy Chinese produces no lemmas (docs/DECISIONS.md), so presidio's
LemmaContextAwareEnhancer cannot match context words; it is replaced
by an explicit no-op enhancer. Column-header context boosting lives in
``context.py`` instead.
"""

from __future__ import annotations

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.context_aware_enhancers import ContextAwareEnhancer
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.recognizer_registry import RecognizerRegistry

from secure_ai_gateway.models import EntityType

# spaCy labels -> gateway entity types. The NER recogniser emits the
# RAW spaCy label as the entity type (identity mapping below), so the
# map keys are spaCy labels, not presidio entity names.
NER_LABEL_MAP: dict[str, EntityType] = {
    "PERSON": EntityType.PERSON,
    "GPE": EntityType.LOCATION,
    "LOC": EntityType.LOCATION,
    "ORG": EntityType.ORGANIZATION,
}

NER_ENTITY_TYPES = frozenset(NER_LABEL_MAP.values())

# The presidio recogniser class name (used to source-label spans).
NER_RECOGNIZER_NAME = "SpacyRecognizer"

# spaCy labels the gateway does NOT adopt. presidio filters NER output
# against the mapping VALUES, so restricting the mapping to the four
# adopted labels would be enough; the ignore list is explicit defence
# (e.g. a model emitting an adopted-looking label it should not).
_NON_ADOPTED_LABELS = (
    "DATE", "TIME", "PERCENT", "MONEY", "QUANTITY", "ORDINAL",
    "CARDINAL", "NORP", "FAC", "EVENT", "LAW", "PRODUCT",
    "WORK_OF_ART", "LANGUAGE", "DATE_TIME", "NRP", "AGE", "ID",
)

_MODEL_CONFIG = {
    "nlp_engine_name": "spacy",
    "models": [
        {"lang_code": "zh", "model_name": "zh_core_web_lg"},
    ],
    # Identity mapping: presidio keeps a label only if the label is in
    # the mapping VALUES, and emits the label as the entity type.
    "ner_model_configuration": {
        "model_to_presidio_entity_mapping": {
            "PER": "PERSON",
            "PERSON": "PERSON",
            "GPE": "GPE",
            "LOC": "LOC",
            "ORG": "ORG",
        },
        "labels_to_ignore": _NON_ADOPTED_LABELS,
    },
}


class _NoopContextAwareEnhancer(ContextAwareEnhancer):
    """zh has no lemmas: presidio context enhancement is a no-op.

    Column-header context boosting lives in ``context.py``.
    """

    def __init__(self) -> None:
        super().__init__(
            context_similarity_factor=0.0,
            min_score_with_context_similarity=0.0,
            context_prefix_count=0,
            context_suffix_count=0,
        )

    def enhance_using_context(
        self,
        text: str,
        raw_results,
        nlp_artifacts,
        recognizers,
        context=None,
    ):
        return list(raw_results)


def build_zh_nlp_engine():
    """Create the spaCy zh engine (loads zh_core_web_lg, ~575MB)."""
    provider = NlpEngineProvider(conf_file=None, nlp_configuration=_MODEL_CONFIG)
    return provider.create_engine()


def build_analyzer(
    nlp_engine=None,
    default_score_threshold: float = 0.4,
) -> AnalyzerEngine:
    """Build the zh-only AnalyzerEngine.

    ``default_score_threshold`` is deliberately low (0.4): per-entity
    calibrated thresholds are applied by the gateway engine AFTER
    analysis (docs/BENCHMARK.md §5.2).

    presidio 2.2.364 constructor notes: ``default_recognizers`` and
    ``allow_overlap`` no longer exist. Overlapping spans of DIFFERENT
    types are kept by default (``remove_duplicates`` only collapses
    same-type containment), which is what the gateway resolution layer
    expects.
    """
    engine = nlp_engine if nlp_engine is not None else build_zh_nlp_engine()
    if not engine.is_loaded():
        engine.load()
    registry = RecognizerRegistry(supported_languages=["zh"])
    # Adds exactly one recogniser: the spaCy zh NER recogniser. The
    # registry is therefore non-empty, so presidio never loads its
    # predefined (English-centric) recognisers.
    registry.add_nlp_recognizer(nlp_engine=engine)
    return AnalyzerEngine(
        registry=registry,
        nlp_engine=engine,
        supported_languages=["zh"],
        default_score_threshold=default_score_threshold,
        context_aware_enhancer=_NoopContextAwareEnhancer(),
    )


def assert_zh_only(engine: AnalyzerEngine) -> None:
    """Guard: the engine must never fall back to English NER."""
    # presidio 2.2.364 exposes the languages as an attribute.
    languages = list(engine.supported_languages)
    if languages != ["zh"]:
        raise RuntimeError(
            f"engine supports unexpected languages: {languages}"
        )
    non_zh = [
        r.name
        for r in engine.registry.recognizers
        if r.supported_language != "zh"
    ]
    if non_zh:
        raise RuntimeError(
            f"non-zh recognisers registered: {sorted(non_zh)}"
        )
    zh_recognizers = engine.registry.get_recognizers(
        language="zh", all_fields=True
    )
    names = {r.name for r in zh_recognizers}
    if NER_RECOGNIZER_NAME not in names:
        raise RuntimeError(
            f"no {NER_RECOGNIZER_NAME} registered for zh: {sorted(names)}"
        )
