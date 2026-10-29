# Event attribution module specification

Status: design proposal. A trained, evaluated attribution model is required before implementing an enrichment module.

The proposed module ranks threat actor hypotheses for an analyst using an explicitly supplied MISP event. The complete event context is required because a single observable is insufficient to support a reliable attribution claim.

## Inputs

Accept an event UUID, selected attributes and objects, ATT&CK technique references, and existing galaxy associations. Define which event fields form model features. Exclude pre-existing actor labels from prediction inputs when those same labels are training targets. Record which features were available and which were missing.

## Model requirements

Supply the model artifact, version, license, training-data provenance, feature schema and supported actor vocabulary. Training and evaluation must use separate events and time ranges; events from one campaign must not straddle those sets. Measure precision and coverage for each actor and test the abstention threshold on held-out campaigns. Probability claims require a documented calibration evaluation.

## Output

Return a referenced annotation containing ranked candidates, scores, evidence features, model version, evaluation version and observation time. Include a no-supported-attribution outcome. Model scores must be labelled as scores unless calibrated as probabilities. Keep source metadata and detection flags. Analysts review the hypotheses before applying any actor galaxy association.

## Execution

Prefer local inference with no training or model download during enrichment. Mark the implementation as internal only when it performs no external lookup or transfer. Any optional remote service must declare external data use and follow MISP marking policy. Bound model size, event size and inference time. Do not load untrusted serialized Python objects from request data or configurable URLs.

## Acceptance criteria

Demonstrate deterministic feature extraction, model compatibility checks, missing-context handling and abstention for out-of-vocabulary activity. Supply held-out evaluation metrics, a labelled fixture set and leakage checks. Verify that results preserve event provenance and never automatically assert actor attribution. Define a maintainer and model update process before enabling the module.
