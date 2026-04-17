# Tier 2 Check Harness Rubric

24 checks across 4 dimensions, 25 pts each, 100 total.

## CORRECTNESS (25 pts)
  check_circuit_compiles           (4)  circom -> r1cs succeeds
  check_witness_generation         (3)  input.json -> witness.wtns succeeds
  check_proof_roundtrip            (4)  prove + verify roundtrip
  check_contract_compiles          (3)  npx hardhat compile
  check_existing_tests_pass        (5)  104+7 existing tests still green (REGRESSION)
  check_new_tests_pass             (4)  experiment's own tests pass
  check_no_shared_modified         (2)  HARD FAIL: no files outside experiments/

## COMPLETENESS (25 pts)
  check_circuit_exists             (3)  new/modified circuit present
  check_contract_exists            (3)  new/modified contract present
  check_spec_section_exists        (4)  spec with normative language
  check_test_vectors_exist         (4)  JSON test vectors present
  check_cip_feature_implemented    (6)  LLM judge: CIP feature implemented?
  check_constraint_budget          (5)  circuit <= 80k constraints

## ADOPTION (25 pts)
  check_sdk_module_exists          (4)  TypeScript or Python SDK module
  check_sdk_types                  (3)  exported types/type hints
  check_sdk_test_exists            (3)  SDK unit test
  check_framework_integration      (4)  LangChain/CrewAI/AutoGen present
  check_tthw_estimate              (5)  LLM: lines to hello-world?
  check_error_messages             (3)  custom error types
  check_docs_exist                 (3)  README or usage docs

## STANDARDS (25 pts)
  check_normative_language         (5)  MUST/SHOULD/MAY present
  check_test_vectors_conformance   (5)  machine-parseable JSON vectors
  check_interop_evidence           (5)  multi-chain/prover evidence
  check_spec_completeness_llm     (10)  LLM judge: spec quality

## Hard Fails
Hard fails (total -> 0):
  - check_no_shared_modified: any file modified outside experiments/
  - check_circuit_compiles: circom compilation failure
  - check_existing_tests_pass: any regression in the 104+7 baseline tests
