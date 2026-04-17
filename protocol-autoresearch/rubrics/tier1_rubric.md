# Tier 1 Candidate Rubric

4 dimensions, 0-25 each, total 100.

## ADOPTION (0-25)
  0-5:   No clear developer benefit; internal optimization only
  6-12:  Useful but devs could build it themselves in a day
  13-18: Saves real integration time; clear SDK improvement
  19-22: Developers would tweet about this; unblocks a common pattern
  23-25: "Shut up and take my npm install"; TTHW drops measurably

## STANDARDS (0-25)
  0-5:   Ad hoc protocol; no specification language
  6-12:  Has a spec section but no normative language
  13-18: Uses RFC 2119 keywords; test vectors included
  19-22: Interoperability proven (multiple chains or proving systems)
  23-25: Ready for IETF/W3C working draft submission

## COMPLETENESS (0-25)
  0-5:   Cosmetic change; no new protocol capability
  6-12:  Minor circuit/contract optimization
  13-18: Implements one CIP feature partially
  19-22: Implements one CIP feature fully
  23-25: Implements CIP feature AND extends to novel capability

## CORRECTNESS (0-25)
  0-5:   Introduces new soundness bugs; no tests
  6-12:  Tests pass but known issues not addressed
  13-18: Fixes a known bug AND adds tests
  19-22: Includes formal verification OR fuzz testing
  23-25: All known bugs fixed, formal properties stated, fuzz tested

## Verdicts
  promote:  total >= 75 AND all dims >= 15
  consider: 60-74
  drop:     < 60 OR any dim <= 8
