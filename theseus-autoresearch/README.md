# Theseus Partnership Discovery Loop

Partnership discovery loop for Bolyra x Theseus Network. Identifies integration opportunities where Bolyra serves as the identity/authorization layer for Theseus's agent-native L1.

## Usage

```bash
python run_loop.py --max-iterations 8 --model opus
```

## Output

- `output/integration_board.json` — scored and ranked integration proposals
- `output/integration_board.md` — human-readable summary

## Scoring

4 dimensions, each 0-25 (total 0-100):

| Dimension | What It Measures |
|---|---|
| Agent Need | How urgently do autonomous agents on Theseus need this? |
| ZKP Edge | Does ZKP provide a meaningful advantage over conventional crypto? |
| Primitive Readiness | Can Bolyra serve this with existing circuits/contracts/SDK? |
| Partnership Leverage | Does this create mutual dependency between Bolyra and Theseus? |

Verdicts: PROMOTE (>= 70, all dims >= 12), CONSIDER (>= 50, no dim <= 5), DROP (< 50 or any dim <= 5).

## Structure

```
theseus-autoresearch/
├── program.md              # Loop specification
├── theseus_context.md       # What we know about Theseus
├── context/                 # Strategic priors and constraints
├── personas/                # 6 research personas
├── rubrics/                 # Tier 1/2/3 scoring rubrics
├── sources/                 # Search query registry
├── history/                 # Iteration history + plateau detection
├── output/                  # Final scored boards
├── scripts/                 # Automation scripts
├── runs/                    # Per-iteration raw data
├── reports/                 # Iteration reports
└── tests/                   # Loop tests
```
