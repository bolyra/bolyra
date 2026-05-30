# demo/demo.tape — vhs recording script for @bolyra/sdk handshake
#
# Produces a clean ~14s GIF showing real Groth16 verification of a mutual
# human+agent handshake, plus single-byte tamper rejection.
#
# Setup:
#   brew install vhs
#   cd /tmp && rm -rf bolyra-sdk-demo && mkdir bolyra-sdk-demo && cd bolyra-sdk-demo
#   npm init -y && npm install @bolyra/sdk
#   cp <repo>/sdk/demo/demo.js .
#   cp <repo>/sdk/demo/humanProof.json .
#   cp <repo>/sdk/demo/agentProof.json .
#   cp <repo>/sdk/demo/nonce.txt .
#   cp <repo>/sdk/demo/HumanUniqueness_vkey.json .
#   cp <repo>/sdk/demo/AgentPolicy_groth16_vkey.json .
#   cp <repo>/sdk/demo/demo.tape .
#   vhs demo.tape

Output demo.gif

Set Shell  "zsh"
Set FontSize 16
Set Width 1100
Set Height 600
Set Theme "Dracula"
Set TypingSpeed 55ms
Set PlaybackSpeed 1.0
Set Padding 24
Set FontFamily "JetBrainsMono Nerd Font"

Hide
Type "clear" Enter
Show

Sleep 600ms

# Show the muscle-memory command — viewers know what install looks like.
Type "npm install @bolyra/sdk"
Sleep 600ms
Enter
Sleep 1500ms

# Clear the install scrollback — focus on the demo, not npm's chatter.
Hide
Type "clear" Enter
Show
Sleep 400ms

# Run the demo. demo.js paces its own scene output via setTimeout.
Type "node demo.js"
Sleep 400ms
Enter

# demo.js takes ~12s end-to-end (two real Groth16 verifies + dramatic pauses).
Sleep 13s

# Hold final frame so the npm-install URL stays readable.
Sleep 2500ms
