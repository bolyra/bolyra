# demo/demo.tape — vhs recording script for @bolyra/delegation
#
# Produces a clean ~20s GIF for cold DMs / community posts.
#
# Setup:
#   brew install vhs
#   cd /tmp && rm -rf bolyra-demo && mkdir bolyra-demo && cd bolyra-demo
#   npm init -y && npm install @bolyra/delegation
#   cp <repo>/delegation/demo/demo.js .
#   cp <repo>/delegation/demo/demo.tape .
#   vhs demo.tape
#
# Output: demo.gif (and demo.mp4 / demo.webm if you uncomment those Output lines)

Output demo.gif
# Output demo.mp4
# Output demo.webm

Set Shell  "zsh"
Set FontSize 16
Set Width 1100
Set Height 720
Set Theme "Dracula"
Set TypingSpeed 55ms
Set PlaybackSpeed 1.0
Set Padding 24
Set FontFamily "JetBrainsMono Nerd Font"

# Hide the typing of the install — viewers know what npm install looks like.
# Just show the run.
Hide
Type "clear" Enter
Show

Sleep 600ms

# Step 1: install (already done, but show the command for muscle memory)
Type "npm install @bolyra/delegation"
Sleep 600ms
Enter
Sleep 1500ms

# Step 2: run the demo
Type "node demo.js"
Sleep 400ms
Enter

# demo.js itself paces its own scene-by-scene output via setTimeout.
# Wait for it to finish (~9s) plus a beat for the closing card.
Sleep 11s

# Hold the final frame so the npm-install URL stays readable.
Sleep 2500ms
