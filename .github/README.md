# .github/social-preview

`social-preview.png` (1280×640) is this repo's GitHub social preview image
— the card shown when the repo link is shared on Slack, Twitter/X, etc.

**GitHub doesn't auto-detect this file.** Upload it manually: repo
**Settings → General → Social preview → Upload an image**.

`social-preview.html` is the editable source (inline CSS + a canvas-drawn
lattice diagram — a real Closest Vector Problem illustration, not stock
imagery). To regenerate the PNG after editing:

```bash
"/path/to/chrome" --headless --disable-gpu --hide-scrollbars \
  --force-device-scale-factor=1 --window-size=1280,640 \
  --screenshot=.github/social-preview.png \
  "file:///$(pwd)/.github/social-preview.html"
```
