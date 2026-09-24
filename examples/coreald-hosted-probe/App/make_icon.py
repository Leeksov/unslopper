#!/usr/bin/env python3
"""Generate a plain, identifiable App Store icon for the private test app."""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

image = Image.new("RGB", (1024, 1024), "#152238")
draw = ImageDraw.Draw(image)
draw.rounded_rectangle((148, 148, 876, 876), radius=150, fill="#2473d9")
draw.rounded_rectangle((235, 315, 789, 709), radius=60, fill="#f7fafc")
draw.rectangle((294, 390, 730, 634), fill="#152238")
font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial Bold.ttf", 124)
draw.text((512, 512), "BA", font=font, anchor="mm", fill="#f7fafc")
path = Path(__file__).parent / "Assets.xcassets" / "AppIcon.appiconset" / "AppIcon.png"
image.save(path)
print(path)
