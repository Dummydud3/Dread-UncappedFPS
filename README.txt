Metroid Dread 1.0.0 - Uncapped FPS

010093801237C000
49161D9CCBC15DF944D0B6278A3C446C006B0BE8

Extract DreadDeltaTime into the game's Ryujinx mod directory.
Enable the mod, disable other timing mods, and set VSync to Unbounded.

python -m pip install -r requirements.txt
python build.py --nso /path/to/main.nso
python package.py
