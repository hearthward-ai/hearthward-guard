# Third-party notices

This project is licensed under Apache-2.0 (see [LICENSE](LICENSE)), except for the material below.

## Hermes Agent (Nous Research), MIT licence

What is covered:

- `bench/prompts/hermes_prompt.json`: the system prompt text and tool schemas, copied from Hermes Agent
  (https://github.com/NousResearch/hermes-agent), commit `2bd378ed1b`.
- A few short verbatim Hermes wording strings that the guard matches so it can recognise Hermes's own notes. They are
  in `guard/hearthward_guard/knock/policy.py` (the Discord triggering note and the cron wrapper note) and in
  `guard/tests/knock/test_knock_fixround5.py`.

Licence text, copied from the upstream `LICENSE` at that commit:

```
﻿MIT License

Copyright (c) 2025 Nous Research

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Not affiliated with or endorsed by Nous Research.
