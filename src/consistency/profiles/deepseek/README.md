# DeepSeek Judge Profiles

These JSON files are reusable DeepSeek judge profiles for the v3 consistency dataset.
They send only the label-free detector projection to the model: provider requirements,
observed actions and observation status.

- deepseek_judge_profile_v1.json: original frozen baseline profile.
- deepseek_judge_profile_c1_v3.json: selected current pilot profile; deepseek-v4-flash, thinking disabled, procedural prompt.
- deepseek_judge_profile_c2.json: C1-style prompt with Flash thinking enabled.
- deepseek_judge_profile_c3.json: C1-style prompt with Pro thinking enabled.
- deepseek_judge_profile_c4_v3.json: closed-world Flash profile.

The earlier C1/C4 prompt-debug profiles were removed because their outputs did not satisfy
the JSON verdict protocol and were excluded from the comparable candidate table.
