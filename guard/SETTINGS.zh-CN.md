[English](SETTINGS.md) | **简体中文**

# Hearthward 守卫：设置参考

守卫版本 0.9.3。本页内容已于 2026-11-18 对照代码核对。

本页列出守卫会读取的全部设置：守卫自己的设置、它要求的 Hermes Agent 设置，以及它会查看的环境变量。每一项都写明默认值、作用、什么时候需要改，以及我们的建议。如果还没安装，请先看[安装指南](INSTALL.zh-CN.md)。

## 改设置之前

**设置存在哪里。** Hermes Agent 把设置保存在一个文件里：`~/.hermes/config.yaml`（`~` 指你的个人主目录）。这个文件用 YAML 格式书写，这是一种纯文本格式，靠每行开头的空格（缩进）表示层级关系。守卫自己的设置位于 `plugins` → `entries` → `hearthward-guard` → `settings` 之下。本页里像 `threshold.weak_action` 这样的名字，指的是这些设置中 `threshold` 部分里的 `weak_action` 这一项。

**怎么改。** 用 `hermes config set` 命令。它会替你修改文件，你不用自己对齐缩进。改守卫的设置时，要在名字前面加上 `plugins.entries.hearthward-guard.settings.`。例如把 `holds.timeout_min` 改成 60：

```bash
hermes config set plugins.entries.hearthward-guard.settings.holds.timeout_min 60
```

成功时会看到一行以 `✓` 开头的输出。列表要写在方括号里，每项加双引号，整体再用单引号括起来：

```bash
hermes config set plugins.entries.hearthward-guard.settings.ocr.languages '["eng", "chi_sim"]'
```

**每次改完**都要重启 Hermes（[安装指南第 4.6 步](INSTALL.zh-CN.md#step-4-6)），并重新运行一次预检（[第 5.1 步](INSTALL.zh-CN.md#step-5-1)）：

```bash
bash ~/hearthward-preflight.sh
```

想撤销某项修改、恢复默认值时，把这项设置删掉：

```bash
hermes config unset plugins.entries.hearthward-guard.settings.holds.timeout_min
```

**守卫对设置很严格。** 键名拼错、类型不对（该填数字的地方填了文字）或数值超出允许范围，都不会被悄悄忽略：守卫会拒收所有消息，直到你改正为止；预检会打印 `FAIL: guard: ...` 并指出是哪个键，但不会打印值本身。这是有意为之：一个笔误不应该悄无声息地关掉某项保护。

**不写的设置保持默认值。** 只需要写你想改的那几项。

## 四个决定

大多数人只需要做这四个选择，其他一切保持默认即可。

| 决定 | 设置 | 建议 |
|---|---|---|
| 谁是主人 | `owners`、`owner_chats` | 你自己在聊天软件上的账号，以及你和助手的私聊 |
| 是否开启模型复查 | `second_check.endpoint` | 如果能在本机运行模型服务就开启；一开始只用规则（关闭）也可以 |
| 用哪个本地模型服务 | `second_check.endpoint`、`json_mode`、`model` | llama.cpp 的 `llama-server`（我们测试过的那个） |
| 严格程度 | `threshold.weak_action`、`threshold.unscanned_media`、`holds.timeout_min` | 保持默认 |

[安装指南](INSTALL.zh-CN.md)会在“你的选择”框里逐个带你做这些决定。

## 守卫要求的 Hermes Agent 设置

这些是 Hermes 自己的设置，不是守卫的。在它们正确之前，预检不会通过。

| 设置 | 必须是 | 原因 |
|---|---|---|
| `plugins.enabled` | 包含 `hearthward-guard` | Hermes 只运行你打开的插件。`hermes plugins enable hearthward-guard` 会把它加进去。 |
| `plugins.disabled` | 不包含 `hearthward-guard` | 名字出现在这个列表里时，它总是优先于 `plugins.enabled`。 |
| `plugins.hook_callback_timeout` | `0` | Hermes 默认是 30 秒。检查超过这个时间时，Hermes 会让消息不经检查直接通过。`0` 表示取消这个时间限制。 |
| `gateway.strict` | `true` | 限制助手能往外发送哪些文件。Hermes 默认是 `false`。 |
| `gateway.trust_recent_files` | `false` | 不让助手仅仅因为文件是新的就把它发出去。Hermes 默认是 `true`。 |
| `platform_toolsets.<平台>` | 你用的每个聊天软件都要有一项，且只写允许的工具集 | 没有这一项时，Hermes 会在该聊天软件上给助手默认工具。预检只接受 `no_mcp`，除非你加上 `--allow-toolset 名字`。 |
| `approvals.mode` | `manual`（建议） | Hermes 0.23.1 默认是 `smart`，即由模型来回答工具审批请求。守卫的工具策略（Knock）只有在由人来回答时才会问你。不设为 `manual` 时，所有“询问”都会变成“拒绝”，预检会打印一行 `NOTE`。 |
| `approvals.approvers` | 只有主人（如果你设了它） | 在聊天软件上，只有当能审批的人全都是主人时，Knock 才会询问。 |
| `gateway.platforms.<平台>` 下的管理员列表，如 `extra.allow_admin_from` | 只有主人 | Hermes 也允许管理员回答审批请求。Knock 会核对每个管理员是不是主人；不是的话，“询问”会变成“拒绝”。 |

**建议：** 完全按安装指南设置这些项。在用熟守卫之前，`platform_toolsets` 保持 `["no_mcp"]`（聊天软件上不给工具）。

## 环境变量

环境变量是程序从启动它的命令行环境里得到的一个有名字的值。Hermes 的一些环境变量会覆盖设置文件里的值，所以守卫也会检查它们。

| 变量 | 守卫怎么处理 | 建议 |
|---|---|---|
| `HERMES_MEDIA_DELIVERY_STRICT` | 只要设成“开”（`1`、`true`、`yes`、`on`）以外的值，就会覆盖 `gateway.strict`，预检失败。 | 不要设置。 |
| `HERMES_MEDIA_TRUST_RECENT_FILES` | 只要设成“关”（`0`、`false`、`no`、`off`）以外的值，就会覆盖 `gateway.trust_recent_files`，预检失败。 | 不要设置。 |
| `HERMES_MEDIA_ALLOW_DIRS` | 只要设置了，预检就失败（它会扩大可以发送文件的文件夹范围）。 | 不要设置。 |
| `HERMES_YOLO_MODE` | 开启时 Hermes 会自动批准所有工具调用，所以 Knock 会把所有“询问”变成“拒绝”。 | 不要设置。 |
| `HERMES_HOME` | 守卫把自己的文件放在 `$HERMES_HOME/hearthward-guard`（通常是 `~/.hermes/hearthward-guard`）。 | 保持 Hermes 的设置。 |
| `HEARTHWARD_GUARD_HEARTBEAT` | `1` 强制开启心跳文件，`0` 强制关闭。不设置时只在网关进程里开启。 | 不要设置。 |
| `<平台>_ALLOW_ADMIN_FROM`、`<平台>_GROUP_ALLOW_ADMIN_FROM`、`<平台>_ADMIN_USERS`、`<平台>_ADMINS`、`<平台>_ADMIN_IDS`、`<平台>_ADMIN_USER_IDS`（例如 `DISCORD_ADMINS`） | 和上面的管理员设置一样当作管理员名单：每个管理员都必须是主人，否则“询问”会变成“拒绝”。 | 只写主人，或者不设置。 |
| `second_check.api_key_env` 里写的那个变量 | 它的值会作为密钥发给你的模型服务。 | 只有模型服务需要密钥时才用。 |
| `PATH` 和 `TESSDATA_PREFIX` | 用来找到图片识别程序（Tesseract）和它的语言数据。只认写成完整路径的文件夹。 | 保持原样。 |

## 守卫设置：顶层

| 设置 | 默认值 | 作用 | 什么时候改 | 建议 |
|---|---|---|---|---|
| `mode` | `enforce` | `enforce`：守卫真正执行（暂扣、过滤、拦截）。`report`：只记录它本来会做什么，不执行任何操作。 | 只在短时间试用、想看看哪些会被暂扣时用 `report`。 | `enforce` |
| `owners` | `[]`（没有人） | 谁可以处理暂扣（`follow <编号>`、`ignore <编号>`）、查看 `/guard`、批准工具调用。每项写成 `平台:用户ID`，例如 `discord:123456789`（虚构的号码）。 | 安装时设一次。另外用一个聊天软件时再加一项。 | 只有你自己的账号 |
| `owner_chats` | `{}`（没有） | 守卫给主人发通知的地方：每个平台一个聊天 ID，例如 `{discord: "987654321"}`（虚构的号码）。不设时，别人被暂扣的消息只会记在守卫日志和 `/guard` 里。 | 安装时设置。[安装指南](INSTALL.zh-CN.md#owner-chat)说明了怎么找到聊天 ID。 | 你和助手的私聊 |
| `require_no_hook_timeout` | `true` | 只有 `plugins.hook_callback_timeout` 为 `0` 时才运行。 | 永远不改。 | `true` |

## 守卫设置：`threshold`（检查收到的内容）

规则会给每条消息定一个等级：**放行**（没有迹象）、**弱**（一个轻微迹象）或**暂扣**（明显迹象）。

| 设置 | 默认值 | 作用 | 什么时候改 | 建议 |
|---|---|---|---|---|
| `scan_attachments` | `true` | 读取并检查文本附件。 | 永远不改。 | `true` |
| `scan_tool_results` | `true` | 在模型看到之前，检查工具带回来的内容（网页、文件）。 | 永远不改。 | `true` |
| `scan_reply_context` | `true` | 检查你引用或回复的那段文字。 | 永远不改。 | `true` |
| `scan_local_turns` | `false` | 也检查你在自己电脑上直接输入给 Hermes 的内容（`hermes` 命令、它的终端界面和桌面应用）。 | 如果别人也能在你的电脑上打字，就打开。 | `false` |
| `window_messages` | `6`（1 到 50） | 同一个聊天里，最近多少条消息放在一起检查，用来发现拆成几条发送的指令。 | 很少需要。 | `6` |
| `window_minutes` | `1440`（1 到 10080） | 消息在这个窗口里保留多少分钟。 | 很少需要。 | `1440`（一天） |
| `max_scan_chars` | `120000`（1000 到 2000000） | 最多检查多少个字符。更长的消息或附件会被暂扣；更长的工具结果会被截断，剩下的部分不给模型看。 | 只有长文档经常被暂扣或截断时才调高。 | `120000` |
| `max_attachment_bytes` | `2000000`（1000 到 50000000） | 最多读取多大的文本附件，单位是字节（2000000 约等于 2 MB）。 | 只有附件更大时才调高。 | `2000000` |
| `max_attachments` | `8`（1 到 50） | 一条消息的附件超过这个数量时，整条消息会被暂扣。 | 很少需要。 | `8` |
| `unscanned_media` | `hold` | 守卫读不了的附件（音频、视频、未知文件，以及图片识别关闭时的图片）怎么处理。`hold`（或 `skip`，意思相同）：整条消息暂扣。`owners`：只放行主人发来的。`allow`：谁发的都放行。 | 只有你自己需要给助手发这类文件时。 | `hold` |
| `weak_action` | `pass` | 私聊消息里出现一个轻微迹象时怎么办。`pass`：放行（如果开了模型复查，会交给它看）。`hold`：暂扣。 | 如果陌生人也能给你的助手发消息，而你想更稳妥，就用 `hold`。 | `pass` |
| `weak_action_content` | `hold` | 同上，但针对附件、引用文字和工具结果。 | 很少需要。改成 `pass` 会放过更多藏起来的指令。 | `hold` |
| `fence_tool_results` | `true` | 用标记把工具结果包起来，告诉模型“这是数据，不是指令”。 | 永远不改。 | `true` |
| `scan_timeout_s` | `10.0`（0.5 到 120） | 检查超过这么多秒，消息就会被暂扣。 | 电脑很慢、普通消息也因超时被暂扣时调高。 | `10.0` |

## 守卫设置：`holds`（暂扣的消息）

| 设置 | 默认值 | 作用 | 什么时候改 | 建议 |
|---|---|---|---|---|
| `timeout_min` | `30`（1 到 10080） | 暂扣的消息等你回复 `follow` 或 `ignore` 的分钟数。没有回复就当作 ignore。 | 你常常回复得晚时调高。 | `30` |
| `default` | `ignore` | 没有回复时怎么办。只允许 `ignore`：沉默永远不会放行消息。 | 永远不改。 | `ignore` |
| `max_pending` | `50`（1 到 1000） | 同时最多有多少条暂扣在等待；超过时丢掉最早的一条。 | 很少需要。 | `50` |
| `notices_per_sender_10min` | `3`（0 到 100） | 每个发送者 10 分钟内最多收到几次“你的消息在等待审核”的回复。 | 很少需要。 | `3` |
| `owner_notices_10min` | `10`（1 到 1000） | 10 分钟内你最多收到几条暂扣通知（所有发送者合计）。其余的仍在等待，下一条通知会告诉你有几条没通知，`/guard` 会列出全部。 | 通知太多时调低。 | `10` |
| `notice_excerpt_chars` | `160`（0 到 1000） | 通知里显示多少暂扣消息的原文（链接和隐藏字符会被处理成无害的样子）。`0` 表示不显示。 | 想让通知更隐私时调低。 | `160` |
| `tell_sender` | `true` | 告诉发送者他的消息在等待审核。 | 想保持沉默时设为 `false`。 | `true` |

## 守卫设置：`second_check`（可选的模型复查）

模型复查会问一个本地 AI 模型（它没有任何工具）：这段文字是不是想给助手下命令。`endpoint` 为空时它是关闭的。它只会增加暂扣，从不减少；模型服务没开或者回答格式不对时，消息会被暂扣。

| 设置 | 默认值 | 作用 | 什么时候改 | 建议 |
|---|---|---|---|---|
| `endpoint` | `""`（关闭） | 模型服务的 OpenAI 风格接口地址，以 `/v1` 结尾，例如 `http://127.0.0.1:9931/v1`。 | 填上它就开启模型复查。 | 你自己电脑上的服务 |
| `model` | `local` | 每次请求附带的模型名。llama.cpp 不看它；Ollama 需要准确的名字（例如 `qwen3:8b`）。 | 用 Ollama 或 LM Studio 时要设置。 | 你的服务里的模型名 |
| `json_mode` | `schema` | 用什么方式要求回答的格式。`schema`：llama.cpp（测试过）。`json_object`：Ollama、LM Studio（我们没测试过）。`none`：不要求。 | 按你的服务来设。 | llama.cpp 用 `schema` |
| `allow_remote` | `false` | 允许不在本机上的地址。这样消息内容会离开你的电脑。 | 只有你信任那台机器和通往它的网络时。 | `false` |
| `api_key_env` | `""` | 存放服务密钥的环境变量的**名字**，绝不是密钥本身。 | 只有服务需要密钥时。 | `""` |
| `timeout_s` | `8.0`（0.5 到 600） | 等一次回答的秒数。太慢就暂扣。 | 电脑慢、消息常因“暂时无法检查”被暂扣时调高。 | `8.0` |
| `tool_timeout_s` | `8.0`（0.5 到 600） | 同上，针对工具结果。 | 同上。 | `8.0` |
| `scope` | `all` | `all`：检查所有还没被暂扣的内容。`weak`：只检查有一个轻微迹象的内容。 | 电脑太慢、查不过来时用 `weak`。 | `all` |
| `channels` | `["chat", "attachment", "reply_context", "tool_result"]` | 检查哪几类内容：聊天消息、附件、引用文字、工具结果。 | 很少需要。 | 全部四类 |
| `owner_chat` | `weak` | 你自己的聊天消息：`off` 从不检查，`weak` 只在规则发现轻微迹象时检查，`all` 总是检查。 | 如果别人也用你的账号，用 `all`。 | `weak` |
| `max_chunks` | `4`（1 到 16） | 长文字会分段检查，最多检查这么多段。 | 长文字常因“太长，无法完整检查”被暂扣时调高。 | `4` |
| `chunk_tokens` | `1500`（200 到 8000） | 每段的大小，按估算的 token（词的片段）计。 | 模型上下文较小时调低。 | `1500` |
| `max_chars` | `6000`（500 到 100000） | 每段最多多少个字符。 | 很少需要。 | `6000` |
| `oversize` | `hold` | 太长、无法完整检查的内容。`hold`：暂扣（你自己打的聊天消息会放行，但标记为未检查）。`taint`：你转发的内容放行，但标记为未检查，有风险的工具需要审批；陌生人的内容仍然暂扣。 | 你常转发长文字时用 `taint`。 | `hold` |
| `calls_per_sender_10min` | `12`（1 到 10000） | 每个其他人 10 分钟内最多能触发几次模型复查。超出后，他的消息不经复查直接暂扣。你自己不受限制。 | 很少需要。 | `12` |
| `calls_all_10min` | `60`（1 到 100000） | 同上，所有其他人合计。 | 很少需要。 | `60` |
| `probes` | `true` | 复查前，先给模型发一段无害、一段恶意的测试文字，答案是已知的。答错就把复查标记为不可靠，消息会被暂扣。 | 永远不改。 | `true` |
| `probe_every_min` | `30`（5 到 1440） | 两次测试之间的分钟数。 | 很少需要。 | `30` |
| `pause_flag` | `""` | 一个文件的完整路径。这个文件存在时，复查视为暂停（消息会被暂扣）。例如游戏启动器创建的文件。 | 只有你有这样的文件时。 | `""` |
| `slot` | `-1`（-1 到 64） | 仅限 llama.cpp：用哪个槽位；`-1` 表示任意空闲的。 | 只有你给守卫留了专用槽位时。 | `-1` |
| `recheck_unavailable` | `false` | 你自己的消息若只是因为模型没开而被暂扣，就在几分钟内自动重新检查。尚未在真实网关中验证。 | 保持关闭。 | `false` |
| `recheck_attempts` | `3`（1 到 3） | 重新检查的次数。 | 只配合 `recheck_unavailable`。 | `3` |
| `recheck_window_min` | `10`（1 到 10） | 重新检查持续的分钟数。 | 只配合 `recheck_unavailable`。 | `10` |
| `tamper_retry` | `false` | 回答格式不对时再问一次。这等于给劫持者第二次机会。 | 保持关闭。 | `false` |
| `prompt_variant_dir` | `""` | 高级：一个放着你自己复查说明的文件夹（`content.txt`、`chat.txt`、`probes.json`）。 | 只在测试其他措辞时。 | `""` |
| `score_mode` | `false` | 向服务要词语概率并记录一个分数。仅供调参。 | 只在调参时。 | `false` |
| `on_error` | `hold` | 复查失败时怎么办。只允许 `hold`。 | 永远不改。 | `hold` |

## 守卫设置：`gatehouse`（检查回复）

| 设置 | 默认值 | 作用 | 什么时候改 | 建议 |
|---|---|---|---|---|
| `strip_invisible` | `true` | 去掉回复里的隐藏字符和控制字符。 | 永远不改。 | `true` |
| `withhold_secrets` | `true` | 回复里有像密码、密钥或令牌的东西时，整条回复都不发。 | 永远不改。 | `true` |
| `block_media_directives` | `true` | 去掉回复里发送文件的指令和本地文件路径。 | 永远不改。 | `true` |
| `block_markdown_images` | `true` | 把回复里的图片换成它的文字说明（否则聊天软件会从网上加载图片，可能泄露数据）。 | 永远不改。 | `true` |
| `block_query_links` | `true` | 去掉看起来在往外带数据的链接（编码过的片段，或你们对话里的原话）。 | 永远不改。 | `true` |
| `safe_link_hosts` | `[]`（最多 64 个） | 链接永远不会被去掉的确切主机名，例如 `["docs.python.org"]`。任何人都能发布网页或表单的网站（如 `docs.google.com`、`github.io`）不能加。 | 你信任的网站链接总被去掉时。 | 空 |
| `id_patterns` | `[]`（最多 32 个） | 你自己的编号格式的正则表达式（文字模式）；匹配到的会变成 `(id removed)`。 | 想让某种编号格式不出现在回复里时。 | 空 |

## 守卫设置：`ocr`（图片和防诈骗）

| 设置 | 默认值 | 作用 | 什么时候改 | 建议 |
|---|---|---|---|---|
| `enabled` | `auto` | `auto`：找到 Tesseract 就开启（Windows 上始终关闭）。`true`：开启；没有 Tesseract 时每张图片都暂扣。`false`：关闭；图片按 `threshold.unscanned_media` 处理。 | 想关掉图片功能时设为 `false`。 | `auto` |
| `engine_path` | `""` | Tesseract 程序的完整路径。为空：在 `PATH` 的文件夹里找 `tesseract`（Linux、macOS）。 | 只有 Tesseract 装在不常见的位置时。 | `""` |
| `tessdata_dir` | `""` | Tesseract 语言数据所在的文件夹。为空：用 Tesseract 自己的。 | 只有语言数据装在别处时。 | `""` |
| `languages` | `["eng", "chi_sim"]` | 要识别的语言（Tesseract 代码）。每一种都必须已安装，否则每张图片都会暂扣。 | 按你收到的语言来设。 | `["eng", "chi_sim"]` |
| `timeout_s` | `20`（1 到 120） | 每张图片的秒数。 | 电脑慢时调高。 | `20` |
| `memory_mb` | `1024`（128 到 8192） | Tesseract 的内存上限（Linux 和 macOS）。 | 很少需要。 | `1024` |
| `max_bytes` | `10000000`（10000 到 50000000） | 更大的图片文件不读，直接暂扣。 | 很少需要。 | `10000000`（约 10 MB） |
| `max_pixels` | `40000000`（10000 到 200000000） | 像素更多的图片不读，直接暂扣。 | 很少需要。 | `40000000` |
| `max_pictures` | `4`（1 到 10） | 每条消息最多读几张图片。 | 很少需要。 | `4` |
| `max_text_chars` | `20000`（500 到 200000） | 每张图片最多取多少个字符。 | 很少需要。 | `20000` |
| `read_metadata` | `true` | 也检查图片文件里存的文字。 | 永远不改。 | `true` |
| `locale` | `en` | 图片结论和提醒用什么语言：`en`、`zh` 或 `both`。 | 读者用中文时设为 `zh` 或 `both`。 | 读者的语言 |
| `alert_owner` | `true` | 别人发来很可能是诈骗的图片时提醒你。 | 不想收到这类提醒时设为 `false`。 | `true` |
| `alerts_per_10min` | `6`（0 到 100） | 10 分钟内最多几条诈骗提醒。 | 很少需要。 | `6` |

## 守卫设置：`log` 和 `heartbeat`

| 设置 | 默认值 | 作用 | 什么时候改 | 建议 |
|---|---|---|---|---|
| `log.raw_text` | `false` | 把消息原文写进守卫日志。`false` 表示日志里不留消息原文。 | 只在排查问题时临时打开，之后关掉。 | `false` |
| `log.path` | `""` | 守卫日志写在哪里。为空：`~/.hermes/hearthward-guard/events.jsonl`。 | 很少需要。 | `""` |
| `heartbeat.dir` | `""` | 心跳文件所在的文件夹（运行中的守卫会不断重写这个小文件，表示自己还活着、状态正常）。为空：`~/.hermes/hearthward-guard/status`。 | 很少需要。 | `""` |
| `heartbeat.interval_s` | `15`（2 到 3600） | 心跳更新的间隔秒数。 | 很少需要。 | `15` |

## 守卫设置：`knock`（工具策略）

Knock 决定哪些工具调用可以运行、哪些被拒绝、哪些要先问你。“外部内容”指不是你写的文字：别人的消息、附件、网页、工具输出。看到过外部内容的对话叫做**被污染**（tainted）。

有些设置会关掉某项检查。这些设置还需要同时设 `knock.unsafe_override: true`，`/guard` 会把它们列出来。

| 设置 | 默认值 | 作用 | 什么时候改 | 建议 |
|---|---|---|---|---|
| `enabled` | `true` | 开关 Knock。设为 `false` 需要 `unsafe_override`。 | 永远不改。 | `true` |
| `taint` | `deny` | 看到来自外面的外部内容之后，有实际效果的工具（写入、发送、运行）：`deny` 拒绝，或 `ask` 问你。效果会持续的工具（记忆、技能、定时任务）即使设为 `ask` 也拒绝。 | 只有你会仔细看每个审批请求时才用 `ask`。 | `deny` |
| `local_taint` | `ask` | 同上，但外部内容只来自你自己的电脑（终端、你的文件）：`ask` 或 `deny`。 | 想更严格时用 `deny`。 | `ask` |
| `unknown_tools` | `deny` | Knock 不认识的工具（包括所有 MCP 工具）：`deny` 或 `ask`。 | 你用了 Knock 不认识的工具时用 `ask`，或者用 `tools` 给它们分类。 | `deny` |
| `untainted_acts` | `allow` | 在干净的对话里，有实际效果的工具：`allow` 或 `ask`。 | 想更严格时用 `ask`。 | `allow` |
| `untainted_exec` | `ask` | 在干净的对话里，运行代码的工具：`ask` 或 `allow`。 | 很少需要。 | `ask` |
| `ask_scope` | `call` | 审批请求上的“总是允许”覆盖什么。`call`：只这一次调用。`tool`：这个工具在本次对话中、仅限今天（需要 `unsafe_override`）。 | 很少需要。 | `call` |
| `tools` | `{}` | 你给工具定的类别，`{工具名或模式: 类别}`。类别：`read`（没有效果，输出可信）、`source`（没有效果，输出算外部内容）、`source:private`（读取你的私人数据）、`source:net`（把文字发到电脑外面）、`act`（有效果）、`act+source`（两者都是）。让内置工具变宽松需要 `unsafe_override`。 | 你加了 Knock 不认识的工具时。 | 空 |
| `job_allowlists` | `{}` | 按键列出唯一允许的工具：`*`（全部）、`cron:*`（所有定时任务）、`cron:<任务ID>`、`platform:<名字>`。 | 想把某个定时任务或某个聊天软件限制在少数几个工具时。 | 空 |
| `trusted_cron_jobs` | `[]` | 提示词算作你自己写的（而不是外部内容）的定时任务。写成 `<任务ID>:<提示词的 sha256>`，这样提示词一改就不再被信任。 | 只用于你自己写的任务。 | 空 |
| `never_allow` | `[]`（最多 100 条） | 你自己的“永不允许”规则：`{id, tools: [名字], args: [模式], label}`。 | 想直接禁止更多操作时。 | 空 |
| `never_allow_disable` | `[]` | 要关掉的内置“永不允许”规则：`money`、`trades`、`passwords`、`id_numbers`、`vault`、`sign_in`、`guard_off`。需要 `unsafe_override`。 | 不建议。 | 空 |
| `unsafe_override` | `false` | 上面那些会关掉检查的设置都需要它。 | 只和那类设置一起用。 | `false` |
| `local_skills` | `[]` | 你自己写的技能，写成 `<技能名>:<它的 SKILL.md 的 sha256>`；读取它们不算外部内容。下载来的技能绝不要列进来。 | 只用于你自己的技能。 | 空 |
| `chat_grants_and_partial` | `false` | 在聊天软件上允许限时授权和只显示一部分的审批请求。在 Discord 上，长请求放不下，本来就会被拒绝。 | 保持关闭。 | `false` |
| `max_sessions` | `20000`（100 到 1000000） | Knock 记住多少个对话。 | 很少需要。 | `20000` |

网关重启后，Knock 没看到已有对话是怎么开始的，所以这些对话里有风险的工具会被拒绝（“history not seen”，即没看到历史）。在那个聊天里用 `/new` 开一个新对话即可（Hermes 会让你用 `/approve` 确认）。

## 预检选项

预检（`tools/preflight.py`）接受下面这些命令行选项。安装指南里的快捷脚本（`bash ~/hearthward-preflight.sh`）已经带上了 `--plugin-dir`，你额外加的选项也会原样传过去，例如 `bash ~/hearthward-preflight.sh --heartbeat`。

| 选项 | 作用 |
|---|---|
| `--plugin-dir 文件夹` | 要检查的已安装守卫文件夹。安装指南用的是 `~/.hermes/plugins/hearthward-guard`。 |
| `--platform 名字` | 也检查这个聊天平台（`owners` 和 `owner_chats` 里的平台本来就会检查）。可以写多次。 |
| `--allow-toolset 名字` | 在 `platform_toolsets` 里接受这个工具集（默认只接受 `no_mcp`）。可以写多次。 |
| `--tools-cli` | 另外运行 `hermes tools list --platform 名字`，那里只要有任何工具开着就失败。 |
| `--heartbeat` | 另外检查运行中网关里的守卫是否写了新鲜、健康的心跳。 |
| `--heartbeat-dir 文件夹`、`--max-age 秒数`、`--pid 进程号` | 心跳在哪里、最多多旧（默认 60 秒）、必须来自哪个网关进程。 |

退出码 0 表示全部通过，1 表示至少有一行 `FAIL`，2 表示预检本身无法运行。
