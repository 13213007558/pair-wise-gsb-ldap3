# ldap3 filter 拼接与 `auto_escape=True` 安全评审

针对“把用户名直接 `%s` 拼进 LDAP filter，再依赖 `Connection(auto_escape=True)`
兜底”这一常见接法的代码级评审。所有结论都来自仓库内 ldap3 2.10.2rc4 的实际
代码路径，并用 `python -m pytest security-review/ -v` 与 `python security-review/demo.py`
复现。没有任何“库会自动修复字符串拼接注入”的结论是凭空声称的——下文每一条都给了
源码位置和对应测试。

## 结论速览

- `auto_escape` **不是**拼接注入的防线。filter 字符串先被语法解析成过滤树，
  转义逻辑之后才有机会运行；而且它只在“值里含反斜杠且看起来不是合法转义”时才调用
  `escape_filter_chars`。不含 `\` 的 `*`、`(`、`)` 注入完全不会被它处理。
- 正确做法是调用方在拼接前对**每个不可信值**调用一次
  `ldap3.utils.conv.escape_filter_chars`（RFC 4515）。
- DN 里的值属于另一层语法，用 `ldap3.utils.dn.escape_rdn`（RFC 4514）。
  两者转义字符集不同，不能互换：`escape_rdn` 不转义 `* ( )`，救不了 filter。
- 转义只做**一次**，发生在“值 → filter 字符串”这一层；BER 编码层只负责把
  字符串转成字节（UTF-8），不再做语义转义。
- 调用方明确需要的 substring 搜索保留：结构性 `*` 由代码显式添加，用户输入里的
  `*` 被转义成 `\2a` 后按字面量匹配，而不是一刀切禁用所有星号。

## `auto_escape=True` 到底保护了什么（代码路径）

1. 连接参数只是存下来：`ldap3/core/connection.py:293`
   （`self.auto_escape = auto_escape`），文档描述在 `connection.py:179`。
2. `Connection.search` 把它传给 `search_operation(...)`
   （`ldap3/core/connection.py:880`、`connection.py:823` 说明可被逐次调用覆盖）。
3. `search_operation` 的顺序是**先解析、后编译**：
   `ldap3/operation/search.py:371`
   `compile_filter(parse_filter(search_filter, ..., auto_escape, ...))`。
4. `parse_filter`（`ldap3/operation/search.py:170`）是一个纯字符状态机，看到
   `(` `)` `&` `|` `!` 就建树（`search.py:184-214`）。它在任何转义发生之前就
   决定了过滤树形状。括号不平衡直接抛 `LDAPInvalidFilterError`
   （`search.py:214`、`search.py:219`）——这是“拒绝”，不是“无害化”。
5. 真正的转义在 `validate_assertion_value`（`ldap3/protocol/convert.py:154`）：
   ```python
   if auto_escape:
       if '\\' in value and not is_filter_escaped(value):
           value = escape_filter_chars(value)
   ```
   即只有值里**已经有反斜杠**且不被 `is_filter_escaped` 判为已转义时才转义。
   `a*b`、`x)(|(uid=*)` 这类没有反斜杠的载荷根本进不了 `escape_filter_chars`。
6. `is_filter_escaped`（`ldap3/utils/conv.py:228`）要求文本里不含 `( ) * NUL`，
   且每个 `\` 后面都是两位十六进制；因此对已经正确转义过的值它返回 True，
   `auto_escape` 不会二次转义（幂等）。
7. 即便走到 `escape_filter_chars`（`ldap3/utils/conv.py:91`），它也只替换
   `\ * ( ) NUL` 五个字符为 RFC 4515 的十六进制对。
8. 编译期 `compile_filter`（`ldap3/operation/search.py:222`）通过
   `prepare_filter_for_sending`（`ldap3/protocol/convert.py:196`）只做
   `str → bytes`（默认 UTF-8），不再解释或修补过滤语义。

实测对照（`demo.py` 第 2 节、测试 `test_parser_builds_the_tree_before_any_escaping`、
`test_auto_escape_only_fires_for_backslash_values`）：

- 用户名 `x)(|(uid=*)` 直接拼接后，`parse_filter` 建成
  `AND(oc=person, uid=x, OR(present uid))` 三分支树——注入成立。
- 同样的串经 `escape_filter_chars` 后是单个 `equalityMatch`，线上值为
  `x\29\28|\28uid=\2a\29`。

## 三种构造方式对照

以用户名 `x)(|(uid=*)` 为例（完整输出见 `demo.py`）：

| 方式 | filter 字符串 | 解析结果 |
| --- | --- | --- |
| 不转义，直接拼 | `(&(objectClass=person)(uid=x)(|(uid=*)))` | AND 三分支，含 `OR(present uid)` 注入 |
| 错误地用 DN 转义 `escape_rdn` | `(&(objectClass=person)(uid=x)(|(uid\=*)))` | `* ( )` 未被转义，括号不平衡直接报错/或星号变 substring |
| 正确 filter 转义 `escape_filter_chars` | `(&(objectClass=person)(uid=x\29\28|\28uid=\2a\29))` | 单个 equality，字面量匹配 |

`escape_rdn` 的字符集见 `ldap3/utils/dn.py:390`：只处理
`\ , + " < > ; = NUL` 以及首尾空格/开头 `#`，明确**不含** `* ( )`。
对应测试：`test_dn_escaping_does_not_protect_a_filter`、
`test_dn_escaping_handles_comma_for_dn_layer_only`。

## BER 层面确认过滤树

`security-review/ber_inspect.py` 是一个不依赖 ASN.1 schema 的最小 BER 读取器，
直接在 `search_operation` 产出的 SearchRequest 字节上还原 filter（RFC 4511
`[APPLICATION 3]`，filter 是第 7 个字段，choice tag 0-9）。要点：

- 正确转义的 filter 在线上是 `and[ equality(objectClass=person),
  equality(uid=<字面量>) ]`，元字符以 ASCII 十六进制对出现，例如
  `\29` 的字节是 `5c 32 39`（见 `test_ber_shows_escaped_value_as_single_equality_literal`）。
- 朴素拼接的注入在线上确实是带 `or/present` 的布尔树
  （`test_ber_shows_naive_injection_as_boolean_tree`）。
- 非 ASCII 字符按原始 UTF-8 上线，元字符按十六进制转义：用户名
  `é用户*(` 的线上值是 `c3a9 e794a8 e688b7 5c3261 5c3238`
  （`test_ber_non_ascii_is_utf8_with_metacharacters_hex_escaped`）。
- substring 的 `*` 作为结构符出现在 TLV 选择里（`substringFilter` 的
  initial/any/final），用户输入的 `*` 则作为 any 值里的 `\2a` 字面量
  （`test_ber_preserves_caller_owned_substring_wildcards`）。

## 编码发生在哪一层（只编码一次）

- 第 1 层（调用方，本评审的 `safe_ldap.py`）：不可信文本 → RFC 4515 转义字符串，
  或 DN 组件 → RFC 4514 转义字符串。**安全责任在这一层，且只做一次。**
- 第 2 层（ldap3 编译）：`prepare_filter_for_sending` 把转义后的字符串
  `encode('utf-8')` 成 OCTET STRING 字节，不改变转义语义。
- bytes 属性值（如 `jpegPhoto`）原样作为字节存储/返回，
  见 `test_mock_bytes_attribute_value_round_trips`。
- 对已经转义的值再次调用 `escape_filter_chars` 会把 `\` 再转成 `\5c`
  造成双重转义；`auto_escape` 因 `is_filter_escaped` 而保持幂等，
  但调用方不应依赖这一点（`test_escaping_is_done_once_and_is_idempotent`）。

## Mock 目录验证与一个真实库缺陷

`demo.py` 第 7 节和 `test_mock_*` 用 `MOCK_SYNC` 策略验证：转义后的注入匹配 0 个
账号，真实账号只返回预期条目，substring 仍可用，bytes 属性完整往返。

需要明确记录的是 Mock 策略自身的二次转义缺陷（不是本评审引入，也未在本评审中修改
库代码）：Mock 在执行搜索时会把 ASN.1 请求重新解码成 filter 字符串
（`ldap3/strategy/mockBase.py:679`），而 `ava_to_dict`
（`ldap3/protocol/convert.py:103`、`convert.py:106`）对 assertionValue **无条件**
再跑一次 `escape_filter_chars`，于是已转义的 `star\2ax` 变成 `star\5c2ax`。
真实 socket 连接发出的 BER 是正确的单次转义；受影响的只是 Mock 策略下“值本身含
元字符”的 equality 回查。该行为由
`test_mock_strategy_re_escapes_wire_values_known_limitation` 固化为证据，
建议作为单独 issue 上报，而不是在业务层绕过。

## 产物清单

- `safe_ldap.py`：安全接入示例（equality / substring / present / 布尔组合 / DN）。
- `ber_inspect.py`：SearchRequest BER 解码，还原线上过滤树。
- `demo.py`：可直接 `python security-review/demo.py` 运行的端到端对照（无需网络/服务器）。
- `test_filter_security.py`：25 个可重复 pytest 用例。
- `docs-patch.diff`：对公共 API 文档的具体修改建议（未直接改动库源码）。

## 运行方式

```bash
python -m pytest security-review/ -v
python security-review/demo.py
```
