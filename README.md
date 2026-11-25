sec-digest-auth
====================

网关把同一份摘要认证口令同时交给审计与重放检测使用，最近发现合法客户端偶尔连不上、而重放旧请求时而被放行：契约要求从挑战值里逐项取出 realm、nonce、opaque、algorithm 与 stale，qop 给出多个候选时必须按逗号拆成有序列表并去掉两端空白、未给出时为空列表，algorithm 未出现时按 MD5 处理、出现时原样返回；解析授权头时 username、realm、nonce、uri、qop、nc、cnonce、response、opaque 必须各自独立取出，保留原始大小写、引号内的反斜杠转义要还原，缺省项为 None，algorithm 缺省同样是 MD5；生成授权头时 username、realm、nonce、uri、cnonce、response、opaque 加双引号，algorithm、qop、nc 保持裸词，只有服务端给出 auth 时才启用 qop 且此时 nc 必须是八位十六进制、cnonce 不可为空，服务端只给出不支持的 qop 时必须报错；摘要的 A1 是 username 冒号 realm 冒号 password 三段的哈希，算法带 -sess 后缀时再对"前一步结果冒号 nonce 冒号 cnonce"取一次哈希，A2 是 method 与请求目标两段的哈希且请求目标必须含查询串、大小写原样参与，启用 qop 时响应为 A1、nonce、nc、cnonce、qop、A2 六段的哈希，未启用时为 A1、nonce、A2 三段的哈希；算法名比较大小写不敏感，哈希函数在 MD5 与 SHA-256 之间按名字选择、忽略 -sess 后缀、未知算法报错，输出小写十六进制；校验顺序固定为字段完整、请求目标与授权头一致、用户名可查、qop 受支持、nonce 存在且剩余有效期严格大于零、opaque 相符、nc 按十六进制数值严格递增、响应摘要相等，任一不满足即返回 ok 为假并给出固定的短横线原因，取值只能是 malformed、missing-field、unknown-user、uri-mismatch、unsupported-qop、stale-nonce、bad-opaque、replay、bad-response 之一（依次对应报文残缺、缺少字段、用户不存在、请求目标与授权头不一致、不支持的 qop、nonce 过期、opaque 不符、重放、摘要不符），全部满足时返回 ok 为真、给出用户名、原因为空串；nonce 计数必须按数值比较而不是按字典序（0000000a 应大于 00000009），校验成功后要把该 nonce 的高水位计数回写到存储中。不变量：同一组输入生成的授权头逐字节相同；校验成功后重复提交同一计数必被拒；不同算法、不同 -sess 开关、不同请求目标必须得到不同摘要；校验除高水位外不得改动调用方传入的存储。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |