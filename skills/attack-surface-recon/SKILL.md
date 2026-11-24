---
name: attack-surface-recon
description: >-
  侦察/攻击面测绘:被动whois/amass/crt.sh/FOFA/Shodan,主动subfinder/httpx/naabu/katana/nuclei,DNS地域/CDN/Nginx catch-all/宝塔/UniApp指纹。按当前证据选择侦察面并写入项目黑板。Use when starting recon, asset mapping, fingerprinting, or CDN/DNS bypass discovery.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 适用场景

适合从域名、IP、证书、DNS、前端资源和公开服务中建立攻击面清单，并为后续测试选择优先目标。

## 核心判断

侦察的价值不是“跑完所有工具”，而是发现可验证的新资产、真实源站、服务边界、技术栈和异常响应。每个发现都要区分：

- 可直接确认的资产或入口
- 需要进一步验证的线索
- 已知重复的探测
- 无实际意义的指纹或网络噪声

## 证据标准

- 资产登记至少需要可信 DNS、证书、HTTP 响应或端口结果。
- 指纹和版本只能作为线索，不能直接升级为漏洞。
- CDN、WAF、catch-all 和真实源站需要对照证据，不能只看单次响应。
- 扫描输出必须保留关键请求、响应头、状态码、长度或 artifact 引用。

## 决策树

- 发现新域名、IP、端口或业务入口：先登记资产和事实。
- 发现框架或组件版本：转入 `component-vuln-intel` 做候选情报搜索。
- 发现响应差异：设计最小对照请求，区分真实入口、catch-all 和 WAF。
- 连续发现重复资产或相同响应：停止重复扫描，转向新面。
- 探测被策略或网络阻断：记录阻断原因并重新选择可观察面。

## 常见误判

- 把 CDN 节点当成真实源站。
- 把 catch-all 的 200 响应当成有效路径。
- 把版本指纹当成已知漏洞成立。
- 把扫描器命中当成可利用证据。
- 只记录成功命中，不记录负结果和已排除路径。

## 可选工具与示例

```
=== 侦察/攻击面测绘(以下命令是候选工具，按当前信号选择；端口/指纹等及时 upsert_project_fact) ===
被动路径(可在不触碰目标业务面的情况下选择执行):
  terminal: whois {domain} | grep -iE 'org|name|email|registrant'
  terminal: amass intel -asn {ASN} -d {domain}
  browser_navigate: https://crt.sh/?q=%.{domain} (证书透明挖子域)
  terminal: curl -s "https://crt.sh/?q=%.{domain}&output=json" | python3 -c "import sys,json;[print(x['name_value']) for x in json.load(sys.stdin)]" | sort -u
  terminal: dig +short {domain} @114.114.114.114; dig +short {domain} @8.8.8.8 (对比差异=CDN)
  terminal: curl -s "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey" | head -100
  browser_navigate: https://fofa.info/result?qbase64=$(echo -n 'domain="{domain}"' | base64)
  browser_navigate: https://www.shodan.io/search?query=hostname:{domain}
主动流水线(逐步执行):
  terminal: subfinder -d {domain} -silent | tee subs.txt; amass enum -d {domain} -passive >> subs.txt; sort -u subs.txt -o subs.txt
  terminal: cat subs.txt | dnsx -silent | tee alive_subs.txt
  terminal: cat alive_subs.txt | httpx -silent -title -status-code -tech-detect -cdn | tee httpx_out.txt
  terminal: naabu -l alive_subs.txt -top-ports 1000 -silent | tee ports.txt; nmap -sCV -iL <(head -20 alive_subs.txt) -oN nmap_out.txt
  terminal: katana -list alive_subs.txt -silent -d 3 | tee urls.txt; gau {domain} >> urls.txt
  terminal: cat urls.txt | grep -iE '\.(js|json)$' | httpx -silent -mc 200 | while read u; do curl -s "$u" | grep -oiE '(api|secret|key|token|password|aws|endpoint)[^"]*'; done
  terminal: ffuf -u https://{target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -fs {catch-all-size}
  terminal: nuclei -l alive_subs.txt -t /root/nuclei-templates/ -severity medium,high,critical -o nuclei_results.txt
  → httpx输出识别到框架/版本 → 读取 `component-vuln-intel`，按组件身份和版本信号选择情报路径
🚨DNS地域限制绕过: 国内CDN(987dns/dnspod/阿里云)常对海外DNS返0.0.0.0,用114.114.114.114解析才拿到真实IP。多DNS对比: dig @1.1.1.1 vs @114.114.114.114 vs @8.8.8.8,差异即CDN地域策略。真实IP藏在国内DNS结果中。
🚨CDN响应过滤绕过(GCCDN/PWS等): CDN对特定URL模式(admin路径/actuator)返502而非转发后端响应:
  指纹识别: Server: PWS/x.x.x.x | Via: 1.1 PS-XXX-XXXX:N (W) | X-Px: ms CS-XXX-XXXXnone(origin) | 通配*.gccdn.net CNAME
  502≠不存在: 502=后端响应被CDN过滤, 404=路径真不存在, 403=CDN路由拒绝。用502/404/403差异枚举存活端点
  路径穿越确认: /api/v1/v/..;/..;/actuator/env → 502(存在被过滤) vs /api/v1/v/..;/..;/xxxx → 404(Tomcat原生不存在)
  CDN节点多端口: 扫CDN IP的3000-9200端口(8000/8080/9090常代理同一后端但规则可能不同,9200可能是独立nginx)
  绕过尝试矩阵(本session全测均失败,记录防重复): URL编码/双编码/大小写/分号后缀/TE空格走私/HTTP管线化/Accept-Encoding/Range
  有效信息提取: 即使502,POST actuator/env仍可能被后端执行(盲写属性)→需配合refresh触发(若refresh 404则链断)
🚨Nginx Catch-All陷阱: PHP CMS配rewrite全路由→所有路径返200同大小=catch-all(不是文件存在!)。识别: 用3个随机路径对比size一致=catch-all。真正存活路径用.php后缀测(nginx `location ~ \.php$`直通FastCGI，不存在返真404)。
🚨Pure-FTPd puredb损坏≠认证绕过: "Unable to read the indexed puredb file"=虚拟用户db坏了，所有用户名(包括匿名)都触发421断连。PAM系统用户认证也走puredb先→全部失败。不是攻击面，跳过。
🚨同IP多站横向: 反查IP(SecurityTrails/微步/VirusTotal)找同服务器其他域名→其中弱站(独立nginx配置返真404=可枚举)突破→宝塔面板统一管理=横向所有站。
指纹优先级: httpx/wappalyzer识别出框架版本后，先把指纹作为候选信号；是否转 `component-vuln-intel`、先继续测绘还是验证其他入口，由当前证据和授权范围决定。
🚨DNS通配符CDN识别: 所有子域名(包括不存在的随机子域)都解析到CDN=通配符DNS(*.domain → CDN CNAME)。此时枚举子域名无意义,所有IP都是CDN节点。
  验证: dig random123456.target.com → 如果也有A记录且指向已知CDN IP = 通配符。真实源IP需从其他渠道获取(历史DNS/证书透明/同服务器其他域名/邮件头/SSRF)
🚨宝塔面板(BT Panel)识别: Cookie名为32位hex hash(如789d6d2de16419a1e8bbfea926c8996e) + 302跳/login + nginx反代 + "入口校验失败"页面 = BT Panel随机安全入口
  Windows版: IIS+nginx共存, 8888端口面板, 888端口phpMyAdmin(可能), /index.html可能泄露站点配置(反向代理目标URL/站点名)
  攻击: 入口路径爆破(8位随机字母数字) | 历史CVE(API key未授权/phar反序列化) | 面板默认FTP/MySQL账户复用
🚨Nginx 404差分指纹: 当nginx catch-all重写掩盖真实路径时,比较响应大小——真实nginx 404(146B)=文件在磁盘存在但location块deny, catch-all(大页面)=路由未匹配。批量探测CMS标志路径(/caches/configs/, /phpcms/modules/, /statics/等)区分响应大小即可确认CMS类型。详见references/nginx-404-differential-fingerprinting.md
🚨UniApp/DCloud APK逆向快速路径: assets/apps/__UNI__*/www/app-service.js = 全部业务逻辑(JS混淆); assets/zlsioh.dat = 加密配置(API域名); lib/arm64-v8a/libirzlemnr.so = 解密库。JS用RC4+base64解混淆(提取a0G数组+a0m解码器); .so中strings搜16字符随机串=可能密钥, 搜`x数字.数字.数字.数字x`格式=硬编码IP(通常是DCloud HTTPDNS基础设施而非目标API)。详见references/uniapp-dcloud-apk-reversing.md
```
