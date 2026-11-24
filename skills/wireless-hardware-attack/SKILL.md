---
name: wireless-hardware-attack
description: >-
  无线/硬件:WiFi PMKID/WPS/Evil Twin,BLE,Zigbee,NFC,SDR,UART/JTAG/SPI,侧信道,故障注入。Use when attacking WiFi, BLE, RFID, SDR, or hardware interfaces.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 无线 / 硬件攻击

## 适用场景

适合在受控环境中评估无线网络、BLE、RFID、SDR、固件和设备接口的安全风险。

## 核心判断

先确认频段、设备、物理接入、测试环境和允许影响，再判断无线协议、固件和硬件接口风险。信号可观测不等于可攻击。

## 证据标准

- 无线测试可准备设备、频段、时间窗和影响范围。
- 固件和接口分析需要镜像、芯片、引脚或调试输出证据。
- 克隆或重放需要实际协议和身份验证差距。
- 侧信道和故障注入需要可重复实验与影响边界。

## 决策树

- 自有设备且可物理接入：先做只读固件和接口识别。
- 无线网络已授权：在隔离环境验证协议和配置。
- 涉及干扰或广播：停止并要求明确授权。
- 需要固件写入或故障注入：准备回滚和备用设备。
- 只有信号或硬件照片：保留线索，不确认漏洞。

## 常见误判

- 把可发现 SSID/BLE 设备当成可入侵。
- 在公共频段执行干扰测试。
- 忽略硬件损坏和业务中断。
- 把固件字符串当成可执行逻辑。
- 没有恢复手段就修改设备。

```
=== 无线/硬件 ===
WiFi: aircrack-ng/PMKID(hcxdumptool+hashcat)/WPS reaver/Evil Twin | BLE: gatttool枚举GATT/无认证读写/Just Works
Zigbee killerbee | NFC/RFID proxmark3克隆/MIFARE mfoc | LoRa/SDR rtl-sdr+gnuradio重放
硬件: UART波特率扫描拿shell | JTAG/SWD读写固件 | SPI flash dump | 侧信道DPA/时序 | 故障注入(电压/时钟毛刺跳认证) | binwalk -Me
```

