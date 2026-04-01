# 基于sword软件所维护的POC仓库

## 项目介绍

- Sword 是一款基于Nuclei引擎，面向安全测试场景的本地桌面工具，围绕 POC 管理、批量扫描、抓包分析、请求重放和结果整理这几条高频链路做统一整合。
- 它的目标不是只做单点能力，而是把“模板管理 -> 扫描执行 -> 结果查看 -> 流量分析 -> 请求重放”串成一条完整工作流，减少在多个工具之间来回切换的成本。
- 下载地址：https://github.com/zg-sec/sword-pocs


## POC仓库维护说明

- 每个yaml文件保持唯一性，参考去重规则 [./TEMPLATE_NAMING_RULES.md](./TEMPLATE_NAMING_RULES.md)
- 严格遵循nuclei官方模板编写和验证规则。
- POC文件将在发布包处发布，解压缩后均为yaml，无其他格式文件。
- 每个yaml文件均通过Sword项目校验可用性。

## 下载地址

- https://github.com/zg-sec/sword-pocs/releases
- 解压统一为：`zhugeanquan`

## 发布记录

- 2026年4月1号：Releases Tag：[v1.0](https://github.com/zg-sec/sword-pocs/releases/tag/v1.0)（57849个）