# REA Workbench — восстановление и подтверждённые проверки

**Версия документа:** 2026-10-08. Это внешняя инструментальная среда разработки и исследования, **не сервер, требующийся готовому Ω VPN**.

## Внешние идентификаторы (не секреты)

- Vercel team ID: `team_CpQKYj9HpAMJIDCw7Bi4hpNF`.
- Vercel project: `rea-reverse-engineering-workbench`; project ID: `prj_oUqaD5jD9tJF3CtyfYcgFV9ByS96`.
- Named persistent sandbox: `rea-toolkit`; регион `fra1`; 2 vCPU/4 GiB.
- Sandbox восстановлен с snapshot `snap_U9wQaMiGYwFgNjbmwEF1PCkstFaJ`, новая сессия на 08.10.2026: `sbx_76Pom2etR9oWT5rlLnJsREO4FRlI`. **ID сессии после последующих рестартов изменится, не хардкодить.**

## Восстановить в обычном чате

1. Использовать **подключённый Vercel**, не пытаться запускать REA как якобы установленный прямой плагин ChatGPT.
2. Вызвать `mcp__Vercel__get_named_sandbox` с `teamId`, `projectId`, `name=rea-toolkit`, `resume=true`.
3. Взять **текущий** `session.id` / `currentSessionId` из ответа.
4. Выполнить через `mcp__Vercel__run_session_command`:
   ```bash
   /vercel/rea-workbench/status.sh
   rea-workbench doctor --provider ghidra --format json
   test -f /vercel/rea-workbench/targets/Happ-4.7.1.apk
   ```
5. Если sandbox после истечения retention не восстановился, считать среду отсутствующей; установить заново по [morluto/rea](https://github.com/morluto/rea), [Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases) и [jadx-headless-mcp](https://github.com/1013503897/jadx-headless-mcp). Проверять SHA-256 официальных бинарников.
6. Публичные исходники Ω VPN, планы и доказательства должны быть **в GitHub**, а не только в Vercel. Sandbox не является вечным хранилищем. Периодическая остановка/снапшоты зависят от тарифа/retention.

## Установленный инструментарий и пути

| Инструмент | Версия / путь |
| --- | --- |
| REA CLI + MCP | `6.0.0`; `rea-workbench`, `/vercel/rea-workbench/rea.sh` |
| Ghidra | `12.1.4`; `/vercel/rea-workbench/tools/ghidra_12.1.4_PUBLIC` |
| JADX headless MCP | `0.7.1`; `/vercel/rea-workbench/tools/jadx-headless-mcp-0.7.1-all.jar` |
| Java | OpenJDK 21; `/usr/lib/jvm/java-21-openjdk-amd64` |
| Node | 24.21.0 |
| sing-box (Linux smoke only) | `1.14.2`; `/vercel/rea-workbench/tools/sing-box-1.14.2-linux-amd64/sing-box` |
| Конфигурация REA | `/vercel/rea-workbench/env.sh` |
| Codex MCP registration | `/vercel/.codex/config.toml` (локально в sandbox, **не** общий ChatGPT MCP) |
| Исследуемые файлы | `/vercel/rea-workbench/targets/` |
| Отчёты проверки | `/vercel/rea-workbench/reports/` |

## Подтверждённый healthcheck

После восстановления из снапшота запущен `status.sh`: REA `6.0.0`; Node `v24.21.0`; Java `21.0.12.1`; JADX JAR присутствует; Ghidra doctor **healthy**; Happ 4.7.1 APK сохранён. Это доказывает наличие инструментов **на момент проверки**, не что они работают в каждом будущeм запуске.

Happ 4.7.1 APK: SHA-256 `488923701e7d46e556b8566e50f03ef1b13ad807be0299feb892b83a2242a093`. Результаты REA: 11 165 классов; `XRayVpnService` и `BIND_VPN_SERVICE`; бинарные `libcore.so`, `libgojni.so`, `libhev-socks5-tunnel.so`. Не выкладывать APK в `omega-vpn` и не копировать proprietary код/ресурсы в приложение.

Ранее также прошёл эксперимент с **разрешённым публичным VLESS/Reality-узлом**: sing-box 1.14.2 + SOCKS5, HTTPS 200 и изменённый IP в облаке. **Это не тест Android**.

## REA-команды для будущего агента

```bash
# Проверка
rea-workbench doctor --provider ghidra --format json

# Статическое исследование Happ APK (без запуска)
rea-workbench inspect-android-package \
  /vercel/rea-workbench/targets/Happ-4.7.1.apk \
  --token-limit 400
rea-workbench inspect-android-class \
  /vercel/rea-workbench/targets/Happ-4.7.1.apk \
  su.happ.proxyutility.service.XRayVpnService \
  --token-limit 500

# Декомпиляция тестовой ELF-функции:
rea-workbench function \
  /vercel/rea-workbench/targets/demo-elf \
  compute_total --provider ghidra --token-limit 500
```

Не комбинировать `--format json` с `--token-limit`: в REA эти флаги несовместимы. Сохранять только безопасные, обобщённые выводы с хэшами/ссылками, не коммитить приватные VPN-конфигурации или перехваченный трафик.

## Ограничения и стоимость

Содержимое Vercel не гарантировано навечно; расходы могут возникать из-за CPU/хранения/сети. Готовое Ω VPN должно работать **без Vercel, REA и собственного сервера**. Сохранённый MCP-сервер доступен как локальный процесс внутри sandbox, а не зарегистрирован глобально во всех разговорах ChatGPT.
