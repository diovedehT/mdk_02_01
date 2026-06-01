# ПР №7. AppArmor, Capabilities и Docker

## 1. Linux Capabilities

### Разбор getcap /usr/bin/ping

```
/usr/bin/ping cap_net_raw=ep
```

`cap_net_raw` — capability позволяющая использовать RAW и PACKET сокеты (необходимо для отправки ICMP пакетов, то есть для работы ping)

- `e` (Effective) — capability активна прямо сейчас, используется при выполнении программы
- `p` (Permitted) — capability разрешена для данного файла, процесс может её использовать

### Файлы с capabilities в системе

Всего найдено 5 файлов:

| Файл | Capabilities |
|------|-------------|
| `/usr/lib/snapd/snap-confine` | cap_chown, cap_dac_override, cap_dac_read_search, cap_fowner, cap_setgid, cap_setuid, cap_sys_chroot, cap_sys_ptrace, cap_sys_admin, cap_sys_resource=p |
| `/usr/lib/x86_64-linux-gnu/gstreamer1.0/.../gst-ptp-helper` | cap_net_bind_service, cap_net_admin=ep |
| `/usr/bin/ping` | cap_net_raw=ep |
| `/usr/bin/dumpcap` | cap_net_admin, cap_net_raw=eip |
| `/usr/bin/mtr-packet` | cap_net_raw=ep |

### CapPrm / CapEff / CapBnd — в чём разница

```
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
```

- **CapInh** (Inheritable) — capabilities которые передаются дочерним процессам при execve
- **CapPrm** (Permitted) — capabilities которые процесс *может* активировать; верхний предел для CapEff
- **CapEff** (Effective) — capabilities которые *прямо сейчас активны* и используются ядром при проверке прав
- **CapBnd** (Bounding) — максимальный потолок capabilities; нельзя получить capability которой нет в Bounding
- **CapAmb** (Ambient) — capabilities которые наследуются непривилегированными дочерними процессами

У обычного пользователя CapPrm и CapEff равны нулю — никаких активных capabilities, что правильно и безопасно. CapBnd = `000001ffffffffff` означает что теоретически доступны все capabilities системы, но они не активированы.

### setcap — демонстрация принципа наименьших привилегий

До выдачи capability:
```
python3 /tmp/test-port.py 80  →  DENIED: порт 80 — [Errno 13] Permission denied
python3 /tmp/test-port.py 8080  →  OK: привязался к порту 8080
```

После `sudo setcap cap_net_bind_service=ep /usr/bin/python3.10`:
```
python3 /tmp/test-port.py 80  →  OK: привязался к порту 80
```

**Почему это лучше чем sudo:** запуск через sudo даёт процессу все права root — это нарушение принципа наименьших привилегий. setcap даёт ровно одну нужную capability и ничего лишнего. Если процесс будет взломан — злоумышленник получит только cap_net_bind_service, а не полный root.

### Флаги e, i, p в cap_net_raw+eip

- `e` (Effective) — capability активна прямо сейчас при выполнении
- `i` (Inheritable) — capability передаётся дочерним процессам через execve
- `p` (Permitted) — capability разрешена и может быть активирована

Разница между `ep` и `eip`: флаг `i` добавляет наследование — дочерние процессы запущенные из этого тоже получат данную capability. Без `i` дочерние процессы её не унаследуют.

---

## 2. AppArmor

### Количество профилей

- **enforce: 68 профилей** (Firefox, Discord, Spotify, cups, tcpdump и др.)
- **complain: 21 профиль** (avahi-daemon, ping, samba, syslog и др.)

### Профиль usr.bin.man — что разрешено

Профиль разрешает программе `man`:
- Запускать groff-утилиты (`eqn`, `tbl`, `troff` и др.) в дочернем профиле `man_groff` — для рендеринга страниц
- Запускать декомпрессоры (`gzip`, `bzip2`, `xz` и др.) в дочернем профиле `man_filter` — для распаковки
- Доступ к любым файлам (`/** mrixwlk`) — цель профиля не ограничить man, а ограничить дочерние процессы
- `capability setuid, setgid` — смена пользователя/группы

Синтаксис: `путь + буквы` означает права (`r`=чтение, `w`=запись, `x`=выполнение, `m`=mmap, `i`=inherit, `k`=lock). `rmCx -> &man_groff` — запустить в дочернем профиле.

### Результаты pr07-reader

| Действие | Без профиля | complain | enforce |
|----------|-------------|----------|---------|
| Читать /tmp/pr07-allowed.txt | OK | OK | OK |
| Читать /etc/shadow | DENIED (DAC) | DENIED (DAC) | DENIED (AppArmor + DAC) |
| Писать в /tmp/pr07-output.txt | OK | OK | OK |
| Писать в /etc/ | DENIED (DAC) | DENIED (DAC) | DENIED (AppArmor + DAC) |

**Режим complain** — профиль фиксирует нарушения в логах но не блокирует. Нужен для отладки профиля перед переводом в enforce.

**Режим enforce** — профиль активно блокирует все действия не разрешённые явно.

### Разбор строки DENIED из audit.log

```
apparmor="DENIED" operation="open" class="file" profile="/usr/local/bin/pr07-reader"
name="/tmp/pr07-notallowed.txt" comm="cat" requested_mask="r" denied_mask="r" fsuid=1000
```

- `apparmor="DENIED"` — действие заблокировано AppArmor
- `operation="open"` — тип операции: попытка открыть файл
- `profile="/usr/local/bin/pr07-reader"` — сработал наш профиль
- `name="/tmp/pr07-notallowed.txt"` — файл к которому был запрещён доступ
- `comm="cat"` — программа которая пыталась открыть файл
- `requested_mask="r"` — процесс хотел читать файл
- `denied_mask="r"` — чтение было заблокировано профилем
- `fsuid=1000` — UID пользователя от которого запущен процесс

---

## 3. Docker — изоляция

| Ресурс | Хост | Контейнер |
|--------|------|-----------|
| Количество процессов | ~десятки | 1-2 шт |
| Сетевые интерфейсы | eth0, lo, docker0 | eth0, lo (отдельные) |
| Корневая файловая система | полная система хоста | изолированный образ ubuntu |
| /etc/shadow хоста | доступен | недоступен (отдельная ФС) |
| Монтирование | разрешено | заблокировано (нет CAP_SYS_ADMIN) |

### Capabilities: обычный контейнер vs --privileged

Обычный контейнер:
```
CapEff: 00000000a80425fb
= cap_chown, cap_dac_override, cap_fowner, cap_fsetid, cap_kill,
  cap_setgid, cap_setuid, cap_setpcap, cap_net_bind_service,
  cap_net_raw, cap_sys_chroot, cap_mknod, cap_audit_write, cap_setfcap
```

--privileged контейнер:
```
CapEff: 000001ffffffffff
= cap_chown, cap_dac_override, cap_dac_read_search, cap_fowner, cap_fsetid,
  cap_kill, cap_setgid, cap_setuid, cap_setpcap, cap_linux_immutable,
  cap_net_bind_service, cap_net_broadcast, cap_net_admin, cap_net_raw,
  cap_ipc_lock, cap_ipc_owner, cap_sys_module, cap_sys_rawio, cap_sys_chroot,
  cap_sys_ptrace, cap_sys_pacct, cap_sys_admin, cap_sys_boot, cap_sys_nice,
  cap_sys_resource, cap_sys_time, cap_sys_tty_config, cap_mknod, cap_lease,
  cap_audit_write, cap_audit_control, cap_setfcap, cap_mac_override,
  cap_mac_admin, cap_syslog, cap_wake_alarm, cap_block_suspend,
  cap_audit_read, cap_perfmon, cap_bpf, cap_checkpoint_restore
```

**Чего нет у обычного контейнера:** cap_sys_admin, cap_sys_module, cap_sys_rawio, cap_net_admin, cap_sys_ptrace и многие другие опасные capabilities.

**Почему --privileged опасен:** контейнер получает почти все права root на хосте — может монтировать файловые системы хоста, загружать модули ядра, читать/писать сырые устройства. Если процесс внутри будет взломан — злоумышленник фактически получит полный доступ к хосту. --privileged оправдан только для специальных задач (например docker-in-docker) в изолированных средах.

### Итоговый nginx с ограниченными capabilities

```
CapEff: 00000000000004c3
= cap_chown, cap_dac_override, cap_setgid, cap_setuid, cap_net_bind_service
```

**Почему именно эти capabilities:**
- `cap_net_bind_service` — чтобы привязаться к порту 80 (привилегированный порт < 1024)
- `cap_chown` — менять владельца файлов логов и временных файлов
- `cap_dac_override` — читать и писать файлы конфигурации и логов
- `cap_setgid` / `cap_setuid` — мастер-процесс nginx стартует от root и переключается на непривилегированного пользователя (www-data) для воркеров

---

## 4. Эшелонированная защита

| Слой | Инструмент | Что ограничивает |
|------|------------|-----------------|
| DAC | chmod/chown | Доступ к файлам и директориям на основе владельца и прав (rwx) |
| Capabilities | --cap-drop ALL + --cap-add | Системные привилегии процесса — что может делать с ресурсами ядра |
| MAC | AppArmor | Какие файлы, сети и системные вызовы доступны конкретной программе |
| Изоляция | Docker namespaces | Видимость процессов, файловой системы, сети — полная изоляция от хоста |

---

##Контрольные вопросы

#1. Чем DAC отличается от MAC? Почему одного DAC недостаточно?
DAC (Discretionary Access Control) — владелец файла сам решает кто имеет доступ (chmod/chown). MAC (Mandatory Access Control) — политики задаёт администратор системы, и даже владелец файла не может их обойти. DAC недостаточно потому что если процесс получит права root — он обойдёт все DAC ограничения. AppArmor (MAC) ограничивает даже root-процессы.

#2. Что означает cap_net_bind_service=eip? Чем ep отличается от eip?
cap_net_bind_service — разрешает привязку к портам ниже 1024. e — effective (активна), i — inheritable (передаётся дочерним процессам), p — permitted (разрешена). Отличие: ep не передаёт capability дочерним процессам, eip — передаёт.

#3. В чём разница между complain и enforce в AppArmor? Зачем нужен complain?
complain — профиль фиксирует нарушения в логах но не блокирует. enforce — профиль активно блокирует запрещённые действия. Complain нужен чтобы протестировать профиль и убедиться что он не сломает работу программы, прежде чем переводить в enforce.

#4. Docker использует то же ядро что и хост — почему тогда контейнер изолирован?
Docker использует Linux namespaces — механизм ядра который создаёт изолированные представления системных ресурсов. Каждый контейнер получает свой pid namespace (видит только свои процессы), mnt namespace (своя файловая система), net namespace (своя сеть), uts namespace (своё hostname). Процессы реально работают на том же ядре, но не видят ресурсы друг друга.

#5. Злоумышленник нашёл RCE в nginx. Что может и не может сделать?
Может: выполнять код внутри контейнера от непривилегированного пользователя, читать файлы доступные этому пользователю внутри контейнера, использовать сеть контейнера.
Не может: выйти за пределы контейнера (namespaces), получить доступ к файлам хоста (изолированная ФС), использовать опасные capabilities (cap-drop ALL), навредить другим процессам на хосте, обойти AppArmor профиль.

#6. Почему --privileged антипаттерн? Когда оправдан?
--privileged даёт контейнеру почти все права root на хосте — может монтировать ФС хоста, загружать модули ядра, читать сырые устройства. Компрометация такого контейнера = компрометация хоста. Оправдан только в изолированных средах для специальных задач: docker-in-docker, отладка ядра, запуск системных утилит в CI.

---

## Выводы

В ходе практической работы были изучены три уровня защиты процессов в Linux:

1. **Linux Capabilities** реализуют принцип наименьших привилегий — вместо запуска от root процессу выдаётся ровно та capability которая нужна. Это существенно снижает ущерб при компрометации процесса.

2. **AppArmor** реализует мандатный контроль доступа (MAC) — даже если процесс запущен от root, профиль AppArmor ограничивает доступ к файлам, сети и системным вызовам. Режим complain позволяет безопасно отлаживать профиль перед переводом в enforce.

3. **Docker** изолирует процессы через namespaces (pid, net, mnt, uts, ipc) и cgroups — контейнер видит только свои процессы, свою файловую систему и свою сеть. В сочетании с --cap-drop ALL, --user и AppArmor это создаёт многоуровневую защиту.

Эшелонированная защита важна потому что каждый слой защищает от разных векторов атаки. DAC может быть обойдён при получении прав root, capabilities ограничивают что может делать даже root-процесс, AppArmor ограничивает доступ к ресурсам независимо от прав, а Docker изолирует весь контейнер от хоста.
